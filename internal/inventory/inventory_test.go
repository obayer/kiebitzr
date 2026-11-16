package inventory

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// podOption mutates a pod built by newPod.
type podOption func(*corev1.Pod)

func newPod(namespace, name string, opts ...podOption) *corev1.Pod {
	pod := &corev1.Pod{
		Namespace: namespace, Name: name,
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, opt := range opts {
		opt(pod)
	}
	return pod
}

func withContainer(name, image, imageID string) podOption {
	return func(pod *corev1.Pod) {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses,
			corev1.ContainerStatus{Name: name, Image: image, ImageID: imageID})
	}
}

func withInitContainer(name, image, imageID string) podOption {
	return func(pod *corev1.Pod) {
		pod.Status.InitContainerStatuses = append(pod.Status.InitContainerStatuses,
			corev1.ContainerStatus{Name: name, Image: image, ImageID: imageID})
	}
}

func withPhase(phase corev1.PodPhase) podOption {
	return func(pod *corev1.Pod) { pod.Status.Phase = phase }
}

func withController(kind, name string) podOption {
	return func(pod *corev1.Pod) {
		pod.OwnerReferences = []metav1.OwnerReference{{
			Kind:       kind,
			Name:       name,
			Controller: new(true),
		}}
	}
}

func TestSnapshotProjectsContainers(t *testing.T) {
	snap := NewSnapshot(nil)
	snap.AddPod(newPod("prod", "web-7d9f8b5c4d-abcde",
		withController("ReplicaSet", "web-7d9f8b5c4d"),
		withInitContainer("migrate", "registry.example/app:1.4.0", "registry.example/app@"+digestA),
		withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA),
		withContainer("sidecar", "registry.example/proxy:2.0.0", "registry.example/proxy@"+digestB),
	))

	want := []Occurrence{
		{Digest: digestA, Image: "registry.example/app:1.4.0", Namespace: "prod", OwnerKind: "Deployment", OwnerName: "web", Container: "app"},
		{Digest: digestA, Image: "registry.example/app:1.4.0", Namespace: "prod", OwnerKind: "Deployment", OwnerName: "web", Container: "migrate"},
		{Digest: digestB, Image: "registry.example/proxy:2.0.0", Namespace: "prod", OwnerKind: "Deployment", OwnerName: "web", Container: "sidecar"},
	}
	if got := snap.Occurrences(); !slices.Equal(got, want) {
		t.Fatalf("Occurrences() = %+v, want %+v", got, want)
	}
	if got, want := snap.Refs()[digestA], "registry.example/app@"+digestA; got != want {
		t.Fatalf("Refs()[A] = %q, want %q", got, want)
	}
	if got := snap.Digests(); !slices.Equal(got, []string{digestA, digestB}) {
		t.Fatalf("Digests() = %v, want both digests sorted", got)
	}
	if snap.Unresolved() != 0 {
		t.Fatalf("Unresolved() = %d, want 0", snap.Unresolved())
	}
}

// Replicas of one Deployment must collapse into a single series, otherwise the collector
// would offer Prometheus the same label set twice.
func TestSnapshotDeduplicatesReplicas(t *testing.T) {
	snap := NewSnapshot(nil)
	for _, name := range []string{"web-7d9f8b5c4d-abcde", "web-7d9f8b5c4d-fghij"} {
		snap.AddPod(newPod("prod", name,
			withController("ReplicaSet", "web-7d9f8b5c4d"),
			withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA),
		))
	}
	if got := snap.Occurrences(); len(got) != 1 {
		t.Fatalf("Occurrences() = %+v, want one entry", got)
	}
}

// The same digest under two workloads keeps two info series but remains one unit of work.
func TestSnapshotSharedDigestIsScannedOnce(t *testing.T) {
	snap := NewSnapshot(nil)
	snap.AddPod(newPod("prod", "web-0",
		withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA)))
	snap.AddPod(newPod("staging", "web-0",
		withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA)))

	if got := snap.Occurrences(); len(got) != 2 {
		t.Fatalf("Occurrences() = %+v, want two entries", got)
	}
	if got := snap.Digests(); !slices.Equal(got, []string{digestA}) {
		t.Fatalf("Digests() = %v, want one digest", got)
	}
}

func TestSnapshotIgnoresPodsThatAreNotRunning(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodPending, corev1.PodSucceeded, corev1.PodFailed, corev1.PodUnknown} {
		t.Run(string(phase), func(t *testing.T) {
			snap := NewSnapshot(nil)
			snap.AddPod(newPod("prod", "job-0", withPhase(phase),
				withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA)))
			if got := snap.Occurrences(); len(got) != 0 {
				t.Fatalf("Occurrences() = %+v, want none for phase %s", got, phase)
			}
		})
	}
}

func TestSnapshotExcludesNamespaces(t *testing.T) {
	snap := NewSnapshot([]string{"kube-system", "monitoring"})
	for _, namespace := range []string{"prod", "kube-system", "monitoring"} {
		snap.AddPod(newPod(namespace, "web-0",
			withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA)))
	}

	occurrences := snap.Occurrences()
	if len(occurrences) != 1 || occurrences[0].Namespace != "prod" {
		t.Fatalf("Occurrences() = %+v, want only the pod outside the excluded namespaces", occurrences)
	}
	if snap.Skipped() != 2 {
		t.Fatalf("Skipped() = %d, want 2", snap.Skipped())
	}
}

// An excluded namespace must not contribute work either: its digests are never catalogued,
// and nothing but the exclusion decides that.
func TestSnapshotExcludedNamespacesContributeNoDigests(t *testing.T) {
	snap := NewSnapshot([]string{"kube-system"})
	snap.AddPod(newPod("kube-system", "agent-0",
		withContainer("app", "registry.example/agent:1.0.0", "registry.example/agent@"+digestB)))

	if digests := snap.Digests(); len(digests) != 0 {
		t.Fatalf("Digests() = %v, want none", digests)
	}
	if refs := snap.Refs(); len(refs) != 0 {
		t.Fatalf("Refs() = %v, want none", refs)
	}
}

// A digest that also runs outside the excluded namespaces stays in scope.
func TestSnapshotKeepsDigestsThatAlsoRunElsewhere(t *testing.T) {
	snap := NewSnapshot([]string{"kube-system"})
	snap.AddPod(newPod("kube-system", "agent-0",
		withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA)))
	snap.AddPod(newPod("prod", "web-0",
		withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA)))

	if digests := snap.Digests(); !slices.Equal(digests, []string{digestA}) {
		t.Fatalf("Digests() = %v, want the digest that still runs in prod", digests)
	}
	if occurrences := snap.Occurrences(); len(occurrences) != 1 {
		t.Fatalf("Occurrences() = %+v, want only the one in prod", occurrences)
	}
}

func TestSnapshotCountsUnresolvedImageIDs(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		imageID string
	}{
		{"not pulled yet", "registry.example/app:1.4.0", ""},
		{"bare digest without reference", "", "sha256:deadbeef"},
		{"imageID is a tag", "registry.example/app:1.4.0", "registry.example/app:1.4.0"},
		{"unknown digest algorithm", "registry.example/app:1.4.0", "registry.example/app@md5:deadbeef"},
		{"digest without hex", "registry.example/app:1.4.0", "registry.example/app@sha256:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := NewSnapshot(nil)
			snap.AddPod(newPod("prod", "web-0", withContainer("app", tt.image, tt.imageID)))
			if got := snap.Occurrences(); len(got) != 0 {
				t.Fatalf("Occurrences() = %+v, want none", got)
			}
			if snap.Unresolved() != 1 {
				t.Fatalf("Unresolved() = %d, want 1", snap.Unresolved())
			}
		})
	}
}

func TestSplitImageID(t *testing.T) {
	tests := []struct {
		name     string
		imageID  string
		image    string
		wantRepo string
	}{
		{"containerd", "registry.example/app@" + digestA, "registry.example/app:1.4.0", "registry.example/app"},
		{"registry with port", "registry.example:5000/app@" + digestA, "registry.example:5000/app:1.4.0", "registry.example:5000/app"},
		{"bare digest falls back to the tagged reference", digestA, "registry.example/app:1.4.0", "registry.example/app"},
		{"bare digest falls back to a digest reference", digestA, "registry.example/app@" + digestA, "registry.example/app"},
		{"reference with port and no tag", digestA, "registry.example:5000/app", "registry.example:5000/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, digest, ok := splitImageID(tt.imageID, tt.image)
			if !ok {
				t.Fatalf("splitImageID(%q, %q) = not ok, want ok", tt.imageID, tt.image)
			}
			if repo != tt.wantRepo || digest != digestA {
				t.Fatalf("splitImageID(%q, %q) = %q, %q, want %q, %q",
					tt.imageID, tt.image, repo, digest, tt.wantRepo, digestA)
			}
		})
	}
}

// The dockershim prefix is gone from current clusters but costs one TrimPrefix to tolerate.
func TestSnapshotAcceptsLegacyImageIDPrefix(t *testing.T) {
	snap := NewSnapshot(nil)
	snap.AddPod(newPod("prod", "web-0", withContainer("app", "registry.example/app:1.4.0",
		legacyIDPrefix+"registry.example/app@"+digestA)))

	occs := snap.Occurrences()
	if len(occs) != 1 || occs[0].Digest != digestA {
		t.Fatalf("Occurrences() = %+v, want one entry with digest A", occs)
	}
}

func TestOwner(t *testing.T) {
	tests := []struct {
		name      string
		pod       *corev1.Pod
		wantKind  string
		wantName  string
		rationale string
	}{
		{
			name:      "replicaset hash is stripped to the deployment",
			pod:       newPod("prod", "web-0", withController("ReplicaSet", "web-7d9f8b5c4d")),
			wantKind:  "Deployment",
			wantName:  "web",
			rationale: "the hash suffix names the Deployment above the ReplicaSet",
		},
		{
			name:      "hand-written replicaset keeps its own name",
			pod:       newPod("prod", "web-0", withController("ReplicaSet", "web")),
			wantKind:  "ReplicaSet",
			wantName:  "web",
			rationale: "no generated suffix to strip",
		},
		{
			name:      "replicaset with a word suffix is not a hash",
			pod:       newPod("prod", "web-0", withController("ReplicaSet", "web-canary")),
			wantKind:  "ReplicaSet",
			wantName:  "web-canary",
			rationale: "`canary` contains letters outside the hash alphabet",
		},
		{
			name:      "daemonset is reported as it is",
			pod:       newPod("kube-system", "agent-abcde", withController("DaemonSet", "agent")),
			wantKind:  "DaemonSet",
			wantName:  "agent",
			rationale: "no workload resource is read, the controller reference is enough",
		},
		{
			name:      "statefulset is reported as it is",
			pod:       newPod("prod", "db-0", withController("StatefulSet", "db")),
			wantKind:  "StatefulSet",
			wantName:  "db",
			rationale: "pod names are ordinals, the owner carries the workload name",
		},
		{
			name:      "pod without controller stands for itself",
			pod:       newPod("prod", "debug", withContainer("app", "", "")),
			wantKind:  "Pod",
			wantName:  "debug",
			rationale: "a static or hand-started pod has no workload above it",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, name := owner(tt.pod)
			if kind != tt.wantKind || name != tt.wantName {
				t.Fatalf("owner() = %s/%s, want %s/%s (%s)", kind, name, tt.wantKind, tt.wantName, tt.rationale)
			}
		})
	}
}

func TestStripHashSuffix(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"web-7d9f8b5c4d", true},
		{"web-bcdfg", true},
		{"web-bcdf", false},        // shorter than any generated hash
		{"web-bcdfghjklmn", false}, // longer than any generated hash
		{"web-canary", false},
		{"web-7d9f8b5c4D", false}, // upper case is outside the alphabet
		{"-abcde", false},
		{"web", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := stripHashSuffix(tt.name); got != tt.want {
				t.Fatalf("stripHashSuffix(%q) stripped = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
