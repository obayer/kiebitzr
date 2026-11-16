// Package inventory turns the pods of a cluster into the set of image digests that are
// running right now. It reads pods and nothing else, and it keeps only the projection — a
// pod spec contains literal env values and is dropped as soon as it has been read
// (ADR 0001).
package inventory

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// legacyIDPrefix prefixed imageIDs in the dockershim era; containerd does not use it.
const legacyIDPrefix = "docker-pullable://"

// hashAlphabet is the alphabet Kubernetes draws a pod-template-hash from
// (k8s.io/apimachinery/pkg/util/rand.SafeEncodeString). A trailing name segment built from
// it is what distinguishes a generated ReplicaSet name from a hand-written one.
const hashAlphabet = "bcdfghjklmnpqrstvwxz2456789"

// Occurrence is one container of one pod running one image digest. Its fields are exactly
// the labels of kiebitzr_image_info, so identical occurrences in different pods — the
// replicas of a Deployment — collapse into a single series.
type Occurrence struct {
	// Digest is the digest the kubelet reports, `sha256:<hex>`. For containerd this is the
	// digest of the multi-arch index, not of a platform manifest.
	Digest string
	// Image is the reference the pod asked for, usually with a tag.
	Image string
	// Namespace of the pod.
	Namespace string
	// OwnerKind and OwnerName approximate the workload the pod belongs to.
	OwnerKind string
	OwnerName string
	// Container is the name of the container within the pod.
	Container string
}

// Snapshot is the deduplicated inventory of one pass over the cluster.
type Snapshot struct {
	seen       map[Occurrence]struct{}
	refs       map[string]string
	excluded   map[string]struct{}
	skipped    int
	unresolved int
}

// NewSnapshot returns an empty Snapshot ready to accumulate pods. Pods in one of the
// excludeNamespaces are dropped on the way in, so their images are never catalogued either.
func NewSnapshot(excludeNamespaces []string) *Snapshot {
	excluded := make(map[string]struct{}, len(excludeNamespaces))
	for _, namespace := range excludeNamespaces {
		excluded[namespace] = struct{}{}
	}
	return &Snapshot{
		seen:     make(map[Occurrence]struct{}),
		refs:     make(map[string]string),
		excluded: excluded,
	}
}

// AddPod projects one pod into the snapshot. Pods that are not running contribute nothing:
// a succeeded or failed pod still reports its imageIDs, but its image is not running.
func (s *Snapshot) AddPod(pod *corev1.Pod) {
	if pod.Status.Phase != corev1.PodRunning {
		return
	}
	if _, excluded := s.excluded[pod.Namespace]; excluded {
		s.skipped++
		return
	}
	ownerKind, ownerName := owner(pod)
	for _, statuses := range [][]corev1.ContainerStatus{
		pod.Status.InitContainerStatuses,
		pod.Status.ContainerStatuses,
	} {
		for _, st := range statuses {
			s.add(pod, ownerKind, ownerName, st)
		}
	}
}

func (s *Snapshot) add(pod *corev1.Pod, ownerKind, ownerName string, st corev1.ContainerStatus) {
	id := strings.TrimPrefix(st.ImageID, legacyIDPrefix)
	repo, digest, ok := splitImageID(id, st.Image)
	if !ok {
		// Either the container has not pulled its image yet, or the runtime reports an
		// imageID we cannot turn into something pullable (a bare config digest). Counted so
		// a blind spot is visible in the metrics instead of silently missing.
		s.unresolved++
		return
	}
	occ := Occurrence{
		Digest:    digest,
		Image:     st.Image,
		Namespace: pod.Namespace,
		OwnerKind: ownerKind,
		OwnerName: ownerName,
		Container: st.Name,
	}
	s.seen[occ] = struct{}{}
	// The first reference wins; any pod running the digest can serve as the pull source.
	if _, dup := s.refs[digest]; !dup {
		s.refs[digest] = repo + "@" + digest
	}
}

// Occurrences returns the deduplicated occurrences in a stable order.
func (s *Snapshot) Occurrences() []Occurrence {
	out := make([]Occurrence, 0, len(s.seen))
	for occ := range s.seen {
		out = append(out, occ)
	}
	slices.SortFunc(out, func(a, b Occurrence) int {
		return cmp.Or(
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.OwnerKind, b.OwnerKind),
			cmp.Compare(a.OwnerName, b.OwnerName),
			cmp.Compare(a.Container, b.Container),
			cmp.Compare(a.Digest, b.Digest),
			cmp.Compare(a.Image, b.Image),
		)
	})
	return out
}

// Refs maps every running digest to the reference it can be pulled by, `repository@digest`.
// This is the work list for cataloguing: one entry per digest, however many pods run it.
func (s *Snapshot) Refs() map[string]string { return s.refs }

// Digests returns the running digests in a stable order.
func (s *Snapshot) Digests() []string {
	return slices.Sorted(maps.Keys(s.refs))
}

// Unresolved counts the container statuses whose imageID could not be turned into a pullable
// reference — the part of the cluster this inventory cannot speak for.
func (s *Snapshot) Unresolved() int { return s.unresolved }

// Skipped counts the running pods dropped by the namespace exclusion. Worth logging: it is
// the difference between "nothing runs there" and "we were told not to look".
func (s *Snapshot) Skipped() int { return s.skipped }

// splitImageID separates the repository from the digest. The kubelet reports an imageID as
// `repository@sha256:<hex>`; some runtimes report only the digest, in which case the
// repository is taken from the image reference of the same container status.
func splitImageID(imageID, image string) (repo, digest string, ok bool) {
	repo, digest, found := strings.Cut(imageID, "@")
	if !found {
		// A bare digest carries no repository, so fall back to the reference. Anything else
		// (an empty imageID, a tag) gives us nothing to match against.
		if !isDigest(imageID) {
			return "", "", false
		}
		repo, digest = "", imageID
	}
	if !isDigest(digest) {
		return "", "", false
	}
	if repo == "" {
		repo = repository(image)
	}
	if repo == "" {
		return "", "", false
	}
	return repo, digest, true
}

// isDigest reports whether s is a digest of a supported algorithm.
func isDigest(s string) bool {
	alg, hex, found := strings.Cut(s, ":")
	if !found || hex == "" {
		return false
	}
	switch alg {
	case "sha256", "sha512":
	default:
		return false
	}
	return !strings.ContainsAny(hex, "/@:")
}

// repository strips a tag or digest from an image reference. A colon only separates a tag
// when it follows the last slash; before that it is a registry port.
func repository(image string) string {
	if repo, _, found := strings.Cut(image, "@"); found {
		image = repo
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// owner approximates the workload a pod belongs to from its controller reference alone; no
// workload resource is read. A ReplicaSet's generated hash suffix is stripped, which names
// the Deployment above it. A pod without a controller stands for itself.
func owner(pod *corev1.Pod) (kind, name string) {
	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return "Pod", pod.Name
	}
	if ref.Kind == "ReplicaSet" {
		if base, stripped := stripHashSuffix(ref.Name); stripped {
			return "Deployment", base
		}
	}
	return ref.Kind, ref.Name
}

// stripHashSuffix removes a trailing `-<pod-template-hash>` segment. A ReplicaSet created by
// hand has no such suffix and is reported as itself.
func stripHashSuffix(name string) (string, bool) {
	i := strings.LastIndex(name, "-")
	if i <= 0 {
		return name, false
	}
	suffix := name[i+1:]
	if len(suffix) < 5 || len(suffix) > 10 {
		return name, false
	}
	for _, r := range suffix {
		if !strings.ContainsRune(hashAlphabet, r) {
			return name, false
		}
	}
	return name[:i], true
}
