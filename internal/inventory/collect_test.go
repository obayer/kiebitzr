package inventory

import (
	"context"
	"errors"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// pagedLister serves prepared pages and records the options of every call.
type pagedLister struct {
	pages [][]corev1.Pod
	calls []metav1.ListOptions
	err   error
}

func (l *pagedLister) List(_ context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	l.calls = append(l.calls, opts)
	if l.err != nil {
		return nil, l.err
	}
	page := len(l.calls) - 1
	list := &corev1.PodList{Items: l.pages[page]}
	if page+1 < len(l.pages) {
		list.Continue = "token"
	}
	return list, nil
}

func TestCollectPagesThroughAllPods(t *testing.T) {
	lister := &pagedLister{pages: [][]corev1.Pod{
		{*newPod("prod", "web-0", withContainer("app", "registry.example/app:1.4.0", "registry.example/app@"+digestA))},
		{*newPod("prod", "api-0", withContainer("app", "registry.example/api:2.0.0", "registry.example/api@"+digestB))},
	}}

	snap, err := Collect(context.Background(), lister, nil)
	if err != nil {
		t.Fatalf("Collect() = %v, want no error", err)
	}
	if got := snap.Digests(); !slices.Equal(got, []string{digestA, digestB}) {
		t.Fatalf("Digests() = %v, want the digests of both pages", got)
	}
	if len(lister.calls) != 2 {
		t.Fatalf("List called %d times, want 2", len(lister.calls))
	}
	if got := lister.calls[0]; got.Limit != pageSize || got.FieldSelector != runningSelector || got.Continue != "" {
		t.Fatalf("first List options = %+v, want a paged, running-only list without a token", got)
	}
	if got := lister.calls[1].Continue; got != "token" {
		t.Fatalf("second List continue = %q, want the token of the first page", got)
	}
}

func TestCollectReportsListErrors(t *testing.T) {
	wantErr := errors.New("forbidden")
	lister := &pagedLister{err: wantErr}

	if _, err := Collect(context.Background(), lister, nil); !errors.Is(err, wantErr) {
		t.Fatalf("Collect() = %v, want it to wrap %v", err, wantErr)
	}
}
