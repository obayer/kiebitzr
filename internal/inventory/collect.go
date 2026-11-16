package inventory

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// pageSize bounds how many pods are in memory at once.
	pageSize = 500
	// runningSelector lets the API server drop everything that is not running, so pods that
	// cannot contribute are never transferred.
	runningSelector = "status.phase=Running"
)

// PodLister is the only Kubernetes access this service makes: listing pods. A
// `clientset.CoreV1().Pods(metav1.NamespaceAll)` satisfies it.
type PodLister interface {
	List(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error)
}

// Collect pages through the running pods of the cluster and returns their projection. Every
// page is projected and then dropped, so peak memory is one page of pods rather than the
// whole cluster.
//
// The namespace exclusion is applied here, on our side, rather than handed to the API server
// as a field selector. A selector the server rejects would fail the whole listing, and
// listing pods is the one thing this service cannot do without.
func Collect(ctx context.Context, pods PodLister, excludeNamespaces []string) (*Snapshot, error) {
	snap := NewSnapshot(excludeNamespaces)
	opts := metav1.ListOptions{Limit: pageSize, FieldSelector: runningSelector}
	for {
		list, err := pods.List(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("list pods: %w", err)
		}
		for i := range list.Items {
			snap.AddPod(&list.Items[i])
		}
		if list.Continue == "" {
			return snap, nil
		}
		opts.Continue = list.Continue
	}
}
