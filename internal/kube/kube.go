// Package kube builds the only Kubernetes client this service has: a cluster-wide pods
// client. Nothing here can reach any other resource kind (ADR 0001).
//
// How the API server is reached depends on the build. A production build knows exactly one
// way in — the pod's own service account — and the code for any other way is not linked into
// it. A build with the `dev` tag also accepts a kubeconfig, so the binary can be run against
// a cluster from a workstation. See config_cluster.go and config_dev.go.
package kube

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Pods returns a pods client for all namespaces. kubeconfig is only honoured by a build with
// the `dev` tag; a production build rejects a non-empty value rather than silently ignoring
// it.
func Pods(kubeconfig, userAgent string) (corev1client.PodInterface, error) {
	cfg, err := restConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	cfg.UserAgent = userAgent

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return clientset.CoreV1().Pods(metav1.NamespaceAll), nil
}
