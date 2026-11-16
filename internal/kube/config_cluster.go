//go:build !dev

package kube

import (
	"errors"
	"fmt"

	"k8s.io/client-go/rest"
)

// restConfig returns the in-cluster configuration, and that is the only way this build can
// reach an API server: the service account token and CA that the kubelet mounts, plus the
// KUBERNETES_SERVICE_* environment. No file is read from a path somebody can choose, no
// KUBECONFIG is honoured, and the kubeconfig loader with its auth plugins and exec hooks is
// not part of the binary at all.
//
// A kubeconfig is refused rather than ignored: silently falling back would turn a deployment
// mistake into a service that watches the wrong cluster.
func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return nil, errors.New("this build reads the in-cluster configuration only; rebuild with -tags dev to use a kubeconfig")
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster configuration: %w", err)
	}
	return cfg, nil
}
