//go:build dev

package kube

import (
	"errors"
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// restConfig prefers the in-cluster configuration and falls back to the usual kubeconfig
// discovery, so the same binary runs in a pod and against a cluster from a workstation.
//
// This file is only compiled with the `dev` tag. It exists for development and debugging:
// the kubeconfig loader it pulls in reads a file path of the operator's choosing and supports
// exec credential plugins, which is surface a production build has no reason to carry.
func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		cfg, err := rest.InClusterConfig()
		switch {
		case err == nil:
			return cfg, nil
		case !errors.Is(err, rest.ErrNotInCluster):
			return nil, fmt.Errorf("in-cluster configuration: %w", err)
		}
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	return cfg, nil
}
