//go:build !dev

package config

// kubeconfigSupported is false in a production build: the -kubeconfig flag is not registered
// at all, so passing it is an error rather than a setting that quietly does nothing. The
// code behind it is not linked in either (see internal/kube/config_cluster.go).
const kubeconfigSupported = false
