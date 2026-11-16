//go:build dev

package config

// kubeconfigSupported is true with the `dev` tag, which registers the -kubeconfig flag so the
// binary can be pointed at a cluster from outside it.
const kubeconfigSupported = true
