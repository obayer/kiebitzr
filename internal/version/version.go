// Package version holds build metadata injected at link time via -ldflags.
package version

// Set by ko / go build: -X github.com/obayer/kiebitzr/internal/version.Version=...
var (
	Version = "dev"
	Commit  = "unknown"
)
