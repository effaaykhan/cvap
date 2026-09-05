//go:build !embedui

package api

import "io/fs"

// spaFS reports no embedded UI in the default build, so `go build ./...` and the
// test suites need no built frontend. spa_embed.go supplies the real one under
// the `embedui` tag.
func spaFS() (fs.FS, bool) { return nil, false }
