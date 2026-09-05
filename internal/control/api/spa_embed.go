//go:build embedui

package api

import (
	"embed"
	"io/fs"
)

// spaDist is the built Vite output. `all:` includes files Vite may emit with a
// leading dot or underscore. This directive is processed ONLY under the embedui
// tag, so the default build does not require web/dist to exist.
//
//go:embed all:web/dist
var spaDist embed.FS

func spaFS() (fs.FS, bool) {
	sub, err := fs.Sub(spaDist, "web/dist")
	if err != nil {
		return nil, false
	}
	return sub, true
}
