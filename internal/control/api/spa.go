package api

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// Serving the operator web UI, same-origin with the API (settled in session 18's
// plan, ADR-053). It is one catch-all Static route through the registry — there
// is no handler path that skips the middleware chain — and it is served from an
// embedded filesystem behind the `embedui` build tag (spa_embed.go), with a stub
// (spa_stub.go) so the default `go build ./...` needs no built frontend.
//
// A second HTTP surface: the browser talks to one origin, the session cookie is
// host-only, the tenant is the Host, and there is NO CORS. That is the whole
// reason there is no CORS anywhere in this package.

// uiNotBuiltPage is served when the binary was built without the UI embedded.
const uiNotBuiltPage = `<!doctype html><html><head><meta charset="utf-8">` +
	`<title>CVAP</title></head><body style="font-family:system-ui;margin:3rem">` +
	`<h1>Operator UI not built into this binary</h1>` +
	`<p>This Core was compiled without the web UI. Build it with the frontend embedded ` +
	`(<code>make ui-build &amp;&amp; go build -tags embedui ./cmd/cvap-core</code>), or use the ` +
	`API directly at <code>/v1/</code> and its document at <code>/v1/openapi.json</code>.</p>` +
	`</body></html>`

// registerSPA adds the single Static catch-all that serves the UI (ADR-053).
func (s *Server) registerSPA() {
	s.reg.Register(Route{
		Method: http.MethodGet, Path: "/",
		Summary: "The operator web UI",
		Description: "Serves the single-page operator UI, same-origin with the API. Not an API " +
			"operation and excluded from this document (ADR-053); public because the shell loads " +
			"before authentication, which then happens through /v1/auth.",
		Access:  AccessPublic,
		Static:  true,
		Handler: spaHandler(),
	})
}

// spaHandler serves the embedded SPA, or the not-built page when the binary has
// no UI. index.html is the fallback for any path the file set does not contain,
// so client-side routes (/findings/{id}, …) resolve to the app.
func spaHandler() http.HandlerFunc {
	files, ok := spaFS()
	if !ok {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(uiNotBuiltPage))
		}
	}
	index, indexErr := fs.ReadFile(files, "index.html")
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if b, err := fs.ReadFile(files, name); err == nil && name != "index.html" {
			if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
				w.Header().Set("Content-Type", ct)
			}
			// Vite emits content-hashed asset names under assets/, so they are
			// safe to cache immutably; anything else is served without a hard
			// cache so a deploy is picked up.
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			// #nosec G705 -- b is compile-time content from the go:embed dist, not
			// attacker data: the caller only chooses WHICH embedded file, the path
			// is path.Clean'd and the FS is fs.Sub-scoped to web/dist so traversal
			// cannot escape it, Content-Type is set from the extension above, and
			// nosniff + CSP are set for every path by the securityHeaders
			// middleware. There is no untrusted byte on this write.
			_, _ = w.Write(b)
			return
		}
		// SPA fallback: the app shell. Never cached hard, so a new build is seen.
		if indexErr != nil {
			http.Error(w, "index.html missing from the embedded UI", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	}
}
