package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// OpenAPI emission, from the registry and the Go types.
//
// Nothing here is hand-maintained, and that is the requirement: a hand-written
// document describes what somebody believed the API did on the day they wrote
// it. This one is derived from the same Route values the mux serves and the
// same structs the handlers decode, so it cannot describe a route that is not
// served, a permission that is not enforced, or a field that does not exist.
//
// It is not a complete OpenAPI implementation and does not try to be. It covers
// the shapes this API actually uses; a shape it cannot express is a reason to
// extend it, not to hand-write around it.

const openAPIVersion = "3.1.0"

type oaDoc struct {
	OpenAPI    string                `json:"openapi"`
	Info       oaInfo                `json:"info"`
	Paths      map[string]oaPath     `json:"paths"`
	Components oaComponents          `json:"components"`
	Security   []map[string][]string `json:"security,omitempty"`
}

type oaInfo struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

type oaPath map[string]oaOperation

type oaOperation struct {
	Summary     string                `json:"summary"`
	Description string                `json:"description,omitempty"`
	OperationID string                `json:"operationId"`
	Parameters  []oaParameter         `json:"parameters,omitempty"`
	RequestBody *oaRequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]oaResponse `json:"responses"`
	Security    []map[string][]string `json:"security,omitempty"`

	// The permission a caller needs. A vendor extension because OpenAPI has no
	// standard field for it, and emitted because an integrator reading the
	// document must be able to see what their token needs to hold.
	Permission string `json:"x-cvap-permission,omitempty"`
}

type oaParameter struct {
	Name        string   `json:"name"`
	In          string   `json:"in"`
	Required    bool     `json:"required"`
	Description string   `json:"description,omitempty"`
	Schema      oaSchema `json:"schema"`
}

type oaRequestBody struct {
	Required bool                   `json:"required"`
	Content  map[string]oaMediaType `json:"content"`
}

type oaResponse struct {
	Description string                 `json:"description"`
	Content     map[string]oaMediaType `json:"content,omitempty"`
}

type oaMediaType struct {
	Schema oaSchema `json:"schema"`
}

type oaSchema struct {
	Ref         string              `json:"$ref,omitempty"`
	Type        string              `json:"type,omitempty"`
	Format      string              `json:"format,omitempty"`
	Items       *oaSchema           `json:"items,omitempty"`
	Properties  map[string]oaSchema `json:"properties,omitempty"`
	Required    []string            `json:"required,omitempty"`
	Description string              `json:"description,omitempty"`
	Nullable    bool                `json:"nullable,omitempty"`
	Enum        []string            `json:"enum,omitempty"`
}

type oaComponents struct {
	Schemas         map[string]oaSchema   `json:"schemas"`
	SecuritySchemes map[string]oaSecurity `json:"securitySchemes"`
}

type oaSecurity struct {
	Type        string `json:"type"`
	In          string `json:"in,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// OpenAPI renders the document for a registry.
func (reg *Registry) OpenAPI(version string) ([]byte, error) {
	doc := oaDoc{
		OpenAPI: openAPIVersion,
		Info: oaInfo{
			Title:   "CVAP Operator API",
			Version: version,
			Description: "Operator-facing control surface for the CyberSentinel Vulnerability " +
				"Assessment Platform.\n\n" +
				"The tenant is resolved from the request host and is never taken from a " +
				"request field, a header or a body key (ADR-041). There is no parameter " +
				"anywhere in this document that names a tenant, and that is deliberate: a " +
				"tenant a client can name is a tenant a client can change.\n\n" +
				"Generated from the route registry. Do not edit.",
		},
		Paths:      map[string]oaPath{},
		Components: oaComponents{Schemas: map[string]oaSchema{}, SecuritySchemes: map[string]oaSecurity{}},
	}

	doc.Components.SecuritySchemes["session"] = oaSecurity{
		Type: "apiKey", In: "cookie", Name: SessionCookie,
		Description: "Session cookie issued by POST /v1/auth/login. HttpOnly, Secure, SameSite=Lax. " +
			"Mutating requests must also carry the " + CSRFHeader + " header, whose value is the " +
			CSRFCookie + " cookie.",
	}

	for _, r := range reg.Routes() {
		op := oaOperation{
			Summary:     r.Summary,
			Description: r.Description,
			OperationID: operationID(r),
			Responses:   map[string]oaResponse{},
		}

		for _, p := range pathParams(r.Path) {
			op.Parameters = append(op.Parameters, oaParameter{
				Name: p, In: "path", Required: true,
				Schema: oaSchema{Type: "string", Format: "uuid"},
			})
		}

		if r.Access != AccessPublic {
			op.Security = []map[string][]string{{"session": {}}}
		}
		if r.Access == AccessPermission {
			op.Permission = string(r.Permission)
		}

		if r.Request != nil {
			op.RequestBody = &oaRequestBody{
				Required: true,
				Content:  map[string]oaMediaType{"application/json": {Schema: schemaRef(doc.Components.Schemas, r.Request)}},
			}
		}

		status := r.Status
		if status == 0 {
			status = http.StatusOK
		}
		resp := oaResponse{Description: http.StatusText(status)}
		if r.Response != nil {
			resp.Content = map[string]oaMediaType{"application/json": {Schema: schemaRef(doc.Components.Schemas, r.Response)}}
		}
		op.Responses[itoa(status)] = resp

		// The error responses every route can produce. Emitted for all of them
		// rather than declared per route, because they come from the middleware
		// chain and are therefore true of every endpoint by construction.
		errSchema := schemaRef(doc.Components.Schemas, ErrorBody{})
		for _, e := range errorStatuses(r) {
			op.Responses[itoa(e.status)] = oaResponse{
				Description: e.description,
				Content:     map[string]oaMediaType{"application/json": {Schema: errSchema}},
			}
		}

		p := doc.Paths[r.Path]
		if p == nil {
			p = oaPath{}
			doc.Paths[r.Path] = p
		}
		p[strings.ToLower(r.Method)] = op
	}

	return json.MarshalIndent(doc, "", "  ")
}

type errStatus struct {
	status      int
	description string
}

func errorStatuses(r Route) []errStatus {
	out := []errStatus{
		{http.StatusBadRequest, "The request body or a path parameter was malformed."},
		{http.StatusInternalServerError, "An unexpected error. The response body never describes the schema or the failing query; the detail is in Core's log against the request id."},
	}
	if r.Access != AccessPublic {
		out = append(out, errStatus{http.StatusUnauthorized, "No valid session. Indistinguishable from an expired or revoked one, deliberately."})
	}
	// The 403 causes are MERGED rather than appended separately.
	//
	// They are keyed by status in the responses map, so two entries meant the
	// second silently overwrote the first and the document's 403 never mentioned
	// the permission it requires — which is the one thing an integrator reads
	// this document to find out.
	var forbidden []string
	if r.Access == AccessPermission {
		forbidden = append(forbidden, "the session's role does not hold "+string(r.Permission))
	}
	if r.Mutating() && r.Access != AccessPublic {
		forbidden = append(forbidden, "the "+CSRFHeader+" header is missing or does not match the session")
	}
	if r.Mutating() {
		forbidden = append(forbidden, "the request did not come from this site")
	}
	if len(forbidden) > 0 {
		out = append(out, errStatus{http.StatusForbidden,
			"Refused because " + strings.Join(forbidden, ", or ") + "."})
	}
	return out
}

// operationID is stable across runs and unique per route: method plus path with
// the separators flattened. Generated rather than declared, because a
// hand-written id is one more thing that can silently collide.
func operationID(r Route) string {
	s := strings.ToLower(r.Method)
	for _, seg := range strings.Split(strings.Trim(r.Path, "/"), "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") {
			s += "By" + title(strings.Trim(seg, "{}"))
			continue
		}
		s += title(seg)
	}
	return s
}

func pathParams(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, strings.Trim(seg, "{}"))
		}
	}
	return out
}

// schemaRef registers a named schema for a struct type and returns a reference
// to it. Non-structs are emitted inline.
func schemaRef(into map[string]oaSchema, v any) oaSchema {
	t := reflect.TypeOf(v)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return oaSchema{}
	}
	if t.Kind() != reflect.Struct || t == reflect.TypeOf(time.Time{}) {
		return schemaFor(into, t)
	}
	name := t.Name()
	if _, ok := into[name]; !ok {
		// Placed before recursion so a self-referential type terminates.
		into[name] = oaSchema{Type: "object"}
		into[name] = structSchema(into, t)
	}
	return oaSchema{Ref: "#/components/schemas/" + name}
}

func structSchema(into map[string]oaSchema, t reflect.Type) oaSchema {
	s := oaSchema{Type: "object", Properties: map[string]oaSchema{}}
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, ok := jsonName(f)
		if !ok {
			continue
		}
		fs := schemaFor(into, f.Type)
		if d := f.Tag.Get("doc"); d != "" {
			fs.Description = d
		}
		s.Properties[name] = fs
		if !opts.omitempty && f.Type.Kind() != reflect.Pointer {
			s.Required = append(s.Required, name)
		}
	}
	sortStrings(s.Required)
	return s
}

type jsonOpts struct{ omitempty bool }

func jsonName(f reflect.StructField) (string, jsonOpts, bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", jsonOpts{}, false
	}
	name, rest, _ := strings.Cut(tag, ",")
	if name == "" {
		name = f.Name
	}
	return name, jsonOpts{omitempty: strings.Contains(rest, "omitempty")}, true
}

func schemaFor(into map[string]oaSchema, t reflect.Type) oaSchema {
	switch {
	case t == reflect.TypeOf(time.Time{}):
		return oaSchema{Type: "string", Format: "date-time"}
	}
	switch t.Kind() {
	case reflect.Pointer:
		s := schemaFor(into, t.Elem())
		s.Nullable = true
		return s
	case reflect.String:
		return oaSchema{Type: "string"}
	case reflect.Bool:
		return oaSchema{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return oaSchema{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return oaSchema{Type: "number"}
	case reflect.Slice, reflect.Array:
		items := schemaFor(into, t.Elem())
		if t.Elem().Kind() == reflect.Struct && t.Elem() != reflect.TypeOf(time.Time{}) {
			items = schemaRef(into, reflect.New(t.Elem()).Elem().Interface())
		}
		return oaSchema{Type: "array", Items: &items}
	case reflect.Map:
		return oaSchema{Type: "object"}
	case reflect.Struct:
		return schemaRef(into, reflect.New(t).Elem().Interface())
	default:
		return oaSchema{}
	}
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = digits[i%10]
		i /= 10
	}
	return string(b[n:])
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
