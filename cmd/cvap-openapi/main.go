// Command cvap-openapi prints the operator API's OpenAPI document to stdout,
// rendered from the route registry with no database.
//
// It is the codegen source for the web client's TypeScript types: `make ui-types`
// pipes it through openapi-typescript, and the web CI job regenerates and fails
// on a diff — the same treatment proto-verify gives gen/ (session 19, note 3).
// The client is a third registry that must agree with this one.
package main

import (
	"fmt"
	"os"

	"github.com/effaaykhan/cvap/internal/control/api"
)

func main() {
	doc, err := api.OpenAPISpec("dev")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cvap-openapi:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(doc); err != nil {
		fmt.Fprintln(os.Stderr, "cvap-openapi:", err)
		os.Exit(1)
	}
	fmt.Println()
}
