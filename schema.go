package schemacafe

import (
	"html/template"
)

type Schema struct {
}

var schemaTemplate = template.Must(template.New("schema").Parse(fsString(pages, "pages/auth/schema.html")))
