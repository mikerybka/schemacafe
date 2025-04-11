package schemacafe

import (
	"html/template"
)

type SchemaName struct {
}

var schemaNameTemplate = template.Must(template.New("schema-name").Parse(fsString(pages, "pages/schema-name.html")))
