package schemacafe

import (
	"html/template"
)

type SchemaFields struct {
}

var schemaFieldsTemplate = template.Must(template.New("schema-fields").Parse(fsString(pages, "pages/auth/schema-fields.html")))
