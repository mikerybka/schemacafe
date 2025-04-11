package schemacafe

import (
	"html/template"
)

type NewSchema struct {
}

var newSchemaTemplate = template.Must(template.New("new-schema").Parse(fsString(pages, "pages/auth/new-schema.html")))
