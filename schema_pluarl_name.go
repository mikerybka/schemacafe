package schemacafe

import (
	"html/template"
)

type SchemaPluarlName struct {
}

var schemaPluralNameTemplate = template.Must(template.New("schema-plural-name").Parse(fsString(pages, "pages/schema-plural-name.html")))
