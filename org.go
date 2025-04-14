package schemacafe

import (
	"html/template"
)

type Org struct {
	ID   string
	Libs []string
}

var orgTemplate = template.Must(template.New("org").Parse(fsString(pages, "pages/org.html")))
