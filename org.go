package schemacafe

import (
	"html/template"
)

type Org struct {
}

var orgTemplate = template.Must(template.New("org").Parse(fsString(pages, "pages/auth/org.html")))
