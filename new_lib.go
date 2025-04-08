package schemacafe

import (
	"html/template"
)

type NewLib struct {
}

var newLibTemplate = template.Must(template.New("new-lib").Parse(fsString(pages, "pages/auth/new-lib.html")))
