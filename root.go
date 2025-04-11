package schemacafe

import (
	"html/template"
)

type Root struct {
	UserID string
}

var rootTemplate = template.Must(template.New("root").Parse(fsString(pages, "pages/root.html")))
