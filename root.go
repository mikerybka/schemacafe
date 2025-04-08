package schemacafe

import (
	"html/template"
)

type Root struct{}

var rootTemplate = template.Must(template.New("root").Parse(fsString(pages, "pages/root.html")))
