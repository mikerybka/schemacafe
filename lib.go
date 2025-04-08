package schemacafe

import (
	"html/template"
)

type Lib struct {
}

var libTemplate = template.Must(template.New("lib").Parse(fsString(pages, "pages/auth/lib.html")))
