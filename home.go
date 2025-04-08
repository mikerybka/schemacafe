package schemacafe

import (
	"html/template"
)

type Home struct {
}

var homeTemplate = template.Must(template.New("home").Parse(fsString(pages, "pages/auth/home.html")))
