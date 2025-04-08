package schemacafe

import (
	"html/template"
)

type Login struct {
}

var loginTemplate = template.Must(template.New("login").Parse(fsString(pages, "pages/auth/login.html")))
