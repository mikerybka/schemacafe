package schemacafe

import (
	"html/template"
)

type Logout struct {
}

var logoutTemplate = template.Must(template.New("logout").Parse(fsString(pages, "pages/auth/logout.html")))
