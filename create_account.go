package schemacafe

import (
	"html/template"
)

type CreateAccount struct {
}

var createAccountTemplate = template.Must(template.New("create-account").Parse(fsString(pages, "pages/auth/create-account.html")))
