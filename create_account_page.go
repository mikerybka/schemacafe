package schemacafe

import (
	"html/template"
	"net/http"
)

func NewCreateAccountPage() *CreateAccountPage {
	return &CreateAccountPage{}
}

type CreateAccountPage struct {
	Error error
}

func (p *CreateAccountPage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := createAccountTemplate.Execute(w, struct {
		Error error
	}{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

var createAccountTemplate = template.Must(template.New("create-account").Parse(fsString(pages, "pages/auth/create-account.html")))
