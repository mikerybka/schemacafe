package schemacafe

import (
	"html/template"
	"net/http"
)

func NewLoginPage() *LoginPage {
	return &LoginPage{}
}

type LoginPage struct {
	Error error
}

var loginTemplate = template.Must(template.New("login").Parse(fsString(pages, "pages/auth/login.html")))

func (p *LoginPage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := loginTemplate.Execute(w, struct {
		Error error
	}{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
