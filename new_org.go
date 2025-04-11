package schemacafe

import (
	"html/template"
)

type NewOrg struct {
}

var newOrgTemplate = template.Must(template.New("new-org").Parse(fsString(pages, "pages/new-org.html")))
