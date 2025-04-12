package main

import (
	"net/http"

	"github.com/mikerybka/util"
	"github.com/schemacafe"
)

func main() {
	server := &schemacafe.Server{
		GiteaURL:        util.EnvVar("GITEA_URL", "http://localhost:3001"),
		GiteaAdminToken: util.RequireEnvVar("GITEA_ADMIN_TOKEN"),
		Host:            "schema.cafe",
	}
	port := util.EnvVar("PORT", "3000")
	panic(http.ListenAndServe(":"+port, server))
}
