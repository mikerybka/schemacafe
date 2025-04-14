package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mikerybka/util"
	"github.com/schemacafe"
)

func main() {
	server := &schemacafe.Server{
		GiteaURL:        util.EnvVar("GITEA_URL", "http://localhost:3001"),
		GiteaAdminToken: readSecret("schema.cafe/GITEA_ADMIN_TOKEN"),
		Host:            "schema.cafe",
	}
	port := util.EnvVar("PORT", "3000")
	panic(http.ListenAndServe(":"+port, server))
}

func readSecret(name string) string {
	path := filepath.Join("/home/mike/data/secrets", name)
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(b))
}
