package main

import (
	"net/http"

	"github.com/mikerybka/util"
	"github.com/schemacafe"
)

func main() {
	server := &schemacafe.Server{
		Workdir: util.EnvVar("WORK_DIR", "data"),
	}
	port := util.EnvVar("PORT", "3000")
	panic(http.ListenAndServe(":"+port, server))
}
