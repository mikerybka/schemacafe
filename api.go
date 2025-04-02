package schemacafe

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/mikerybka/auth"
	"github.com/mikerybka/data"
	"github.com/mikerybka/twilio"
)

type API struct {
	Workdir      string
	TwilioClient *twilio.Client
}

func (api *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/auth") {
		h := &auth.Server{
			DB: &auth.DB{
				Dir: filepath.Join(api.Workdir, "auth"),
			},
			TwilioClient: api.TwilioClient,
		}
		http.StripPrefix("/auth", h)
	} else if strings.HasPrefix(r.URL.Path, "/data") {
		h := &data.Server{
			Workdir: filepath.Join(api.Workdir, "data"),
		}
		http.StripPrefix("/data", h)
	}
}
