package schemacafe

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/mikerybka/authentication"
	"github.com/mikerybka/util"
	"github.com/schemacafe/pkg/basicauth"
)

type Server struct {
	Workdir string
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, authorized, err := s.auth(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !authorized {
		http.NotFound(w, r)
		return
	}

	mux := http.NewServeMux()

	// Landing page
	mux.Handle("GET /{$}", util.NewTemplateServer[Root](rootTemplate, filepath.Join(s.Workdir, "root")))

	// Create account
	mux.HandleFunc("GET /auth/create-account", func(w http.ResponseWriter, r *http.Request) {

	})
	mux.HandleFunc("POST /auth/create-account", func(w http.ResponseWriter, r *http.Request) {
		req := &struct {
			Username        string `json:"username"`
			Password        string `json:"password"`
			ConfirmPassword string `json:"confirmPassword"`
		}{}
		if util.ContentType(r, "application/json") {
			err = json.NewDecoder(r.Body).Decode(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			req.Username = r.FormValue("username")
			req.Password = r.FormValue("password")
			req.ConfirmPassword = r.FormValue("confirm_password")
		}

		token, err := s.authentication().Join(req.Username, req.Password, req.ConfirmPassword)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if util.Accept(r, "application/json") {
			err = json.NewEncoder(w).Encode(token)
			if err != nil {
				panic(err)
			}
		} else {
			http.SetCookie(w, &http.Cookie{
				Name:  "user_id",
				Value: req.Username,
				Path:  "/",
			})
			http.SetCookie(w, &http.Cookie{
				Name:  "token",
				Value: token,
				Path:  "/",
			})
			http.Redirect(w, r, "/home", http.StatusSeeOther)
		}
	})

	// Login
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {})

	// Logout
	mux.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {})

	// Create org
	mux.HandleFunc("GET /new", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("PUT /{orgID}", func(w http.ResponseWriter, r *http.Request) {})

	// View orgs
	mux.HandleFunc("GET /home", func(w http.ResponseWriter, r *http.Request) {})

	// Delete org
	mux.HandleFunc("GET /{orgID}/delete", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("DELETE /{orgID}", func(w http.ResponseWriter, r *http.Request) {})

	// Create lib
	mux.HandleFunc("GET /{orgID}/new", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("PUT /{orgID}/{libID}", func(w http.ResponseWriter, r *http.Request) {})

	// View libs
	mux.HandleFunc("GET /{orgID}", func(w http.ResponseWriter, r *http.Request) {})

	// Delete lib
	mux.HandleFunc("DELETE /{orgID}/{libID}", func(w http.ResponseWriter, r *http.Request) {})

	// Create schema
	mux.HandleFunc("GET /{orgID}/{libID}/new", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}", func(w http.ResponseWriter, r *http.Request) {})

	// View schema
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}", func(w http.ResponseWriter, r *http.Request) {})

	// Set name
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}/name", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}/name", func(w http.ResponseWriter, r *http.Request) {})

	// Set plural name
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}/plural-name", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}/plural-name", func(w http.ResponseWriter, r *http.Request) {})

	// Set fields
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}/fields", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}/fields", func(w http.ResponseWriter, r *http.Request) {

	})

	// Delete schema
	mux.ServeHTTP(w, r)
}

var tlpBlocklist = []string{
	"public",
	"auth",
	"home",
	"mike",
}

func (s *Server) authentication() authentication.Service {
	return basicauth.NewServer(filepath.Join(s.Workdir, "auth"))
}

func (s *Server) auth(r *http.Request) (string, bool, error) {
	userID, err := s.authentication().GetUserID(r)
	if err != nil {
		return "", false, err
	}

	if isPublicPath(r) {
		return userID, true, nil
	}

	if r.PathValue("orgID") == userID {
		return userID, true, nil
	}

	return userID, false, nil
}

func isPublicPath(r *http.Request) bool {
	publicPaths := []string{
		"/",
		"/auth/create-account",
		"/auth/login",
	}
	for _, path := range publicPaths {
		if path == r.URL.Path {
			return true
		}
	}
	return false
}
