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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.getRoot)
	mux.HandleFunc("GET /auth/create-account", s.getCreateAccount)
	mux.HandleFunc("POST /auth/create-account", s.postCreateAccount)
	mux.HandleFunc("GET /auth/login", s.getLogin)
	mux.HandleFunc("POST /auth/login", s.postLogin)
	mux.HandleFunc("GET /auth/logout", s.getLogout)
	mux.HandleFunc("POST /auth/logout", s.postLogout)
	mux.HandleFunc("GET /new", s.getNewOrg)
	mux.HandleFunc("PUT /{orgID}", s.putOrg)
	mux.HandleFunc("GET /home", s.getHome)
	mux.HandleFunc("GET /{orgID}/delete", s.getDeleteOrg)
	mux.HandleFunc("DELETE /{orgID}", s.deleteOrg)
	mux.HandleFunc("GET /{orgID}/new", s.getCreateLib)
	mux.HandleFunc("PUT /{orgID}/{libID}", s.putLib)
	mux.HandleFunc("GET /{orgID}", s.getOrg)
	mux.HandleFunc("GET /{orgID}/{libID}/delete", s.getDeleteLib)
	mux.HandleFunc("DELETE /{orgID}/{libID}", s.deleteLib)
	mux.HandleFunc("GET /{orgID}/{libID}/new", s.getCreateSchema)
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}", s.putSchema)
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}", s.getSchema)
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}/name", s.getSchemaName)
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}/name", s.putSchemaName)
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}/plural-name", s.getSchemaPluralName)
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}/plural-name", s.putSchemaPluralName)
	mux.HandleFunc("GET /{orgID}/{libID}/{schemaID}/fields", s.getSchemaFields)
	mux.HandleFunc("PUT /{orgID}/{libID}/{schemaID}/fields", s.putSchemaFields)
	mux.ServeHTTP(w, r)
}

func (s *Server) getRoot(w http.ResponseWriter, r *http.Request) {
	userID, err := s.authentication().GetUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	util.NewTemplateServer[Root](rootTemplate, s.Workdir, userID).ServeHTTP(w, r)
}

func (s *Server) getCreateAccount(w http.ResponseWriter, r *http.Request) {
	userID, err := s.authentication().GetUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	util.NewTemplateServer[CreateAccount](createAccountTemplate, s.Workdir, userID).ServeHTTP(w, r)
}

func (s *Server) postCreateAccount(w http.ResponseWriter, r *http.Request) {
	req := &struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
	}{}
	if util.ContentType(r, "application/json") {
		err := json.NewDecoder(r.Body).Decode(req)
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
}
func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	userID, err := s.authentication().GetUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	util.NewTemplateServer[Login](loginTemplate, s.Workdir, userID)
}
func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {}
func (s *Server) getLogout(w http.ResponseWriter, r *http.Request) {
	userID, err := s.authentication().GetUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	util.NewTemplateServer[Logout](logoutTemplate, s.Workdir, userID)
}
func (s *Server) postLogout(w http.ResponseWriter, r *http.Request)          {}
func (s *Server) getNewOrg(w http.ResponseWriter, r *http.Request)           {}
func (s *Server) putOrg(w http.ResponseWriter, r *http.Request)              {}
func (s *Server) getHome(w http.ResponseWriter, r *http.Request)             {}
func (s *Server) getDeleteOrg(w http.ResponseWriter, r *http.Request)        {}
func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request)           {}
func (s *Server) getOrg(w http.ResponseWriter, r *http.Request)              {}
func (s *Server) getDeleteLib(w http.ResponseWriter, r *http.Request)        {}
func (s *Server) deleteLib(w http.ResponseWriter, r *http.Request)           {}
func (s *Server) getCreateLib(w http.ResponseWriter, r *http.Request)        {}
func (s *Server) putLib(w http.ResponseWriter, r *http.Request)              {}
func (s *Server) getCreateSchema(w http.ResponseWriter, r *http.Request)     {}
func (s *Server) putSchema(w http.ResponseWriter, r *http.Request)           {}
func (s *Server) getSchema(w http.ResponseWriter, r *http.Request)           {}
func (s *Server) getSchemaName(w http.ResponseWriter, r *http.Request)       {}
func (s *Server) putSchemaName(w http.ResponseWriter, r *http.Request)       {}
func (s *Server) getSchemaPluralName(w http.ResponseWriter, r *http.Request) {}
func (s *Server) putSchemaPluralName(w http.ResponseWriter, r *http.Request) {}
func (s *Server) getSchemaFields(w http.ResponseWriter, r *http.Request)     {}
func (s *Server) putSchemaFields(w http.ResponseWriter, r *http.Request)     {}

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
