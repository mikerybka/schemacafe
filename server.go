package schemacafe

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/mikerybka/util"
)

type Server struct {
	GiteaURL        string
	GiteaAdminToken string
	Host            string
}

//go:embed favicon.ico
var favicon []byte

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.getRoot)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Write(favicon)
	})
	mux.Handle("GET /auth/create-account", NewCreateAccountPage())
	mux.HandleFunc("POST /auth/create-account", s.postCreateAccount)
	mux.Handle("GET /auth/login", NewLoginPage())
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

func (s *Server) userToken(r *http.Request) (string, error) {
	token := r.Header.Get("Token")
	if token == "" {
		cookie, err := r.Cookie("token")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return "public", nil
			}
			return "", err
		}
		token = cookie.Value
	}
	return token, nil
}

func (s *Server) userGiteaToken(r *http.Request) (string, string, error) {
	userToken, err := s.userToken(r)
	if err != nil {
		return "", "", err
	}

	giteaTokenName, giteaToken, ok := strings.Cut(userToken, ":")
	if !ok {
		return "", "", err
	}
	return giteaTokenName, giteaToken, nil
}

func (s *Server) userGiteaClient(r *http.Request) (*gitea.Client, error) {
	_, giteaToken, err := s.userGiteaToken(r)
	if err != nil {
		return nil, err
	}
	return gitea.NewClient(s.GiteaURL, gitea.SetToken(giteaToken))
}

func (s *Server) userID(r *http.Request) (string, error) {
	c, err := s.userGiteaClient(r)
	if err != nil {
		return "", err
	}
	user, _, err := c.GetMyUserInfo()
	if err != nil {
		if err.Error() == "token is required" {
			return "", nil
		}
		return "", err
	}
	return user.UserName, nil
}

func (s *Server) getRoot(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = rootTemplate.Execute(w, struct {
		UserID string
	}{
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) postCreateAccount(w http.ResponseWriter, r *http.Request) {
	// Get inputs
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
		req.Username = strings.ToLower(r.FormValue("username"))
		req.Password = r.FormValue("password")
		req.ConfirmPassword = r.FormValue("confirm_password")
	}

	// Check username blocklist
	if map[string]bool{
		"admin":     true,
		"auth":      true,
		"settings":  true,
		"internal":  true,
		"cmd":       true,
		"pkg":       true,
		"authorize": true,
		"login":     true,
		"logout":    true,
	}[req.Username] {
		http.Error(w, "username not allowed", http.StatusBadRequest)
		return
	}

	// Check passwords match
	if req.Password != req.ConfirmPassword {
		http.Error(w, "passwords don't match", http.StatusBadRequest)
		return
	}

	// Create gitea account
	c, err := gitea.NewClient(s.GiteaURL, gitea.SetToken(s.GiteaAdminToken))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	no := false
	_, _, err = c.AdminCreateUser(gitea.CreateUserOption{
		Username:           req.Username,
		Email:              fmt.Sprintf("%s@%s", req.Username, s.Host),
		Password:           req.Password,
		MustChangePassword: &no,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create session token
	c, err = gitea.NewClient(s.GiteaURL, gitea.SetBasicAuth(req.Username, req.Password))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := util.RandomID()
	t, _, err := c.CreateAccessToken(gitea.CreateAccessTokenOption{
		Name:   name,
		Scopes: []gitea.AccessTokenScope{"all"},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token := name + ":" + t.Token

	// Send outputs
	if util.Accept(r, "application/json") {
		err = json.NewEncoder(w).Encode(token)
		if err != nil {
			panic(err)
		}
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:  "token",
			Value: token,
			Path:  "/",
		})
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	// Get inputs
	req := &struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}
	if util.ContentType(r, "application/json") {
		err := json.NewDecoder(r.Body).Decode(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		req.Username = strings.ToLower(r.FormValue("username"))
		req.Password = r.FormValue("password")
	}

	// Create session token
	c, err := gitea.NewClient(s.GiteaURL, gitea.SetBasicAuth(req.Username, req.Password))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := util.RandomID()
	t, _, err := c.CreateAccessToken(gitea.CreateAccessTokenOption{
		Name:   name,
		Scopes: []gitea.AccessTokenScope{"all"},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token := name + ":" + t.Token

	// Send outputs
	if util.Accept(r, "application/json") {
		err = json.NewEncoder(w).Encode(token)
		if err != nil {
			panic(err)
		}
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:  "token",
			Value: token,
			Path:  "/",
		})
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
}
func (s *Server) getLogout(w http.ResponseWriter, r *http.Request) {
	err := logoutTemplate.Execute(w, struct{}{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0), // or time.Now().Add(-1 * time.Hour)
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) getNewOrg(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = newOrgTemplate.Execute(w, struct {
		UserID string
	}{
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) putOrg(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) getHome(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = homeTemplate.Execute(w, struct {
		UserID string
	}{
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) getDeleteOrg(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}

func listGiteaRepos(c *gitea.Client, orgID string, page int) ([]*gitea.Repository, int, error) {
	repos, resp, err := c.ListOrgRepos(orgID, gitea.ListOrgReposOptions{
		ListOptions: gitea.ListOptions{
			Page:     page,
			PageSize: 50,
		},
	})
	if resp.StatusCode == 404 {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	totalStr := resp.Header.Get("X-Total-Count")
	total, err := strconv.Atoi(totalStr)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to parse X-Total-Count: %v", err)
	}
	return repos, total, nil
}

func listAllGiteaRepos(client *gitea.Client, orgID string) ([]*gitea.Repository, error) {
	repos, total, err := listGiteaRepos(client, orgID, 1)
	if err != nil {
		return nil, err
	}
	if total > 50 {
		numPages := total/50 + 1
		for page := 2; page <= numPages; page++ {
			r, _, err := listGiteaRepos(client, orgID, page)
			if err != nil {
				return nil, err
			}
			repos = append(repos, r...)
		}
	}
	return repos, nil
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	c, err := s.userGiteaClient(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	orgID := r.PathValue("orgID")
	repos, err := listAllGiteaRepos(c, orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	libs := []string{}
	for _, repo := range repos {
		libs = append(libs, repo.Name)
	}
	err = orgTemplate.Execute(w, Org{
		ID:   orgID,
		Libs: libs,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) getDeleteLib(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) deleteLib(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) getCreateLib(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
	err = newLibTemplate.Execute(w, struct {
		UserID string
	}{
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) putLib(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) getCreateSchema(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
	err = newSchemaTemplate.Execute(w, struct {
		UserID string
	}{
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) putSchema(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) getSchema(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
	err = schemaTemplate.Execute(w, struct {
		UserID string
	}{
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) getSchemaName(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
	err = schemaNameTemplate.Execute(w, struct {
		UserID string
	}{
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (s *Server) putSchemaName(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) getSchemaPluralName(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) putSchemaPluralName(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) getSchemaFields(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
func (s *Server) putSchemaFields(w http.ResponseWriter, r *http.Request) {
	userID, err := s.userID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userID == "public" {
		redirectTo := fmt.Sprintf("/auth/login?target=%s", r.URL.Path)
		http.Redirect(w, r, redirectTo, http.StatusUnauthorized)
		return
	}
	if r.PathValue("orgID") != userID {
		http.Error(w, "403 forbidden", http.StatusForbidden)
		return
	}
}
