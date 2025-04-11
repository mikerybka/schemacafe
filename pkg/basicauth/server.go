package basicauth

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/mikerybka/brass"
)

func NewServer(workdir string) *Server {
	return &Server{workdir}
}

type Server struct {
	Workdir string
}

func (s *Server) GetUserID(r *http.Request) (string, error) {
	// Get user ID from request
	userID := r.Header.Get("UserID")
	if userID == "" {
		cookie, err := r.Cookie("user_id")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return "public", nil
			}
			return "", err
		}
		userID = cookie.String()
	}

	// Get token from request
	token := r.Header.Get("Token")
	if token == "" {
		cookie, err := r.Cookie("token")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return "public", nil
			}
			return "", err
		}
		token = cookie.String()
	}

	// Check if session is legit
	path := filepath.Join(s.Workdir, "users", userID, "sessions", token)
	ok, err := brass.ReadBool(path)
	if err != nil {
		return "", err
	}
	if !ok {
		return "public", nil
	}

	// Return user ID
	return userID, nil
}

func (s *Server) Join(username, password, confirmPassword string) (string, error) {
	fmt.Println(username, password, confirmPassword)
	panic("not yet implemented")
}
func (s *Server) Login(username, password string) (string, error) {
	panic("not yet implemented")
}
func (s *Server) Logout(username, token string) error {
	panic("not yet implemented")
}
