// SPDX-License-Identifier: GPL-3.0-only
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
)

var (
	ErrAuthentication = errors.New("authentication failed")
	ErrInitialized    = errors.New("administrator is already initialized")
	ErrInvalidInput   = errors.New("invalid authentication input")
	ErrLimited        = errors.New("authentication is busy")
)

const SessionLifetime = 12 * time.Hour
const ReauthLifetime = 5 * time.Minute
const SetupLifetime = 30 * time.Minute
const SetupFilename = "setup-token"

type SetupState struct {
	Initialized bool
	TokenHash   string
	ExpiresAt   time.Time
}
type Repository interface {
	AuthSetupState(context.Context) (SetupState, error)
	SetSetupToken(context.Context, string, time.Time, bool) error
	InitializeAdmin(context.Context, string, string, string, time.Time) (model.AdminAccount, error)
	AdminAccount(context.Context) (model.AdminAccount, error)
	CreateAdminSession(context.Context, model.AdminSession) error
	AdminSession(context.Context, string, time.Time) (model.AdminAccount, model.AdminSession, error)
	RevokeAdminSession(context.Context, string) error
	ChangeAdminPassword(context.Context, string, int64, string) error
	GrantReauth(context.Context, string, int64, time.Time, time.Time) error
	PurgeAdminSessions(context.Context, time.Time) error
}
type Service struct {
	repo  Repository
	dir   string
	slots chan struct{}
	dummy string
}
type SessionView struct {
	Account   model.AdminAccount `json:"account"`
	ExpiresAt time.Time          `json:"expires_at"`
	CSRFToken string             `json:"csrf_token"`
}

func New(repo Repository, dir string) (*Service, error) {
	if repo == nil {
		return nil, errors.New("authentication repository is required")
	}
	dummy, err := HashPassword(rand.Text())
	if err != nil {
		return nil, err
	}
	return &Service{repo: repo, dir: dir, slots: make(chan struct{}, 2), dummy: dummy}, nil
}
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func (s *Service) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
		return nil
	default:
		return ErrLimited
	}
}
func (s *Service) SetupStatus(ctx context.Context) (bool, error) {
	v, err := s.repo.AuthSetupState(ctx)
	return !v.Initialized, err
}
func (s *Service) EnsureSetupFile(ctx context.Context, renew bool) (time.Time, error) {
	state, err := s.repo.AuthSetupState(ctx)
	if err != nil {
		return time.Time{}, err
	}
	path := filepath.Join(s.dir, SetupFilename)
	if state.Initialized {
		if renew {
			return time.Time{}, ErrInitialized
		}
		_ = os.Remove(path)
		return time.Time{}, nil
	}
	if state.TokenHash != "" && !renew {
		info, err := os.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return time.Time{}, err
		}
		if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
			return time.Time{}, errors.New("setup token file must be a private regular file")
		}
		return state.ExpiresAt, nil
	}
	token := Token()
	expires := time.Now().UTC().Add(SetupLifetime)
	f, err := os.CreateTemp(s.dir, ".setup-token-")
	if err != nil {
		return time.Time{}, err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.WriteString(token + "\n")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return time.Time{}, err
	}
	if err = s.repo.SetSetupToken(ctx, TokenHash(token), expires, renew); err != nil {
		return time.Time{}, err
	}
	if err = os.Rename(temp, path); err != nil {
		return time.Time{}, err
	}
	if d, e := os.Open(s.dir); e == nil {
		err = d.Sync()
		d.Close()
	} else {
		err = e
	}
	return expires, err
}
func (s *Service) Initialize(ctx context.Context, token, username, password string) (model.AdminAccount, error) {
	if !ValidUsername(username) || !ValidPassword(password) || len(token) != 43 {
		return model.AdminAccount{}, ErrInvalidInput
	}
	state, err := s.repo.AuthSetupState(ctx)
	if err != nil {
		return model.AdminAccount{}, err
	}
	if state.Initialized {
		return model.AdminAccount{}, ErrInitialized
	}
	digest := TokenHash(token)
	if !state.ExpiresAt.After(time.Now()) || subtle.ConstantTimeCompare([]byte(state.TokenHash), []byte(digest)) != 1 {
		return model.AdminAccount{}, ErrAuthentication
	}
	if err = s.acquire(ctx); err != nil {
		return model.AdminAccount{}, err
	}
	defer func() { <-s.slots }()
	hash, err := HashPassword(password)
	if err != nil {
		return model.AdminAccount{}, err
	}
	account, err := s.repo.InitializeAdmin(ctx, digest, username, hash, time.Now().UTC())
	// The database is authoritative even if COMMIT's response was cancelled.
	check, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if needed, e := s.SetupStatus(check); e == nil && !needed {
		_ = os.Remove(filepath.Join(s.dir, SetupFilename))
	}
	return account, err
}
func (s *Service) Login(ctx context.Context, username, password string) (string, SessionView, error) {
	if len(username) > 64 || len(password) > 1024 {
		return "", SessionView{}, ErrAuthentication
	}
	if err := s.acquire(ctx); err != nil {
		return "", SessionView{}, err
	}
	defer func() { <-s.slots }()
	account, err := s.repo.AdminAccount(ctx)
	if err != nil && !errors.Is(err, ports.ErrNotFound) {
		return "", SessionView{}, err
	}
	encoded := s.dummy
	if err == nil {
		encoded = account.PasswordHash
	}
	valid := VerifyPassword(encoded, password)
	if err != nil || !valid || subtle.ConstantTimeCompare([]byte(username), []byte(account.Username)) != 1 {
		return "", SessionView{}, ErrAuthentication
	}
	token := Token()
	now := time.Now().UTC()
	session := model.AdminSession{TokenHash: TokenHash(token), AccountID: account.ID, AccountVersion: account.Version, CSRFToken: Token(), CreatedAt: now, ExpiresAt: now.Add(SessionLifetime)}
	if err := s.repo.CreateAdminSession(ctx, session); err != nil {
		return "", SessionView{}, err
	}
	return token, view(account, session), nil
}
func view(a model.AdminAccount, s model.AdminSession) SessionView {
	return SessionView{Account: a, ExpiresAt: s.ExpiresAt, CSRFToken: s.CSRFToken}
}
func (s *Service) Session(ctx context.Context, token string) (model.AdminAccount, model.AdminSession, error) {
	if len(token) != 43 {
		return model.AdminAccount{}, model.AdminSession{}, ErrAuthentication
	}
	a, session, err := s.repo.AdminSession(ctx, TokenHash(token), time.Now().UTC())
	if errors.Is(err, ports.ErrNotFound) {
		err = ErrAuthentication
	}
	return a, session, err
}
func (s *Service) View(a model.AdminAccount, session model.AdminSession) SessionView {
	return view(a, session)
}
func (s *Service) Logout(ctx context.Context, session model.AdminSession) error {
	return s.repo.RevokeAdminSession(ctx, session.TokenHash)
}
func (s *Service) checkPassword(ctx context.Context, a model.AdminAccount, password string) (model.AdminAccount, error) {
	current, err := s.repo.AdminAccount(ctx)
	if err != nil {
		return current, err
	}
	if current.ID != a.ID || current.Version != a.Version || !VerifyPassword(current.PasswordHash, password) {
		return current, ErrAuthentication
	}
	return current, nil
}
func (s *Service) ChangePassword(ctx context.Context, a model.AdminAccount, current, newPassword string) error {
	if !ValidPassword(newPassword) || len(current) > 1024 {
		return ErrInvalidInput
	}
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-s.slots }()
	account, err := s.checkPassword(ctx, a, current)
	if err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.repo.ChangeAdminPassword(ctx, account.ID, account.Version, hash)
}
func (s *Service) Reauthenticate(ctx context.Context, a model.AdminAccount, session model.AdminSession, password string) (time.Time, error) {
	if len(password) > 1024 {
		return time.Time{}, ErrAuthentication
	}
	if err := s.acquire(ctx); err != nil {
		return time.Time{}, err
	}
	defer func() { <-s.slots }()
	if _, err := s.checkPassword(ctx, a, password); err != nil {
		return time.Time{}, err
	}
	now := time.Now().UTC()
	until := now.Add(ReauthLifetime)
	return until, s.repo.GrantReauth(ctx, session.TokenHash, a.Version, now, until)
}
func (s *Service) ResetPassword(ctx context.Context, password string) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-s.slots }()
	account, err := s.repo.AdminAccount(ctx)
	if err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.repo.ChangeAdminPassword(ctx, account.ID, account.Version, hash)
}
func (s *Service) Purge(ctx context.Context) error {
	return s.repo.PurgeAdminSessions(ctx, time.Now().UTC())
}
func ValidCSRF(got, want string) bool {
	return len(got) == 43 && !strings.ContainsAny(got, "\r\n") && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
