// SPDX-License-Identifier: GPL-3.0-only
package auth_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

const password = "administrator-test-password"

func fixture(t *testing.T) (*sqlite.Store, *auth.Service, string, string) {
	t.Helper()
	dir := t.TempDir()
	repo, err := sqlite.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repo.Close(); err != nil {
			t.Error(err)
		}
	})
	service, err := auth.New(repo, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnsureSetupFile(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, auth.SetupFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(path)
	if stat.Mode().Perm() != 0600 {
		t.Fatal("setup token permissions", stat.Mode())
	}
	return repo, service, strings.TrimSpace(string(raw)), dir
}
func initialize(t *testing.T, s *auth.Service, token string) model.AdminAccount {
	t.Helper()
	a, err := s.Initialize(context.Background(), token, "admin", password)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestSetupRaceAndSessionLifecycle(t *testing.T) {
	repo, service, token, dir := fixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := service.Initialize(ctx, token, "admin", password); results <- err })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, auth.ErrInitialized) && !errors.Is(err, auth.ErrLimited) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("setup did not elect one administrator", successes)
	}
	if _, err := os.Stat(filepath.Join(dir, auth.SetupFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("consumed token file remains")
	}
	if _, err := service.EnsureSetupFile(ctx, true); !errors.Is(err, auth.ErrInitialized) {
		t.Fatal("setup was reopened", err)
	}
	token1, view1, err := service.Login(ctx, "admin", password)
	if err != nil {
		t.Fatal(err)
	}
	token2, _, err := service.Login(ctx, "admin", password)
	if err != nil {
		t.Fatal(err)
	}
	a, s1, err := service.Session(ctx, token1)
	if err != nil || !auth.ValidCSRF(view1.CSRFToken, s1.CSRFToken) {
		t.Fatal(err)
	}
	if _, err := service.Reauthenticate(ctx, a, s1, password); err != nil {
		t.Fatal(err)
	}
	if err := service.Logout(ctx, s1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Session(ctx, token1); !errors.Is(err, auth.ErrAuthentication) {
		t.Fatal("logout did not revoke", err)
	}
	if _, err := service.Reauthenticate(ctx, a, s1, password); !errors.Is(err, auth.ErrAuthentication) {
		t.Fatal("revoked session gained sensitive access", err)
	}
	a, _, err = service.Session(ctx, token2)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ChangePassword(ctx, a, password, "replacement-test-password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Session(ctx, token2); !errors.Is(err, auth.ErrAuthentication) {
		t.Fatal("password change left a live session")
	}
	if _, _, err := service.Login(ctx, "admin", password); !errors.Is(err, auth.ErrAuthentication) {
		t.Fatal("old password accepted")
	}
	if _, _, err := service.Login(ctx, "admin", "replacement-test-password"); err != nil {
		t.Fatal(err)
	}
	account, err := repo.AdminAccount(ctx)
	if err != nil || strings.Contains(account.PasswordHash, password) || !strings.HasPrefix(account.PasswordHash, "$argon2id$") {
		t.Fatal("password was not stored with Argon2id")
	}
}

type delayedSessionStore struct {
	*sqlite.Store
	entered, release chan struct{}
}

func (s *delayedSessionStore) CreateAdminSession(ctx context.Context, value model.AdminSession) error {
	close(s.entered)
	<-s.release
	return s.Store.CreateAdminSession(ctx, value)
}
func TestLoginVerifiedBeforePasswordRotationCannotCreateSession(t *testing.T) {
	repo, s, token, dir := fixture(t)
	initialize(t, s, token)
	wrapped := &delayedSessionStore{Store: repo, entered: make(chan struct{}), release: make(chan struct{})}
	login, err := auth.New(wrapped, dir)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, _, err := login.Login(context.Background(), "admin", password); result <- err }()
	<-wrapped.entered
	if err := s.ResetPassword(context.Background(), "rotated-by-local-recovery"); err != nil {
		t.Fatal(err)
	}
	close(wrapped.release)
	if err := <-result; !errors.Is(err, auth.ErrAuthentication) {
		t.Fatal("stale login issued a session", err)
	}
}

type commitResponseFault struct{ *sqlite.Store }

func (s commitResponseFault) ChangeAdminPassword(ctx context.Context, id string, version int64, hash string) error {
	if err := s.Store.ChangeAdminPassword(ctx, id, version, hash); err != nil {
		return err
	}
	return context.Canceled
}
func TestPasswordCommitResponseFailureStillRevokes(t *testing.T) {
	repo, s, token, dir := fixture(t)
	initialize(t, s, token)
	session, _, err := s.Login(context.Background(), "admin", password)
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := s.Session(context.Background(), session)
	fault, err := auth.New(commitResponseFault{repo}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fault.ChangePassword(context.Background(), a, password, "new-durable-password"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := s.Session(context.Background(), session); !errors.Is(err, auth.ErrAuthentication) {
		t.Fatal("committed password rotation was undone")
	}
	if _, _, err := s.Login(context.Background(), "admin", "new-durable-password"); err != nil {
		t.Fatal(err)
	}
}
func TestExpiredSetupAndSessionAreRejected(t *testing.T) {
	repo, s, _, dir := fixture(t)
	ctx := context.Background()
	expired := auth.Token()
	if err := repo.SetSetupToken(ctx, auth.TokenHash(expired), time.Now().Add(-time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Initialize(ctx, expired, "admin", password); err == nil {
		t.Fatal("expired setup accepted")
	}
	if _, err := s.EnsureSetupFile(ctx, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, auth.SetupFilename))
	if err != nil {
		t.Fatal(err)
	}
	account := initialize(t, s, strings.TrimSpace(string(raw)))
	token := auth.Token()
	if err := repo.CreateAdminSession(ctx, model.AdminSession{TokenHash: auth.TokenHash(token), AccountID: account.ID, AccountVersion: account.Version, CSRFToken: auth.Token(), CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Session(ctx, token); !errors.Is(err, auth.ErrAuthentication) {
		t.Fatal("expired session accepted", err)
	}
}
func TestHashRejectsMaliciousParameters(t *testing.T) {
	if auth.VerifyPassword("$argon2id$v=19$m=4294967295,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password) {
		t.Fatal("unbounded Argon2 parameters accepted")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(hash, password) || auth.VerifyPassword(hash, password+"!") {
		t.Fatal("password verification failed")
	}
}
