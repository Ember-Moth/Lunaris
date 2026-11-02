// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	ss "github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

const adminPassword = "test-administrator-password"

type managementTest struct {
	url, origin, setup, csrf string
	cookie                   *http.Cookie
	client                   *http.Client
	repo                     *sqlite.Store
	service                  *config.Service
	api                      *API
	dir                      string
}
type envelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func startManagement(t *testing.T, secure bool, proxies []netip.Prefix) *managementTest {
	return startManagementRepo(t, secure, proxies, nil)
}
func startManagementRepo(t *testing.T, secure bool, proxies []netip.Prefix, decorate func(*sqlite.Store) ports.ManagementRepository) *managementTest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	repository, err := sqlite.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := TrackListener(raw)
	storage := ports.ManagementRepository(repository)
	if decorate != nil {
		storage = decorate(repository)
	}
	registry, _ := builtin.NewRegistry()
	endpoint, _ := netip.ParseAddrPort(raw.Addr().String())
	service, err := config.OpenManagementService(ctx, storage, registry, []netip.AddrPort{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := auth.New(repository, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authentication.EnsureSetupFile(ctx, false); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(filepath.Join(dir, auth.SetupFilename))
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	var serverTLS, clientTLS *tls.Config
	if secure {
		scheme = "https"
		asset, trust := testutil.Certificate(t)
		pair, err := tls.X509KeyPair(asset.Certificate, asset.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		serverTLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		clientTLS = trust
	}
	base := scheme + "://" + raw.Addr().String()
	origin := base
	if len(proxies) > 0 {
		origin = "https://manage.example.com"
	}
	api, err := NewAPI(ctx, APIOptions{Repository: storage, Service: service, Registry: registry, Auth: authentication, Origin: origin, NativeTLS: secure, TrustedProxies: proxies, Version: Version{Version: "test", APISchema: "lunaris-management-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Listener: listener, Assets: fstest.MapFS{"index.html": {Data: []byte("test frontend")}}, Ready: repository.Ping, API: api, TLS: serverTLS})
	done := make(chan error, 1)
	go func() { done <- h.Run() }()
	transport := &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true}
	test := &managementTest{url: base, origin: origin, setup: strings.TrimSpace(string(token)), client: &http.Client{Transport: transport, Timeout: 8 * time.Second}, repo: repository, service: service, api: api, dir: dir}
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if h.IsRunning() {
			_ = h.Shutdown(cleanup)
		}
		listener.Close()
		listener.CloseConnections()
		select {
		case <-done:
		case <-cleanup.Done():
			t.Error("HTTP shutdown timed out")
		}
		if err := service.Close(cleanup); err != nil {
			t.Error(err)
		}
		if err := repository.Close(); err != nil {
			t.Error(err)
		}
		transport.CloseIdleConnections()
	})
	return test
}
func (m *managementTest) request(t *testing.T, method, path string, body any, headers map[string]string) (*http.Response, envelope, []byte) {
	t.Helper()
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, m.url+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Origin", m.origin)
	if m.cookie != nil {
		request.AddCookie(m.cookie)
	}
	if m.csrf != "" {
		request.Header.Set("X-CSRF-Token", m.csrf)
	}
	for key, value := range headers {
		if key == "Host" {
			request.Host = value
		} else if value == "" {
			request.Header.Del(key)
		} else {
			request.Header.Set(key, value)
		}
	}
	response, err := m.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var result envelope
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("non-JSON response %d: %s", response.StatusCode, data)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	return response, result, data
}
func expectStatus(t *testing.T, r *http.Response, want int, e envelope) {
	t.Helper()
	if r.StatusCode != want {
		t.Fatalf("HTTP %d, want %d: %+v %s", r.StatusCode, want, e, e.Data)
	}
}
func dataAs[T any](t *testing.T, e envelope) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(e.Data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func (m *managementTest) initialize(t *testing.T) {
	t.Helper()
	r, e, _ := m.request(t, "POST", "/api/v1/setup", map[string]string{"token": m.setup, "username": "admin", "password": adminPassword}, nil)
	expectStatus(t, r, 201, e)
}
func (m *managementTest) login(t *testing.T, password string) {
	t.Helper()
	r, e, _ := m.request(t, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": password}, nil)
	expectStatus(t, r, 200, e)
	v := dataAs[auth.SessionView](t, e)
	m.csrf = v.CSRFToken
	cookies := r.Cookies()
	if len(cookies) != 1 {
		t.Fatal("login cookie absent")
	}
	m.cookie = cookies[0]
	if !m.cookie.HttpOnly || m.cookie.SameSite != http.SameSiteStrictMode || m.cookie.Path != "/" || m.cookie.Domain != "" {
		t.Fatal("unsafe cookie", m.cookie)
	}
}
func (m *managementTest) asset(t *testing.T, secret string) model.CredentialAsset {
	t.Helper()
	r, e, raw := m.request(t, "POST", "/api/v1/credentials", map[string]any{"kind": "password", "label": "device", "secret": secret}, nil)
	expectStatus(t, r, 201, e)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("credential response exposed secret")
	}
	return dataAs[model.CredentialAsset](t, e)
}
func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return port
}
func (m *managementTest) waitOperation(t *testing.T, id string) model.ApplyOperation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, e, _ := m.request(t, "GET", "/api/v1/operations/"+id, nil, nil)
		expectStatus(t, r, 200, e)
		op := dataAs[model.ApplyOperation](t, e)
		if op.Terminal() {
			return op
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("operation stuck")
	return model.ApplyOperation{}
}
func TestManagementHTTPWorkflow(t *testing.T) {
	m := startManagement(t, false, nil)
	r, e, raw := m.request(t, "GET", "/api/v1/setup/status", nil, nil)
	expectStatus(t, r, 200, e)
	if string(e.Data) != "{\"needs_setup\":true}" {
		t.Fatal(string(raw))
	}
	r, e, _ = m.request(t, "GET", "/api/v1/status", nil, nil)
	expectStatus(t, r, 401, e)
	m.initialize(t)
	m.login(t, adminPassword)
	asset := m.asset(t, "proxy-secret-before-rotation")
	port := freeTCPPort(t)
	draft := model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "ss", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: port, Network: []string{"tcp"}, CredentialRefs: []string{"device"}, Options: []byte(`{"method":"aes-128-gcm"}`)}}}, CredentialAssets: map[string]string{"device": asset.ID}, CertificateAssets: map[string]string{}}
	r, e, _ = m.request(t, "PUT", "/api/v1/config/draft", draft, nil)
	expectStatus(t, r, 428, e)
	r, e, _ = m.request(t, "PUT", "/api/v1/config/draft", draft, map[string]string{"If-Match": "\"r0\""})
	expectStatus(t, r, 200, e)
	saved := dataAs[model.ConfigRevision](t, e)
	if saved.CredentialAssets["device"] != asset.ID || r.Header.Get("ETag") != "\""+saved.ID+"\"" {
		t.Fatal("asset binding or ETag incorrect")
	}
	r, e, _ = m.request(t, "PUT", "/api/v1/config/draft", draft, map[string]string{"If-Match": "\"r0\""})
	expectStatus(t, r, 412, e)
	r, e, _ = m.request(t, "POST", "/api/v1/config/plans", map[string]string{"draft_revision": saved.ID, "base_revision": "r0"}, nil)
	expectStatus(t, r, 200, e)
	plan := dataAs[config.ApplicationPlan](t, e)
	body := map[string]any{"plan_id": plan.ID, "acknowledge_disconnects": false}
	r, e, _ = m.request(t, "POST", "/api/v1/config/apply", body, map[string]string{"Idempotency-Key": "first-apply"})
	expectStatus(t, r, 202, e)
	accepted := dataAs[struct {
		ID string `json:"operation_id"`
	}](t, e)
	if r.Header.Get("Location") != "/api/v1/operations/"+accepted.ID {
		t.Fatal("missing operation location")
	}
	if final := m.waitOperation(t, accepted.ID); final.Status != "succeeded" {
		t.Fatal(final)
	}
	r, e, _ = m.request(t, "POST", "/api/v1/config/apply", body, map[string]string{"Idempotency-Key": "first-apply"})
	expectStatus(t, r, 202, e)
	if dataAs[struct {
		ID string `json:"operation_id"`
	}](t, e).ID != accepted.ID {
		t.Fatal("request replay created another operation")
	}
	body["acknowledge_disconnects"] = true
	r, e, _ = m.request(t, "POST", "/api/v1/config/apply", body, map[string]string{"Idempotency-Key": "first-apply"})
	expectStatus(t, r, 409, e)
	if e.Code != 40903 {
		t.Fatal(e)
	}
	connection := map[string]any{"committed_revision": saved.ID, "host": "127.0.0.1", "credential_ref": "device"}
	r, e, _ = m.request(t, "POST", "/api/v1/listeners/ss/connection-info", connection, nil)
	expectStatus(t, r, 403, e)
	r, e, _ = m.request(t, "POST", "/api/v1/auth/reauth", map[string]string{"password": adminPassword}, nil)
	expectStatus(t, r, 200, e)
	r, e, raw = m.request(t, "POST", "/api/v1/listeners/ss/connection-info", connection, nil)
	expectStatus(t, r, 200, e)
	if !bytes.Contains(raw, []byte("proxy-secret-before-rotation")) {
		t.Fatal("reauthenticated export missing selected credential")
	}
	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(2 * time.Second))
	method, err := ss.New("aes-128-gcm", nil, "proxy-secret-before-rotation")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := method.DialConn(rawConn, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = proxy.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err = io.ReadFull(proxy, response); err != nil || string(response) != "live" {
		t.Fatal("API-applied node did not forward", err)
	}
	r, e, _ = m.request(t, "DELETE", "/api/v1/credentials/"+asset.ID, nil, nil)
	expectStatus(t, r, 409, e)
	if e.Code != 40905 {
		t.Fatal(e)
	}
	for _, path := range []string{"/api/v1/config/draft", "/api/v1/config/committed", "/api/v1/credentials", "/api/v1/status", "/api/v1/logs", "/api/v1/config/template"} {
		r, e, raw = m.request(t, "GET", path, nil, nil)
		expectStatus(t, r, 200, e)
		if bytes.Contains(raw, []byte("proxy-secret-before-rotation")) || bytes.Contains(raw, []byte(adminPassword)) || bytes.Contains(raw, []byte(m.setup)) {
			t.Fatalf("secret exposed by %s", path)
		}
	}
	r, e, _ = m.request(t, "POST", "/api/v1/auth/logout", nil, nil)
	expectStatus(t, r, 200, e)
	r, e, _ = m.request(t, "GET", "/api/v1/status", nil, nil)
	expectStatus(t, r, 401, e)
}
func TestManagementHTTPOriginCSRFAndCookieSecurity(t *testing.T) {
	m := startManagement(t, true, nil)
	m.initialize(t)
	m.login(t, adminPassword)
	if !m.cookie.Secure || !strings.HasPrefix(m.cookie.Name, "__Host-") {
		t.Fatal("HTTPS cookie is not host-bound secure")
	}
	for _, headers := range []map[string]string{{"Origin": "https://attacker.example"}, {"Origin": ""}, {"Host": "attacker.example"}, {"X-CSRF-Token": "wrong"}, {"Sec-Fetch-Site": "cross-site"}} {
		r, e, _ := m.request(t, "POST", "/api/v1/auth/logout", nil, headers)
		expectStatus(t, r, 403, e)
	}
	r, e, _ := m.request(t, "GET", "/api/v1/status", nil, map[string]string{"X-Forwarded-Host": "attacker.example", "X-Forwarded-Proto": "http"})
	expectStatus(t, r, 200, e)
	r, e, _ = m.request(t, "PUT", "/api/v1/auth/password", map[string]string{"current_password": adminPassword, "new_password": "next-administrator-password"}, nil)
	expectStatus(t, r, 200, e)
	r, e, _ = m.request(t, "GET", "/api/v1/auth/session", nil, nil)
	expectStatus(t, r, 401, e)
	m.login(t, "next-administrator-password")
	r, e, _ = m.request(t, "GET", "/api/v1/unknown-route", nil, nil)
	expectStatus(t, r, 404, e)
}
func TestManagementHTTPInputLimits(t *testing.T) {
	m := startManagement(t, false, nil)
	m.initialize(t)
	m.login(t, adminPassword)
	r, e, raw := m.request(t, "POST", "/api/v1/credentials", map[string]any{"kind": "password", "secret": "never-echo-this-secret", "unexpected": "never-echo-this-secret"}, nil)
	expectStatus(t, r, 400, e)
	if bytes.Contains(raw, []byte("never-echo-this-secret")) {
		t.Fatal("decoder echoed rejected secret")
	}
	r, e, _ = m.request(t, "POST", "/api/v1/credentials", map[string]any{"kind": "password", "secret": strings.Repeat("x", 20<<10)}, nil)
	expectStatus(t, r, 413, e)
	r, e, _ = m.request(t, "GET", "/api/v1/credentials?limit=101", nil, nil)
	expectStatus(t, r, 400, e)
	r, e, _ = m.request(t, "GET", "/api/v1/credentials?limit=1&limit=2", nil, nil)
	expectStatus(t, r, 400, e)
	r, e, _ = m.request(t, "POST", "/api/v1/config/import", map[string]any{"content": "credentials:\n - id: key\n   secret_file: /etc/passwd\n"}, map[string]string{"If-Match": "\"r0\""})
	expectStatus(t, r, 422, e)
}
func TestTrustedProxyHeadersRequireConfiguredPeer(t *testing.T) {
	m := startManagement(t, false, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	headers := map[string]string{"Host": "manage.example.com", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "manage.example.com", "X-Forwarded-For": "198.18.0.1"}
	r, e, _ := m.request(t, "GET", "/api/v1/setup/status", nil, headers)
	expectStatus(t, r, 200, e)
	headers["X-Forwarded-Proto"] = "http"
	r, e, _ = m.request(t, "GET", "/api/v1/setup/status", nil, headers)
	expectStatus(t, r, 403, e)
	untrusted := startManagement(t, false, []netip.Prefix{netip.MustParsePrefix("10.88.0.0/24")})
	headers["X-Forwarded-Proto"] = "https"
	r, e, _ = untrusted.request(t, "GET", "/api/v1/setup/status", nil, headers)
	expectStatus(t, r, 403, e)
}

type httpApplyBarrier struct {
	ports.ManagementRepository
	entered, release chan struct{}
}

func (b *httpApplyBarrier) SetPhase(ctx context.Context, id, phase string) error {
	if phase == "applying" {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return b.ManagementRepository.SetPhase(ctx, id, phase)
}
func TestHTTPDisconnectAndLogoutDoNotCancelAcceptedApply(t *testing.T) {
	var barrier *httpApplyBarrier
	m := startManagementRepo(t, false, nil, func(s *sqlite.Store) ports.ManagementRepository {
		barrier = &httpApplyBarrier{ManagementRepository: s, entered: make(chan struct{}), release: make(chan struct{})}
		return barrier
	})
	m.initialize(t)
	m.login(t, adminPassword)
	r, e, _ := m.request(t, "POST", "/api/v1/config/plans", map[string]string{"draft_revision": "r0", "base_revision": "r0"}, nil)
	expectStatus(t, r, 200, e)
	plan := dataAs[config.ApplicationPlan](t, e)
	payload, _ := json.Marshal(map[string]any{"plan_id": plan.ID, "acknowledge_disconnects": false})
	request, _ := http.NewRequest("POST", m.url+"/api/v1/config/apply", bytes.NewReader(payload))
	request.Header.Set("Origin", m.origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", m.csrf)
	request.Header.Set("Idempotency-Key", "disconnected-browser")
	request.AddCookie(m.cookie)
	raw, err := net.DialTimeout("tcp", strings.TrimPrefix(m.url, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(raw); err != nil {
		t.Fatal(err)
	}
	select {
	case <-barrier.entered:
	case <-time.After(3 * time.Second):
		raw.Close()
		t.Fatal("apply was not accepted")
	}
	raw.Close()
	r, e, _ = m.request(t, "GET", "/api/v1/status", nil, nil)
	expectStatus(t, r, 200, e)
	state := dataAs[config.ServiceStatus](t, e)
	if !state.Applying || state.ActiveOperation == "" {
		t.Fatal("request cancellation stopped accepted job")
	}
	r, e, _ = m.request(t, "POST", "/api/v1/credentials", map[string]any{"kind": "password", "secret": "busy-proxy-secret"}, nil)
	expectStatus(t, r, 409, e)
	r, e, _ = m.request(t, "POST", "/api/v1/auth/logout", nil, nil)
	expectStatus(t, r, 200, e)
	m.login(t, adminPassword)
	close(barrier.release)
	if final := m.waitOperation(t, state.ActiveOperation); final.Status != "succeeded" {
		t.Fatal("logout canceled an accepted operation", final)
	}
	r, e, _ = m.request(t, "POST", "/api/v1/config/apply", map[string]any{"plan_id": plan.ID, "acknowledge_disconnects": false}, map[string]string{"Idempotency-Key": "disconnected-browser"})
	expectStatus(t, r, 202, e)
	if dataAs[struct {
		ID string `json:"operation_id"`
	}](t, e).ID != state.ActiveOperation {
		t.Fatal("relogin changed idempotency scope")
	}
}
func TestLogCursorsAndBounds(t *testing.T) {
	logs := NewLogs("first-boot")
	for range 520 {
		logs.Add("info", "safe message", "")
	}
	first, err := logs.Page("", 100)
	if err != nil || !first.Truncated || len(first.Entries) != 100 || first.Entries[0].Sequence != 9 {
		t.Fatal(first, err)
	}
	second, err := logs.Page(first.NextCursor, 100)
	if err != nil || len(second.Entries) != 100 || second.Entries[0].Sequence != 109 {
		t.Fatal(second, err)
	}
	restarted := NewLogs("new-boot")
	restarted.Add("info", "restarted", "")
	page, err := restarted.Page(first.NextCursor, 100)
	if err != nil || !page.Restarted || !page.Truncated {
		t.Fatal(page, err)
	}
}
func TestTemplateRejectsAliasesAndDuplicateFields(t *testing.T) {
	for _, input := range []string{"a: &anchor [1,2]\nb: *anchor", "config: {}\nconfig: {}", "---\nconfig: {}\n---\nconfig: {}", "config: !!python/object abc"} {
		if _, err := templateJSON(input); err == nil {
			t.Fatal("unsafe YAML accepted")
		}
	}
	if _, err := templateJSON("config:\n  schema_version: 1\n  listeners: []\ncredential_assets: {}\ncertificate_assets: {}\n"); err != nil {
		t.Fatal(err)
	}
}

func TestAPIRequiresDisconnectAcknowledgementAndRetainsHistory(t *testing.T) {
	m := startManagement(t, false, nil)
	m.initialize(t)
	m.login(t, adminPassword)
	initial := m.asset(t, "initial-proxy-password")
	replacement := m.asset(t, "replacement-proxy-password")
	port := freeTCPPort(t)
	input := model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "ss", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: port, Network: []string{"tcp"}, CredentialRefs: []string{"key"}, Options: []byte(`{"method":"aes-128-gcm"}`)}}}, CredentialAssets: map[string]string{"key": initial.ID}, CertificateAssets: map[string]string{}}
	save := func(expected string) model.ConfigRevision {
		r, e, _ := m.request(t, "PUT", "/api/v1/config/draft", input, map[string]string{"If-Match": "\"" + expected + "\""})
		expectStatus(t, r, 200, e)
		return dataAs[model.ConfigRevision](t, e)
	}
	plan := func(draft, base string) config.ApplicationPlan {
		r, e, _ := m.request(t, "POST", "/api/v1/config/plans", map[string]string{"draft_revision": draft, "base_revision": base}, nil)
		expectStatus(t, r, 200, e)
		return dataAs[config.ApplicationPlan](t, e)
	}
	first := save("r0")
	preview := plan(first.ID, "r0")
	r, e, _ := m.request(t, "POST", "/api/v1/config/apply", map[string]any{"plan_id": preview.ID}, map[string]string{"Idempotency-Key": "start-ss"})
	expectStatus(t, r, 202, e)
	op := dataAs[struct {
		ID string `json:"operation_id"`
	}](t, e)
	if result := m.waitOperation(t, op.ID); result.Status != "succeeded" {
		t.Fatal(result)
	}
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
	cipher, _ := ss.New("aes-128-gcm", nil, "initial-proxy-password")
	conn, err := cipher.DialConn(raw, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	exchange := func() {
		t.Helper()
		if _, err := conn.Write([]byte("keep")); err != nil {
			t.Fatal(err)
		}
		value := make([]byte, 4)
		if _, err := io.ReadFull(conn, value); err != nil {
			t.Fatal(err)
		}
	}
	exchange()
	input.CredentialAssets["key"] = replacement.ID
	next := save(first.ID)
	preview = plan(next.ID, first.ID)
	if len(preview.Changes) != 1 || !preview.Changes[0].ClosesConnections {
		t.Fatal("disconnect impact omitted")
	}
	r, e, _ = m.request(t, "POST", "/api/v1/config/apply", map[string]any{"plan_id": preview.ID}, map[string]string{"Idempotency-Key": "rotate-ss"})
	expectStatus(t, r, 409, e)
	if e.Code != 40904 {
		t.Fatal(e)
	}
	exchange()
	r, e, _ = m.request(t, "POST", "/api/v1/config/apply", map[string]any{"plan_id": preview.ID, "acknowledge_disconnects": true}, map[string]string{"Idempotency-Key": "rotate-ss"})
	expectStatus(t, r, 202, e)
	op = dataAs[struct {
		ID string `json:"operation_id"`
	}](t, e)
	if result := m.waitOperation(t, op.ID); result.Status != "succeeded" {
		t.Fatal(result)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("old connection survived credential rotation")
	}
	r, e, _ = m.request(t, "DELETE", "/api/v1/credentials/"+initial.ID, nil, nil)
	expectStatus(t, r, 409, e)
	r, e, _ = m.request(t, "GET", "/api/v1/config/template", nil, nil)
	expectStatus(t, r, 200, e)
	template := dataAs[struct {
		Content string `json:"content"`
	}](t, e)
	r, e, _ = m.request(t, "POST", "/api/v1/config/import", map[string]string{"content": template.Content}, map[string]string{"If-Match": "\"" + next.ID + "\""})
	expectStatus(t, r, 200, e)
	if imported := dataAs[model.ConfigRevision](t, e); imported.ID != next.ID {
		t.Fatal("template round trip changed configuration")
	}
}
func TestLoginRateLimitAndDuplicateCookie(t *testing.T) {
	m := startManagement(t, false, nil)
	m.initialize(t)
	m.login(t, adminPassword)
	duplicate := m.cookie.Name + "=" + m.cookie.Value + "; " + m.cookie.Name + "=invalid"
	r, e, _ := m.request(t, "GET", "/api/v1/status", nil, map[string]string{"Cookie": duplicate})
	expectStatus(t, r, 401, e)
	for range 4 {
		r, e, _ = m.request(t, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "incorrect-password"}, nil)
		expectStatus(t, r, 401, e)
	}
	r, e, _ = m.request(t, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": adminPassword}, nil)
	expectStatus(t, r, 429, e)
}
