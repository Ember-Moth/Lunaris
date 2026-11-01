// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"io/fs"
)

func startTestServer(t *testing.T, assets fs.FS, ready func(context.Context) error) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Listener: listener, Assets: assets, Ready: ready})
	done := make(chan error, 1)
	go func() { done <- h.Run() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if h.IsRunning() {
			_ = h.Shutdown(ctx)
		}
		listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("server exit: %v", err)
			}
		case <-ctx.Done():
			t.Error("server did not stop")
		}
	})
	return "http://" + listener.Addr().String()
}

func TestRoutesAndEnvelope(t *testing.T) {
	assets := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>Lunaris</title>")}, "assets/app.js": {Data: []byte("console.log('ok')")}}
	baseURL := startTestServer(t, assets, func(context.Context) error { return nil })
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	cases := []struct {
		method, path string
		status, code int
		envelope     bool
	}{
		{"GET", "/healthz", 200, CodeOK, true},
		{"GET", "/api/v1/config/draft", 404, CodeNotFound, true},
		{"POST", "/healthz", 405, CodeMethodNotAllowed, true},
		{"GET", "/about", 200, 0, false},
		{"GET", "/assets/app.js", 200, 0, false},
		{"GET", "/assets/missing.js", 404, 0, false},
	}
	for _, test := range cases {
		t.Run(test.method+test.path, func(t *testing.T) {
			request, err := http.NewRequest(test.method, baseURL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			content, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status {
				t.Fatalf("status %d: %s", response.StatusCode, content)
			}
			if test.envelope {
				var body map[string]json.RawMessage
				if err := json.Unmarshal(content, &body); err != nil {
					t.Fatal(err)
				}
				if len(body) != 3 || body["msg"] == nil || body["data"] == nil {
					t.Fatalf("invalid envelope: %s", content)
				}
				var code int
				if err := json.Unmarshal(body["code"], &code); err != nil {
					t.Fatal(err)
				}
				if code != test.code {
					t.Fatalf("code %d, want %d", code, test.code)
				}
			} else if test.status == http.StatusNotFound && strings.Contains(string(content), "<title>Lunaris") {
				t.Fatal("missing asset fell back to the SPA")
			}
		})
	}
}

func TestHealthDoesNotExposeStorageErrors(t *testing.T) {
	baseURL := startTestServer(t, fstest.MapFS{}, func(context.Context) error { return errors.New("private storage path") })
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 503 || strings.Contains(string(content), "private storage path") {
		t.Fatalf("unexpected response: %s", content)
	}
}
