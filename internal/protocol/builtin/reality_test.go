// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	M "github.com/sagernet/sing/common/metadata"
)

func TestREALITYAuthenticationAndFallback(t *testing.T) {
	cert, trust := testutil.Certificate(t)
	pair, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ordinary target website") }))
	target.EnableHTTP2 = true
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	target.StartTLS()
	defer target.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	short := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	registry, err := builtin.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	limits := model.DefaultLimits()
	flow := relay.New(ctx, &egress.Direct{}, limits)
	defer flow.Close(context.Background())
	spec := model.ListenerSpec{ID: "reality", Enabled: true, Protocol: "vless", Address: "127.0.0.1", Options: []byte("{}"), CredentialRefs: []string{"user"}, Transport: model.Transport{Type: "reality", Reality: &model.Reality{AllowLegacyClients: true, Target: target.Listener.Addr().String(), ServerNames: []string{"localhost"}, PrivateKeyRef: "key", ShortIDs: []string{"0102030405060708"}}}}
	server, err := registry.Build(protocol.ResolvedListenerSpec{Spec: spec, Limits: limits, Credentials: map[string][]byte{"user": []byte(userID), "key": []byte(base64.RawURLEncoding.EncodeToString(key.Bytes()))}}, protocol.Dependencies{Handler: flow})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := server.Stop(cleanup); err != nil {
			t.Error(err)
		}
	}()
	if err = server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := server.(interface{ Addr() net.Addr }).Addr().String()
	raw, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	authenticated, err := testutil.RealityClient(ctx, raw, key.PublicKey().Bytes(), short, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	client := streamClient(t, "vless", authenticated, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	echo(t, client)
	legacyRaw, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer legacyRaw.Close()
	_ = legacyRaw.SetDeadline(time.Now().Add(3 * time.Second))
	legacyConn, err := testutil.LegacyRealityClient(ctx, legacyRaw, key.PublicKey().Bytes(), short, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	legacyClient := streamClient(t, "vless", legacyConn, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	echo(t, legacyClient)
	// Disabling compatibility on another listener leaves the new path intact
	// and rejects the exact same authenticated legacy ClientHello.
	strictSpec := spec
	strictSpec.Transport = spec.Transport.Clone()
	strictSpec.Transport.Reality.AllowLegacyClients = false
	strict, err := registry.Build(protocol.ResolvedListenerSpec{Spec: strictSpec, Limits: limits, Credentials: map[string][]byte{"user": []byte(userID), "key": []byte(base64.RawURLEncoding.EncodeToString(key.Bytes()))}}, protocol.Dependencies{Handler: flow})
	if err != nil {
		t.Fatal(err)
	}
	defer strict.Stop(context.Background())
	if err = strict.Start(ctx); err != nil {
		t.Fatal(err)
	}
	oldRaw, err := net.DialTimeout("tcp", strict.(interface{ Addr() net.Addr }).Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = oldRaw.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = testutil.LegacyRealityClient(ctx, oldRaw, key.PublicKey().Bytes(), short, "localhost")
	oldRaw.Close()
	if err == nil {
		t.Fatal("strict listener accepted legacy ClientHello")
	}
	legacyWrong, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = legacyWrong.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = testutil.LegacyRealityClient(ctx, legacyWrong, key.PublicKey().Bytes(), []byte{9}, "localhost")
	legacyWrong.Close()
	if err == nil {
		t.Fatal("compatibility bypassed short-ID authentication")
	}
	wrong, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrong.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = testutil.RealityClient(ctx, wrong, key.PublicKey().Bytes(), []byte{9}, "localhost")
	wrong.Close()
	if err == nil {
		t.Fatal("wrong short ID accepted")
	}
	httpTransport := &http.Transport{TLSClientConfig: trust}
	defer httpTransport.CloseIdleConnections()
	response, err := (&http.Client{Transport: httpTransport, Timeout: 3 * time.Second}).Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !strings.Contains(string(body), "ordinary target website") {
		t.Fatal("REALITY fallback failed", err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err = server.Stop(cleanup); err != nil {
		t.Fatal(err)
	}
	_ = legacyClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = legacyClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("legacy REALITY connection survived Stop")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = client.Read(make([]byte, 1)); err == nil {
		t.Fatal("REALITY connection survived Stop")
	}
}
