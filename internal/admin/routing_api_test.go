// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	ss "github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/encoding/protowire"
)

func apiGeoData() []byte {
	domain := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 3)
	domain = protowire.AppendString(protowire.AppendTag(domain, 2, protowire.BytesType), "blocked.test")
	category := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "TEST")
	category = protowire.AppendBytes(protowire.AppendTag(category, 2, protowire.BytesType), domain)
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), category)
}
func (m *managementTest) uploadGeo(t *testing.T, kind string, data []byte) (*http.Response, envelope) {
	t.Helper()
	request, err := http.NewRequest("POST", m.url+"/api/v1/geodata?kind="+kind+"&label=test", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", m.origin)
	request.Header.Set("X-CSRF-Token", m.csrf)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.AddCookie(m.cookie)
	response, err := m.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var e envelope
	if err := json.NewDecoder(response.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	return response, e
}
func TestRoutingGeoDataManagementAndRuntimeApply(t *testing.T) {
	m := startManagement(t, false, nil)
	m.initialize(t)
	m.login(t, adminPassword)
	r, e := m.uploadGeo(t, "geosite", apiGeoData())
	expectStatus(t, r, 201, e)
	asset := dataAs[model.GeoDataAsset](t, e)
	r, e = m.uploadGeo(t, "geosite", apiGeoData())
	expectStatus(t, r, 201, e)
	if dataAs[model.GeoDataAsset](t, e).ID != asset.ID {
		t.Fatal("retry created a new dataset")
	}
	r, e = m.uploadGeo(t, "geoip", apiGeoData())
	expectStatus(t, r, 422, e)
	dnsAddress := managementDNS(t)
	secret := "routing-management-password"
	credential := m.asset(t, secret)
	port := freeTCPPort(t)
	input := model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "ss", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: port, Network: []string{"tcp", "udp"}, CredentialRefs: []string{"key"}, Options: []byte(`{"method":"aes-128-gcm"}`)}}, GeoData: map[string]string{"geosite": asset.ID}, Route: &model.RouteConfig{Block: []string{"geosite:test"}}, DNS: &model.DNSConfig{Strategy: "only_ipv4", Servers: []model.DNSServer{{Proto: "udp", Address: dnsAddress}}}}, CredentialAssets: map[string]string{"key": credential.ID}, CertificateAssets: map[string]string{}}
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
	apply := func(p config.ApplicationPlan, key string, ack bool) {
		r, e, _ := m.request(t, "POST", "/api/v1/config/apply", map[string]any{"plan_id": p.ID, "acknowledge_disconnects": ack}, map[string]string{"Idempotency-Key": key})
		expectStatus(t, r, 202, e)
		op := dataAs[struct {
			ID string `json:"operation_id"`
		}](t, e)
		if result := m.waitOperation(t, op.ID); result.Status != "succeeded" {
			t.Fatal(result)
		}
	}
	first := save("r0")
	apply(plan(first.ID, "r0"), "routing-first", false)
	r, e, _ = m.request(t, "POST", "/api/v1/auth/reauth", map[string]string{"password": adminPassword}, nil)
	expectStatus(t, r, 200, e)
	r, e, _ = m.request(t, "POST", "/api/v1/listeners/ss/connection-info", map[string]string{"committed_revision": first.ID, "host": "127.0.0.1", "credential_ref": "key"}, nil)
	expectStatus(t, r, 200, e)
	r, e, _ = m.request(t, "DELETE", "/api/v1/geodata/"+asset.ID, nil, nil)
	expectStatus(t, r, 409, e)
	if e.Code != 40905 {
		t.Fatal("geodata reference protection missing", e)
	}
	target := testutil.TCPEcho(t)
	dial := func(destination M.Socksaddr) net.Conn {
		raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		raw.SetDeadline(time.Now().Add(2 * time.Second))
		cipher, err := ss.New("aes-128-gcm", nil, secret)
		if err != nil {
			t.Fatal(err)
		}
		client, err := cipher.DialConn(raw, destination)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		return client
	}
	allowed := dial(M.SocksaddrFromNet(target))
	defer allowed.Close()
	if _, err := allowed.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err := io.ReadFull(allowed, response[:]); err != nil {
		t.Fatal("direct route failed", err)
	}
	denied := dial(M.Socksaddr{Fqdn: "blocked.test", Port: M.SocksaddrFromNet(target).Port})
	defer denied.Close()
	denied.Write([]byte("denied"))
	if _, err := denied.Read(response[:]); err == nil {
		t.Fatal("geosite block did not affect proxy traffic")
	}
	input.Config.Route = &model.RouteConfig{Block: []string{"ip:127.0.0.0/8"}}
	second := save(first.ID)
	preview := plan(second.ID, first.ID)
	if len(preview.Changes) != 1 || !preview.Changes[0].ClosesConnections {
		t.Fatal("global policy change did not require disconnect acknowledgement", preview)
	}
	r, e, _ = m.request(t, "POST", "/api/v1/config/apply", map[string]any{"plan_id": preview.ID}, map[string]string{"Idempotency-Key": "routing-second"})
	expectStatus(t, r, 409, e)
	if _, err := allowed.Write([]byte("ok")); err != nil {
		t.Fatal("unconfirmed policy changed live traffic", err)
	}
	if _, err := io.ReadFull(allowed, response[:]); err != nil {
		t.Fatal(err)
	}
	apply(preview, "routing-second", true)
	if _, err := allowed.Read(response[:]); err == nil {
		t.Fatal("old policy flow survived replacement")
	}
	deniedIP := dial(M.SocksaddrFromNet(target))
	defer deniedIP.Close()
	deniedIP.Write([]byte("blocked"))
	if _, err := deniedIP.Read(response[:]); err == nil {
		t.Fatal("IP policy did not apply")
	}
	// The old asset is protected by history even if the newest draft no longer uses it.
	input.Config.GeoData = nil
	third := save(second.ID)
	r, e, _ = m.request(t, "DELETE", "/api/v1/geodata/"+asset.ID, nil, nil)
	expectStatus(t, r, 409, e)
	input.Config.Route = &model.RouteConfig{Block: []string{"geosite:missing"}}
	r, e, _ = m.request(t, "PUT", "/api/v1/config/draft", input, map[string]string{"If-Match": "\"" + third.ID + "\""})
	expectStatus(t, r, 422, e)
	r, e, _ = m.request(t, "GET", "/api/v1/config/draft", nil, nil)
	expectStatus(t, r, 200, e)
	if dataAs[model.ConfigRevision](t, e).ID != third.ID {
		t.Fatal("invalid policy changed draft")
	}
	r, e, _ = m.request(t, "GET", "/api/v1/geodata", nil, nil)
	expectStatus(t, r, 200, e)
}

func managementDNS(t *testing.T) string {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [4096]byte
		for {
			n, peer, err := socket.ReadFrom(b[:])
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(b[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true}, Questions: request.Questions}
			for _, q := range request.Questions {
				if q.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			raw, err := response.Pack()
			if err == nil {
				socket.WriteTo(raw, peer)
			}
		}
	}()
	t.Cleanup(func() { socket.Close(); <-done })
	return socket.LocalAddr().String()
}
