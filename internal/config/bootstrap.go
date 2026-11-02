// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/net/idna"
)

type Admin struct {
	Listen         string    `yaml:"listen"`
	PublicURL      string    `yaml:"public_url"`
	TLS            *AdminTLS `yaml:"tls"`
	TrustedProxies []string  `yaml:"trusted_proxies"`
}

type AdminTLS struct {
	CertificateFile string `yaml:"certificate_file"`
	PrivateKeyFile  string `yaml:"private_key_file"`
}

// Bootstrap contains deployment settings, not managed proxy configuration.
type Bootstrap struct {
	DataDir string `yaml:"data_dir"`
	Admin   Admin  `yaml:"admin"`
}

func Defaults() Bootstrap {
	return Bootstrap{DataDir: "./data", Admin: Admin{Listen: "127.0.0.1:9080"}}
}

// Load resolves relative data paths against the configuration file directory.
func Load(path string) (Bootstrap, error) {
	options := Defaults()
	file, err := os.Open(path)
	if err != nil {
		return options, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return options, err
	}
	if len(content) > 64*1024 {
		return options, errors.New("bootstrap exceeds 64 KiB")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return options, fmt.Errorf("decode bootstrap: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return options, errors.New("bootstrap must be a YAML mapping")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&options); err != nil {
		return options, fmt.Errorf("decode bootstrap: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return options, errors.New("bootstrap must contain exactly one YAML document")
	}
	if options.DataDir != "" && !filepath.IsAbs(options.DataDir) {
		options.DataDir = filepath.Join(filepath.Dir(path), options.DataDir)
	}
	if options.Admin.TLS != nil {
		for _, p := range []*string{&options.Admin.TLS.CertificateFile, &options.Admin.TLS.PrivateKeyFile} {
			if *p != "" && !filepath.IsAbs(*p) {
				*p = filepath.Join(filepath.Dir(path), *p)
			}
		}
	}
	return options, options.Validate()
}

func (b Bootstrap) Validate() error {
	if b.DataDir == "" {
		return errors.New("data_dir must not be empty")
	}
	host, port, err := net.SplitHostPort(b.Admin.Listen)
	if err != nil {
		return fmt.Errorf("invalid admin listen address: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("admin listen must use a literal IP address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("admin listen port must be between 1 and 65535")
	}
	if b.Admin.TLS != nil {
		if b.Admin.TLS.CertificateFile == "" || b.Admin.TLS.PrivateKeyFile == "" || len(b.Admin.TrustedProxies) > 0 {
			return errors.New("native management TLS requires a certificate/key pair without trusted proxy mode")
		}
	} else if len(b.Admin.TrustedProxies) == 0 && !address.IsLoopback() {
		return errors.New("plain management HTTP must listen on loopback")
	}
	origin, err := b.Admin.Origin()
	if err != nil {
		return err
	}
	parsed, _ := url.Parse(origin)
	if b.Admin.TLS != nil || len(b.Admin.TrustedProxies) > 0 {
		if parsed.Scheme != "https" {
			return errors.New("management TLS and trusted proxy modes require an https public_url")
		}
	} else {
		ip, e := netip.ParseAddr(parsed.Hostname())
		if parsed.Scheme != "http" || parsed.Hostname() != "localhost" && (e != nil || !ip.IsLoopback()) {
			return errors.New("plain management HTTP requires a loopback public_url")
		}
	}
	if len(b.Admin.TrustedProxies) > 16 {
		return errors.New("too many trusted proxies")
	}
	for _, raw := range b.Admin.TrustedProxies {
		prefix, e := netip.ParsePrefix(raw)
		if e != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return errors.New("trusted proxies must be explicit IP prefixes")
		}
	}
	return nil
}

func (a Admin) Origin() (string, error) {
	raw := a.PublicURL
	if raw == "" {
		if len(a.TrustedProxies) > 0 {
			return "", errors.New("trusted proxy mode requires public_url")
		}
		scheme := "http"
		if a.TLS != nil {
			scheme = "https"
		}
		raw = scheme + "://" + a.Listen
	}
	return CanonicalOrigin(raw)
}

// CanonicalOrigin accepts only an origin, never userinfo, a path or a host suffix.
func CanonicalOrigin(raw string) (string, error) {
	if len(raw) > 512 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t") {
		return "", errors.New("invalid management origin")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Opaque != "" || u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("invalid management origin")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if strings.ContainsAny(host, "% /?#") {
		return "", errors.New("invalid management host")
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.IsUnspecified() {
			return "", errors.New("management public host must not be a wildcard")
		}
		host = ip.String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || len(host) > 253 {
			return "", errors.New("invalid management host")
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("invalid management host")
			}
		}
	}
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid management port")
		}
		port = strconv.Itoa(n)
	}
	if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}
