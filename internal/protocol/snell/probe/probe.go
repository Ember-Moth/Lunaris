// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
// Copyright (C) 2026 Polaris contributors.
package probe

import snell "github.com/sagernet/sing-snell"

// Probe only recognizes public filler. Authentication still requires AEAD.
type Probe struct {
	profile           *Profile
	offsets, expected []byte
}

func New(psk []byte) *Probe {
	p := &Probe{profile: NewProfile(psk)}
	expected := make([]byte, p.SaltBlockLen())
	p.profile.fillPadding(saltBlockFillSeq, expected)
	positions := p.profile.saltPositions()
	scattered := make([]bool, len(expected))
	for _, offset := range positions {
		scattered[offset] = true
	}
	for offset := range expected {
		if !scattered[offset] {
			p.offsets = append(p.offsets, byte(offset))
			p.expected = append(p.expected, expected[offset])
		}
	}
	return p
}
func (p *Probe) SaltBlockLen() int { return p.profile.saltBlockLen }
func (p *Probe) HeaderLen() int {
	return p.SaltBlockLen() + p.profile.recordPrefixLen(0) + snell.HeaderCipherLen
}
func (p *Probe) Matches(input []byte) bool {
	if len(input) < p.SaltBlockLen() {
		return false
	}
	for i, offset := range p.offsets {
		if input[offset] != p.expected[i] {
			return false
		}
	}
	return true
}
func (p *Probe) Header(input []byte) (salt [16]byte, prefix, sealed []byte) {
	n := p.SaltBlockLen()
	end := n + p.profile.recordPrefixLen(0)
	return p.profile.extractSalt(input[:n]), input[n:end], input[end:p.HeaderLen()]
}
