// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package protocol

type originDefinition struct {
	userID [4]byte
}

func (*originDefinition) Metadata() Metadata { return Metadata{SingleUser: true} }

func (*originDefinition) Overhead() int { return 0 }

func (d *originDefinition) NewStream(_ []byte) Stream {
	return &originStream{userID: d.userID}
}

func (d *originDefinition) DecodePacket(_ []byte, packet, _ []byte) ([]byte, [4]byte, error) {
	return packet, d.userID, nil
}

func (*originDefinition) EncodePacket(dst, payload []byte, _ [4]byte, _ []byte) ([]byte, error) {
	return append(dst, payload...), nil
}

type originStream struct {
	userID        [4]byte
	authenticated bool
}

func (*originStream) SetReadIV([]byte) {}

func (s *originStream) Decode(dst, input []byte) ([]byte, bool, bool, error) {
	if len(input) == 0 {
		return nil, false, false, nil
	}
	s.authenticated = true
	if dst == nil {
		return input, true, false, nil
	}
	return append(dst, input...), false, false, nil
}

func (*originStream) Encode(dst, payload []byte) ([]byte, error) {
	return append(dst, payload...), nil
}

func (s *originStream) UserID() ([4]byte, bool) { return s.userID, s.authenticated }

func (*originStream) Close() {}
