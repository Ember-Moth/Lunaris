// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
// Copyright (C) 2026 Polaris contributors.
package probe

// Surge 6.7.0 (11520): FUN_100015274/FUN_1000140bc: shuffles and masks v6 default-mode salts with this namespace xor.
const saltNSXor = 0xdaa66d2c7ddf743f

// Surge 6.7.0 (11520): FUN_100014610: fills the salt block with the padding generator
// under this sentinel sequence before scattering the salt into it.
const saltBlockFillSeq = 0xffffffff

func saltShufflePRF(nsSalt uint64, domain uint32, index uint32) uint32 {
	rdx := uint64(index)*coefB + addB
	rdi := nsSalt ^ saltNSXor
	rsi := uint64(domain)*coefA + addA
	y := splitmix64((rdx ^ rdi) ^ rsi)
	return uint32(y ^ (y >> 32))
}

func shufflePerm(nsSalt uint64, rounds uint8, length int) []byte {
	out := make([]byte, length)
	for index := range out {
		out[index] = byte(index)
	}
	if length == 0 {
		return out
	}
	if rounds == 0 {
		rounds = 1
	}
	for round := uint32(0); round < uint32(rounds); round++ {
		domain := uint32(mixHandshakeDomain) + round
		for i := range length {
			span := uint64(length - i)
			raw := uint64(saltShufflePRF(nsSalt, domain, uint32(i)))
			j := i + int(raw%span)
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

func saltMask(nsSalt uint64, mixStride uint8, index uint32) byte {
	prf := prf32Fold(nsSalt, labelMotif, uint64(mixHandshakeDomain), uint64(index))
	return byte(index)*mixStride ^ byte(prf)
}

// saltPositions returns the block offsets that writeSaltBlock overwrites with salt
// bytes. Every other offset keeps the deterministic saltBlockFillSeq filler, which
// is what lets a server recognise a credential without deriving its Argon2id key.
func (p *Profile) saltPositions() [saltLen]byte {
	perm := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), p.saltBlockLen)
	var out [saltLen]byte
	copy(out[:], perm[:saltLen])
	return out
}

func (p *Profile) extractSalt(block []byte) [saltLen]byte {
	perm := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), len(block))
	var out [saltLen]byte
	for i := range saltLen {
		out[i] = saltMask(p.namespaces.salt, byte(p.mixStrideHandshake), uint32(i)) ^ block[perm[i]]
	}
	return out
}

func (p *Profile) writeSaltBlock(salt []byte, block []byte) {
	perm := shufflePerm(p.namespaces.salt, byte(p.mixRoundsHandshake), len(block))
	for i := range saltLen {
		block[perm[i]] = saltMask(p.namespaces.salt, byte(p.mixStrideHandshake), uint32(i)) ^ salt[i]
	}
}
