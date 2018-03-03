// An implementation of blake2s with support for salting and personalization.
package blake2s

import (
	"encoding/binary"
	"errors"
)

// The constant values will be different for other BLAKE2 variants. These are
// appropriate for BLAKE2s.
const (
	// The length of the key field.
	KeyLength = 32
	// The maximum number of bytes to produce.
	MaxOutput = 32
	// Max size of the salt, in bytes
	SaltLength = 8
	// Max size of the personalization string, in bytes
	SeparatorLength = 8
	// Number of G function rounds for BLAKE2s.
	RoundCount = 10
	// Size of a block buffer in bytes
	BlockSize = 64

	// Initialization vector for BLAKE2s
	IV0 uint32 = 0x6a09e667
	IV1 uint32 = 0xbb67ae85
	IV2 uint32 = 0x3c6ef372
	IV3 uint32 = 0xa54ff53a
	IV4 uint32 = 0x510e527f
	IV5 uint32 = 0x9b05688c
	IV6 uint32 = 0x1f83d9ab
	IV7 uint32 = 0x5be0cd19
)

// These are the user-visible parameters of a BLAKE2 hash instance. The
// parameter block is XOR'd with the IV at the beginning of the hash.
// Currently we only support sequential mode, so many of these values will be
// hardcoded to a default. They are nevertheless defined for clarity.
type parameterBlock struct {
	DigestSize      byte   // 0
	KeyLength       byte   // 1
	fanout          byte   // 2
	depth           byte   // 3
	leafLength      uint32 // 4-7
	nodeOffset      uint32 // 8-11
	xofLength       uint16 // 12-13
	nodeDepth       byte   // 14
	innerLength     byte   // 15
	Salt            []byte // 16-23
	Personalization []byte // 24-31
}

// Packs a BLAKE2 parameter block.
func (p *parameterBlock) Marshal() []byte {
	buf := make([]byte, 32)
	buf[0] = p.DigestSize
	buf[1] = p.KeyLength
	buf[2] = p.fanout
	buf[3] = p.depth
	binary.LittleEndian.PutUint32(buf[4:], p.leafLength)
	binary.LittleEndian.PutUint32(buf[8:], p.nodeOffset)
	binary.LittleEndian.PutUint16(buf[12:], p.xofLength)
	buf[14] = p.nodeDepth
	buf[15] = p.innerLength
	copy(buf[16:], p.Salt)
	copy(buf[24:], p.Personalization)
	return buf
}

// The internal state of the BLAKE2s algorithm.
type Digest struct {
	h      [8]uint32
	t0, t1 uint32
	f0, f1 uint32

	buf []byte

	// size is definted in hash.Hash, and returns the number of bytes Sum will
	// return. Since BLAKE2 output length is dynamic, so is this.
	size int
}

// After this function is called, the ParameterBlock can be discarded.
func initFromParams(p *parameterBlock) *Digest {
	paramBytes := p.Marshal()

	h0 := IV0 ^ binary.LittleEndian.Uint32(paramBytes[0:4])
	h1 := IV1 ^ binary.LittleEndian.Uint32(paramBytes[4:8])
	h2 := IV2 ^ binary.LittleEndian.Uint32(paramBytes[8:12])
	h3 := IV3 ^ binary.LittleEndian.Uint32(paramBytes[12:16])
	h4 := IV4 ^ binary.LittleEndian.Uint32(paramBytes[16:20])
	h5 := IV5 ^ binary.LittleEndian.Uint32(paramBytes[20:24])
	h6 := IV6 ^ binary.LittleEndian.Uint32(paramBytes[24:28])
	h7 := IV7 ^ binary.LittleEndian.Uint32(paramBytes[28:32])

	d := &Digest{
		h:    [8]uint32{h0, h1, h2, h3, h4, h5, h6, h7},
		buf:  make([]byte, 0, BlockSize),
		size: int(p.DigestSize),
	}

	return d
}

func (d *Digest) compress() {
	// Split the buffer into 16x32-bit words.
	m0 := binary.LittleEndian.Uint32(d.buf[0*4 : 0*4+4])
	m1 := binary.LittleEndian.Uint32(d.buf[1*4 : 1*4+4])
	m2 := binary.LittleEndian.Uint32(d.buf[2*4 : 2*4+4])
	m3 := binary.LittleEndian.Uint32(d.buf[3*4 : 3*4+4])
	m4 := binary.LittleEndian.Uint32(d.buf[4*4 : 4*4+4])
	m5 := binary.LittleEndian.Uint32(d.buf[5*4 : 5*4+4])
	m6 := binary.LittleEndian.Uint32(d.buf[6*4 : 6*4+4])
	m7 := binary.LittleEndian.Uint32(d.buf[7*4 : 7*4+4])
	m8 := binary.LittleEndian.Uint32(d.buf[8*4 : 8*4+4])
	m9 := binary.LittleEndian.Uint32(d.buf[9*4 : 9*4+4])
	m10 := binary.LittleEndian.Uint32(d.buf[10*4 : 10*4+4])
	m11 := binary.LittleEndian.Uint32(d.buf[11*4 : 11*4+4])
	m12 := binary.LittleEndian.Uint32(d.buf[12*4 : 12*4+4])
	m13 := binary.LittleEndian.Uint32(d.buf[13*4 : 13*4+4])
	m14 := binary.LittleEndian.Uint32(d.buf[14*4 : 14*4+4])
	m15 := binary.LittleEndian.Uint32(d.buf[15*4 : 15*4+4])

	// Create the internal round state. Copy the current hash state to the top,
	// then the tweaked IVs to the bottom. Use local variables to avoid
	// allocating another slice.
	v0, v1, v2, v3 := d.h[0], d.h[1], d.h[2], d.h[3]
	v4, v5, v6, v7 := d.h[4], d.h[5], d.h[6], d.h[7]
	v8, v9, v10, v11 := IV0, IV1, IV2, IV3
	v12 := IV4 ^ d.t0
	v13 := IV5 ^ d.t1
	v14 := IV6 ^ d.f0
	v15 := IV7 ^ d.f1

	// This round structure is several steps removed from the spec and
	// reference implementation. We unrolled the loops and calculated the
	// offsets from the permutation table entry for each round, then directly
	// mapped it to the correct word of the input block. This is a tradeoff:
	// the doubly-indirect lookups were horrible for performance, but it's not
	// at all obvious what this code is doing anymore.

	// Round 0 w/ precomputed permutation offsets
	v0, v4, v8, v12 = g(v0+v4+m0, v4, v8, v12, m1)
	v1, v5, v9, v13 = g(v1+v5+m2, v5, v9, v13, m3)
	v2, v6, v10, v14 = g(v2+v6+m4, v6, v10, v14, m5)
	v3, v7, v11, v15 = g(v3+v7+m6, v7, v11, v15, m7)

	v0, v5, v10, v15 = g(v0+v5+m8, v5, v10, v15, m9)
	v1, v6, v11, v12 = g(v1+v6+m10, v6, v11, v12, m11)
	v2, v7, v8, v13 = g(v2+v7+m12, v7, v8, v13, m13)
	v3, v4, v9, v14 = g(v3+v4+m14, v4, v9, v14, m15)

	// Round 1
	v0, v4, v8, v12 = g(v0+v4+m14, v4, v8, v12, m10)
	v1, v5, v9, v13 = g(v1+v5+m4, v5, v9, v13, m8)
	v2, v6, v10, v14 = g(v2+v6+m9, v6, v10, v14, m15)
	v3, v7, v11, v15 = g(v3+v7+m13, v7, v11, v15, m6)

	v0, v5, v10, v15 = g(v0+v5+m1, v5, v10, v15, m12)
	v1, v6, v11, v12 = g(v1+v6+m0, v6, v11, v12, m2)
	v2, v7, v8, v13 = g(v2+v7+m11, v7, v8, v13, m7)
	v3, v4, v9, v14 = g(v3+v4+m5, v4, v9, v14, m3)

	// Round 2
	v0, v4, v8, v12 = g(v0+v4+m11, v4, v8, v12, m8)
	v1, v5, v9, v13 = g(v1+v5+m12, v5, v9, v13, m0)
	v2, v6, v10, v14 = g(v2+v6+m5, v6, v10, v14, m2)
	v3, v7, v11, v15 = g(v3+v7+m15, v7, v11, v15, m13)

	v0, v5, v10, v15 = g(v0+v5+m10, v5, v10, v15, m14)
	v1, v6, v11, v12 = g(v1+v6+m3, v6, v11, v12, m6)
	v2, v7, v8, v13 = g(v2+v7+m7, v7, v8, v13, m1)
	v3, v4, v9, v14 = g(v3+v4+m9, v4, v9, v14, m4)

	// Round 3
	v0, v4, v8, v12 = g(v0+v4+m7, v4, v8, v12, m9)
	v1, v5, v9, v13 = g(v1+v5+m3, v5, v9, v13, m1)
	v2, v6, v10, v14 = g(v2+v6+m13, v6, v10, v14, m12)
	v3, v7, v11, v15 = g(v3+v7+m11, v7, v11, v15, m14)

	v0, v5, v10, v15 = g(v0+v5+m2, v5, v10, v15, m6)
	v1, v6, v11, v12 = g(v1+v6+m5, v6, v11, v12, m10)
	v2, v7, v8, v13 = g(v2+v7+m4, v7, v8, v13, m0)
	v3, v4, v9, v14 = g(v3+v4+m15, v4, v9, v14, m8)

	// Round 4
	v0, v4, v8, v12 = g(v0+v4+m9, v4, v8, v12, m0)
	v1, v5, v9, v13 = g(v1+v5+m5, v5, v9, v13, m7)
	v2, v6, v10, v14 = g(v2+v6+m2, v6, v10, v14, m4)
	v3, v7, v11, v15 = g(v3+v7+m10, v7, v11, v15, m15)

	v0, v5, v10, v15 = g(v0+v5+m14, v5, v10, v15, m1)
	v1, v6, v11, v12 = g(v1+v6+m11, v6, v11, v12, m12)
	v2, v7, v8, v13 = g(v2+v7+m6, v7, v8, v13, m8)
	v3, v4, v9, v14 = g(v3+v4+m3, v4, v9, v14, m13)

	// Round 5
	v0, v4, v8, v12 = g(v0+v4+m2, v4, v8, v12, m12)
	v1, v5, v9, v13 = g(v1+v5+m6, v5, v9, v13, m10)
	v2, v6, v10, v14 = g(v2+v6+m0, v6, v10, v14, m11)
	v3, v7, v11, v15 = g(v3+v7+m8, v7, v11, v15, m3)

	v0, v5, v10, v15 = g(v0+v5+m4, v5, v10, v15, m13)
	v1, v6, v11, v12 = g(v1+v6+m7, v6, v11, v12, m5)
	v2, v7, v8, v13 = g(v2+v7+m15, v7, v8, v13, m14)
	v3, v4, v9, v14 = g(v3+v4+m1, v4, v9, v14, m9)

	// Round 6
	v0, v4, v8, v12 = g(v0+v4+m12, v4, v8, v12, m5)
	v1, v5, v9, v13 = g(v1+v5+m1, v5, v9, v13, m15)
	v2, v6, v10, v14 = g(v2+v6+m14, v6, v10, v14, m13)
	v3, v7, v11, v15 = g(v3+v7+m4, v7, v11, v15, m10)

	v0, v5, v10, v15 = g(v0+v5+m0, v5, v10, v15, m7)
	v1, v6, v11, v12 = g(v1+v6+m6, v6, v11, v12, m3)
	v2, v7, v8, v13 = g(v2+v7+m9, v7, v8, v13, m2)
	v3, v4, v9, v14 = g(v3+v4+m8, v4, v9, v14, m11)

	// Round 7
	v0, v4, v8, v12 = g(v0+v4+m13, v4, v8, v12, m11)
	v1, v5, v9, v13 = g(v1+v5+m7, v5, v9, v13, m14)
	v2, v6, v10, v14 = g(v2+v6+m12, v6, v10, v14, m1)
	v3, v7, v11, v15 = g(v3+v7+m3, v7, v11, v15, m9)

	v0, v5, v10, v15 = g(v0+v5+m5, v5, v10, v15, m0)
	v1, v6, v11, v12 = g(v1+v6+m15, v6, v11, v12, m4)
	v2, v7, v8, v13 = g(v2+v7+m8, v7, v8, v13, m6)
	v3, v4, v9, v14 = g(v3+v4+m2, v4, v9, v14, m10)

	// Round 8
	v0, v4, v8, v12 = g(v0+v4+m6, v4, v8, v12, m15)
	v1, v5, v9, v13 = g(v1+v5+m14, v5, v9, v13, m9)
	v2, v6, v10, v14 = g(v2+v6+m11, v6, v10, v14, m3)
	v3, v7, v11, v15 = g(v3+v7+m0, v7, v11, v15, m8)

	v0, v5, v10, v15 = g(v0+v5+m12, v5, v10, v15, m2)
	v1, v6, v11, v12 = g(v1+v6+m13, v6, v11, v12, m7)
	v2, v7, v8, v13 = g(v2+v7+m1, v7, v8, v13, m4)
	v3, v4, v9, v14 = g(v3+v4+m10, v4, v9, v14, m5)

	// Round 9
	v0, v4, v8, v12 = g(v0+v4+m10, v4, v8, v12, m2)
	v1, v5, v9, v13 = g(v1+v5+m8, v5, v9, v13, m4)
	v2, v6, v10, v14 = g(v2+v6+m7, v6, v10, v14, m6)
	v3, v7, v11, v15 = g(v3+v7+m1, v7, v11, v15, m5)

	v0, v5, v10, v15 = g(v0+v5+m15, v5, v10, v15, m11)
	v1, v6, v11, v12 = g(v1+v6+m9, v6, v11, v12, m14)
	v2, v7, v8, v13 = g(v2+v7+m3, v7, v8, v13, m12)
	v3, v4, v9, v14 = g(v3+v4+m13, v4, v9, v14, m0)

	d.h[0] = d.h[0] ^ v0 ^ v8
	d.h[1] = d.h[1] ^ v1 ^ v9
	d.h[2] = d.h[2] ^ v2 ^ v10
	d.h[3] = d.h[3] ^ v3 ^ v11
	d.h[4] = d.h[4] ^ v4 ^ v12
	d.h[5] = d.h[5] ^ v5 ^ v13
	d.h[6] = d.h[6] ^ v6 ^ v14
	d.h[7] = d.h[7] ^ v7 ^ v15
}

// The internal BLAKE2s round function.
func g(a, b, c, d, m1 uint32) (uint32, uint32, uint32, uint32) {
	// We lift the table lookups and the initial triple addition into the
	// caller so this function has a better chance of inlining. Similarly, the
	// math/bits calls are themselves inlinable but seem to count against us in
	// the AST budget anyway. TODO: file a bug for that

	// a = a + b + m0
	d = ((d ^ a) >> 16) | ((d ^ a) << (32 - 16))
	c = c + d
	b = ((b ^ c) >> 12) | ((b ^ c) << (32 - 12))
	a = a + b + m1
	d = ((d ^ a) >> 8) | ((d ^ a) << (32 - 8))
	c = c + d
	b = ((b ^ c) >> 7) | ((b ^ c) << (32 - 7))
	return a, b, c, d
}

// Note that due to the nature of the hash.Hash interface, calling finalize
// WILL NOT permanently update the underlying hash state. Instead it will
// simulate what would happen if the current block were the final block.
func (d *Digest) finalize() ([]byte, error) {
	if d.f0 != 0 {
		return nil, errors.New("blake2s: tried to finalize but last flag already set")
	}

	// make copies of everything
	dCopy := *d

	// Zero the unused portion of the buffer. This triggers a specific
	// optimization for memset, see https://codereview.appspot.com/137880043
	dCopy.buf = d.buf[len(d.buf):cap(d.buf)]
	for i := range dCopy.buf {
		dCopy.buf[i] = 0
	}
	dCopy.buf = d.buf[0:cap(d.buf)]

	// increment counter by size of pending input before padding
	dCopy.t0 += uint32(len(d.buf))
	if dCopy.t0 < uint32(len(d.buf)) {
		dCopy.t1++
	}
	// set last block flag
	dCopy.f0 = 0xFFFFFFFF

	dCopy.compress()

	// extract output
	out := make([]byte, dCopy.size)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], dCopy.h[i])
	}

	return out, nil
}

func NewDigest(key, salt, personalization []byte, outputBytes int) (*Digest, error) {
	params := &parameterBlock{
		fanout: 1, // sequential mode
		depth:  1, // sequential mode
	}

	if outputBytes <= 0 {
		return nil, errors.New("blake2s: asked for negative or zero output")
	}
	if outputBytes > MaxOutput {
		return nil, errors.New("blake2s: asked for too much output")
	}
	params.DigestSize = byte(outputBytes & 0xFF)

	if key != nil {
		if len(key) > KeyLength {
			return nil, errors.New("blake2s: key too large")
		}
		params.KeyLength = byte(len(key) & 0xFF)
	}

	params.Salt = make([]byte, SaltLength)
	if salt != nil {
		if len(salt) > SaltLength {
			return nil, errors.New("blake2s: salt too large")
		}
		// If salt is too short, this will implicitly right-pad with zero.
		copy(params.Salt, salt)
	}

	params.Personalization = make([]byte, SeparatorLength)
	if personalization != nil {
		if len(personalization) > SeparatorLength {
			return nil, errors.New("blake2s: personalization string too large")
		}
		// If personalization string is short, this will implicitly right-pad with zero.
		copy(params.Personalization, personalization)
	}

	// Initialize the internal state
	digest := initFromParams(params)

	if key != nil {
		// Write key to entire first block and compress
		if len(key) < BlockSize {
			keyBuf := make([]byte, BlockSize)
			copy(keyBuf, key)
			digest.Write(keyBuf)
		}
	}

	return digest, nil
}

// Write adds more data to the running hash.
func (d *Digest) Write(input []byte) (n int, err error) {
	bytesWritten := 0

	// If we have capacity, just copy and reslice to wait for a full block. If
	// we don't have capacity, we'll need to take a full block and compress.
	for bytesWritten < len(input) {
		// How much space do we have left in the block?
		freeBytes := cap(d.buf) - len(d.buf)
		inputLeft := len(input) - bytesWritten

		if inputLeft <= freeBytes {
			newOffset := len(d.buf) + inputLeft
			copy(d.buf[len(d.buf):newOffset], input[bytesWritten:])
			d.buf = d.buf[0:newOffset]
			return bytesWritten + inputLeft, nil
		}

		newOffset := len(d.buf) + freeBytes
		copy(d.buf[len(d.buf):newOffset], input[bytesWritten:bytesWritten+freeBytes])
		d.buf = d.buf[0:newOffset]

		// increment counter, preserving overflow behavior
		d.t0 += uint32(len(d.buf))
		if d.t0 < uint32(len(d.buf)) {
			d.t1++
		}

		d.compress()

		// advance pointers
		bytesWritten += freeBytes
		d.buf = d.buf[:0]

		// loop until we can't fill another buffer
	}

	return bytesWritten, nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *Digest) Sum(b []byte) []byte {
	out, err := d.finalize()
	if err != nil {
		return b
	}
	return append(b, out...)
}

// Reset resets the Hash to its initial state.
func (d *Digest) Reset() {
	// TODO: not this
	panic("BLAKE2 cannot be reset without storing the key")
}

// Digest output size in bytes.
func (d *Digest) Size() int { return d.size }

// BlockSize returns the hash's underlying block size. The Write method must be
// able to accept any amount of data, but it may operate more efficiently if
// all writes are a multiple of the block size.
func (d *Digest) BlockSize() int { return BlockSize }
