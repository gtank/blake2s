// An implementation of blake2s with support for salting and personalization.
package blake2s

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// The constant values will be different for other BLAKE2 variants. These are
// appropriate for BLAKE2s.
const (
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
	BlockBytes = 64

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

var (
	// Lookup table of the permutations of 0...15 used by the BLAKE2 round
	// function.
	SIGMA = [10][16]uint32{
		[16]uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		[16]uint32{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		[16]uint32{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		[16]uint32{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		[16]uint32{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		[16]uint32{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		[16]uint32{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		[16]uint32{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		[16]uint32{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		[16]uint32{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	}
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
	h      []uint32
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
		h:    []uint32{h0, h1, h2, h3, h4, h5, h6, h7},
		buf:  make([]byte, 0, BlockBytes),
		size: int(p.DigestSize),
	}

	return d
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
			oldOffset := len(d.buf)
			newOffset := len(d.buf) + inputLeft
			copy(d.buf[oldOffset:newOffset], input[bytesWritten:])
			d.buf = d.buf[0:newOffset]
			return bytesWritten + inputLeft, nil
		}

		oldOffset := len(d.buf)
		newOffset := len(d.buf) + freeBytes
		copy(d.buf[oldOffset:newOffset], input[bytesWritten:bytesWritten+freeBytes])
		d.buf = d.buf[0:newOffset]

		// increment counter, preserving overflow behavior
		d.t0 += uint32(len(d.buf))
		if d.t0 < uint32(len(d.buf)) {
			d.t1++
		}

		// compress
		err := d.compress()
		if err != nil {
			// TODO a Hash should never return error on write
			return bytesWritten, err
		}

		// advance pointers
		bytesWritten += freeBytes
		d.buf = d.buf[:0]

		// loop until we can't fill another buffer
	}

	return bytesWritten, nil
}

func (d *Digest) compress() error {
	if len(d.buf) != cap(d.buf) || len(d.buf) != BlockBytes {
		return errors.New("blake2s: tried to compress when buffer wasn't full")
	}

	if len(d.h) != 8 {
		return errors.New("blake2s: internal hash state too large")
	}

	// Split the buffer into 32-bit words
	m := make([]uint32, 16)
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint32(d.buf[i*4 : i*4+4])
	}

	// New 16x32 array for updated hash state. Copy the current hash state to
	// the top, then set IVs.
	v := make([]uint32, 16)
	copy(v, d.h)
	v[8] = IV0
	v[9] = IV1
	v[10] = IV2
	v[11] = IV3
	v[12] = IV4 ^ d.t0
	v[13] = IV5 ^ d.t1
	v[14] = IV6 ^ d.f0
	v[15] = IV7 ^ d.f1

	for round := 0; round < RoundCount; round++ {
		for i := 0; i < 8; i++ {
			m0 := m[SIGMA[round][2*i+0]]
			m1 := m[SIGMA[round][2*i+1]]
			switch i {
			case 0:
				v[0], v[4], v[8], v[12] = g(v[0], v[4], v[8], v[12], m0, m1)
			case 1:
				v[1], v[5], v[9], v[13] = g(v[1], v[5], v[9], v[13], m0, m1)
			case 2:
				v[2], v[6], v[10], v[14] = g(v[2], v[6], v[10], v[14], m0, m1)
			case 3:
				v[3], v[7], v[11], v[15] = g(v[3], v[7], v[11], v[15], m0, m1)
			case 4:
				v[0], v[5], v[10], v[15] = g(v[0], v[5], v[10], v[15], m0, m1)
			case 5:
				v[1], v[6], v[11], v[12] = g(v[1], v[6], v[11], v[12], m0, m1)
			case 6:
				v[2], v[7], v[8], v[13] = g(v[2], v[7], v[8], v[13], m0, m1)
			case 7:
				v[3], v[4], v[9], v[14] = g(v[3], v[4], v[9], v[14], m0, m1)
			default:
				return errors.New("blake2s: invalid round index")
			}
		}
	}

	for i := 0; i < 8; i++ {
		d.h[i] = d.h[i] ^ v[i] ^ v[i+8]
	}

	return nil
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
	dCopy.buf = make([]byte, cap(d.buf)) // want this zero-padded to BlockSize anyway
	copy(dCopy.buf, d.buf)
	dCopy.h = make([]uint32, len(d.h))
	copy(dCopy.h, d.h)

	// increment counter by size of pending input before padding
	dCopy.t0 += uint32(len(d.buf))
	if dCopy.t0 < uint32(len(d.buf)) {
		dCopy.t1++
	}
	// set last block flag
	dCopy.f0 = 0xFFFFFFFF

	// compress
	err := dCopy.compress()
	if err != nil {
		return nil, err
	}

	// extract output
	out := make([]byte, dCopy.size)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], dCopy.h[i])
	}

	return out, nil
}

// The internal BLAKE2s round function. We lift the table lookups into the
// caller so this function has a better chance of inlining.
func g(a, b, c, d, m0, m1 uint32) (uint32, uint32, uint32, uint32) {
	a = a + b + m0
	d = bits.RotateLeft32(d^a, -16)
	c = c + d
	b = bits.RotateLeft32(b^c, -12)
	a = a + b + m1
	d = bits.RotateLeft32(d^a, -8)
	c = c + d
	b = bits.RotateLeft32(b^c, -7)
	return a, b, c, d
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
		if len(key) < BlockBytes {
			keyBuf := make([]byte, BlockBytes)
			copy(keyBuf, key)
			digest.Write(keyBuf)
		}
	}

	return digest, nil
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
func (d *Digest) BlockSize() int { return BlockBytes }
