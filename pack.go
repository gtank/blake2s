package blake2s

func u32LE(b []byte) uint32 {
	_ = b[3] // bounds check hint to the compiler, see golang.org/issue/14808
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func putU32LE(b []byte, n uint32) {
	_ = b[3] // bounds check hint to the compiler, see golang.org/issue/14808
	b[0] = byte(n)
	b[1] = byte(n >> 8)
	b[2] = byte(n >> 16)
	b[3] = byte(n >> 24)
}

func putU16LE(b []byte, n uint16) {
	_ = b[1] // bounds check hint to the compiler, see golang.org/issue/14808
	b[0] = byte(n)
	b[1] = byte(n >> 8)
}
