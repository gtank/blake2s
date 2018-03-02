package main

import (
	"fmt"
	"io"
	"os"

	"github.com/gtank/blake2s"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}

	f, err := os.Open(os.ExpandEnv(os.Args[1]))
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()

	d, err := blake2s.NewDigest([]byte{0x0}, nil, nil, 32)
	if err != nil {
		os.Exit(1)
	}

	_, err = io.Copy(d, f)
	if err != nil {
		os.Exit(1)
	}

	_, err = fmt.Fprintf(os.Stdout, "%x", d.Sum(nil))
	if err != nil {
		os.Exit(1)
	}

	return
}
