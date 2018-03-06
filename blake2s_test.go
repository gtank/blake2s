package blake2s

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
)

const (
	// Source: BLAKE2 Section 2.8
	SeqNoKeySaltOrPersonal = "2020010100000000000000000000000000000000000000000000000000000000"
)

func TestParameterBlockInit(t *testing.T) {
	params := &parameterBlock{
		fanout:     1,
		depth:      1,
		KeyLength:  32,
		DigestSize: 32,
	}

	packedBytes := params.Marshal()
	expectedBytes, _ := hex.DecodeString(SeqNoKeySaltOrPersonal)

	if !bytes.Equal(packedBytes, expectedBytes) {
		t.Errorf("packed bytes mismatch: %x %x", packedBytes, expectedBytes)
	}

	digest := initFromParams(params)
	if digest.h[0] != (IV0 ^ 0x01012020) {
		t.Errorf("first u32 of parameter block was wrong: %x", digest.h[0])
	}
}

func TestNewDigest(t *testing.T) {
	_, err := NewDigest(nil, nil, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
}

// These come from the BLAKE2s reference implementation.
type ReferenceTestVector struct {
	Hash    string `json:"hash"`
	Input   string `json:"in"`
	Key     string `json:"key"`
	Persona string `json:"persona,omitempty"`
	Salt    string `json:"salt,omitempty"`
	Output  string `json:"out"`
}

func TestStandardVectors(t *testing.T) {
	jsonTestData, err := ioutil.ReadFile("testdata/blake2s-kat.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []ReferenceTestVector
	err = json.Unmarshal(jsonTestData, &tests)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		if test.Hash != "blake2s" {
			t.Errorf("Got a test for the wrong hash: %s", test.Hash)
			continue
		}
		decodedInput, _ := hex.DecodeString(test.Input)
		if len(decodedInput) == 0 {
			decodedInput = nil
		}
		decodedKey, _ := hex.DecodeString(test.Key)
		if len(decodedKey) == 0 {
			decodedKey = nil
		}
		decodedOutput, _ := hex.DecodeString(test.Output)
		d, err := NewDigest(decodedKey, nil, nil, 32)
		if err != nil {
			t.Error(err)
			continue
		}
		if decodedInput != nil {
			d.Write(decodedInput)
		}
		if !bytes.Equal(decodedOutput, d.Sum(nil)) {
			t.Errorf("Failed test: %v", test.Output)
			break
		}
	}
}

func TestFullInputBlock(t *testing.T) {
	test := &ReferenceTestVector{
		Input:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		Key:    "",
		Output: "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e",
	}

	decodedInput, _ := hex.DecodeString(test.Input)
	decodedOutput, _ := hex.DecodeString(test.Output)

	d, err := NewDigest(nil, nil, nil, 32)
	if err != nil {
		t.Error(err)
	}

	d.Write(decodedInput)

	if !bytes.Equal(decodedOutput, d.Sum(nil)) {
		t.Errorf("Single representative write produced wrong output")
	}
}

func TestKeyedWrite(t *testing.T) {
	test := &ReferenceTestVector{
		Input:  "00",
		Key:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		Output: "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
	}

	decodedInput, _ := hex.DecodeString(test.Input)
	if len(decodedInput) == 0 {
		decodedInput = nil
	}
	decodedKey, _ := hex.DecodeString(test.Key)
	if len(decodedKey) == 0 {
		decodedKey = nil
	}
	decodedOutput, _ := hex.DecodeString(test.Output)
	d, err := NewDigest(decodedKey, nil, nil, 32)
	if err != nil {
		t.Error(err)
	}
	if decodedInput != nil {
		d.Write(decodedInput)
	}
	if !bytes.Equal(decodedOutput, d.Sum(nil)) {
		t.Errorf("Failed test: %v", test.Output)
	}
}

func TestMultiBlockWrite(t *testing.T) {
	test := &ReferenceTestVector{
		Input:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
		Key:    "",
		Output: "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472",
	}
	decodedInput, _ := hex.DecodeString(test.Input)
	if len(decodedInput) == 0 {
		decodedInput = nil
	}
	decodedKey, _ := hex.DecodeString(test.Key)
	if len(decodedKey) == 0 {
		decodedKey = nil
	}
	decodedOutput, _ := hex.DecodeString(test.Output)
	d, err := NewDigest(decodedKey, nil, nil, 32)
	if err != nil {
		t.Error(err)
	}
	if decodedInput != nil {
		d.Write(decodedInput)
	}
	if !bytes.Equal(decodedOutput, d.Sum(nil)) {
		t.Errorf("Failed test: %v", test.Output)
	}
}

func TestStreamingWrite(t *testing.T) {
	test := &ReferenceTestVector{
		Input:  "00010203",
		Key:    "",
		Output: "0cc70e00348b86ba2944d0c32038b25c55584f90df2304f55fa332af5fb01e20",
	}

	decodedInput, _ := hex.DecodeString(test.Input)
	decodedOutput, _ := hex.DecodeString(test.Output)

	d, err := NewDigest(nil, nil, nil, 32)
	if err != nil {
		t.Error(err)
	}

	d.Write(decodedInput[:len(decodedInput)/2])
	_ = d.Sum(nil)
	d.Write(decodedInput[len(decodedInput)/2:])

	if !bytes.Equal(decodedOutput, d.Sum(nil)) {
		t.Errorf("Interrupted write produced wrong output")
	}
}

var extrasVectors = []struct {
	input, key, salt, personality, output string
}{
	{
		input:       "",
		key:         "",
		salt:        "",
		personality: "",
		output:      "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
	},

	{
		input:       "",
		key:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		salt:        "",
		personality: "",
		output:      "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
	},
	{
		input:       "",
		key:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		salt:        "",
		personality: "personal",
		output:      "25a4ee63b594aed3f88a971e1877ef7099534f9097291f88fb86c79b5e70d022",
	},
	{
		input:       "",
		key:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		salt:        "",
		personality: "pers0nal",
		output:      "4b25933bf9a95a67d95d104a86b2d31753a1030e22bb55cc85a523d1650484b7",
	},
}

func TestPersona(t *testing.T) {
	for _, test := range extrasVectors {
		decodedInput, _ := hex.DecodeString(test.input)
		if len(decodedInput) == 0 {
			decodedInput = nil
		}
		decodedKey, _ := hex.DecodeString(test.key)
		if len(decodedKey) == 0 {
			decodedKey = nil
		}
		decodedSalt, _ := hex.DecodeString(test.salt)
		if len(decodedSalt) == 0 {
			decodedSalt = nil
		}
		decodedOutput, _ := hex.DecodeString(test.output)
		d, err := NewDigest(decodedKey, decodedSalt, []byte(test.personality), 32)
		if err != nil {
			t.Fatal(err)
		}
		if decodedInput != nil {
			fmt.Println(decodedInput)
			n, _ := d.Write(decodedInput)
			fmt.Println(n)
		}
		if !bytes.Equal(decodedOutput, d.Sum(nil)) {
			t.Errorf("Failed test: %v", test)
		}
	}
}

//go:generate python3 gen_vectors.py testdata/blake2s-extras.json

func TestExtrasVectors(t *testing.T) {
	jsonTestData, err := ioutil.ReadFile("testdata/blake2s-extras.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []ReferenceTestVector
	err = json.Unmarshal(jsonTestData, &tests)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		if test.Hash != "blake2s" {
			t.Errorf("Got a test for the wrong hash: %s", test.Hash)
			continue
		}
		decodedInput, _ := hex.DecodeString(test.Input)
		if len(decodedInput) == 0 {
			decodedInput = nil
		}
		decodedKey, _ := hex.DecodeString(test.Key)
		if len(decodedKey) == 0 {
			decodedKey = nil
		}
		decodedSalt, _ := hex.DecodeString(test.Salt)
		if len(decodedSalt) == 0 {
			decodedSalt = nil
		}
		decodedPersona, _ := hex.DecodeString(test.Persona)
		if len(decodedPersona) == 0 {
			decodedPersona = nil
		}
		decodedOutput, _ := hex.DecodeString(test.Output)

		d, err := NewDigest(decodedKey, decodedSalt, decodedPersona, 32)
		if err != nil {
			t.Error(err)
			continue
		}

		if decodedInput != nil {
			d.Write(decodedInput)
		}

		if !bytes.Equal(decodedOutput, d.Sum(nil)) {
			t.Errorf("Failed test: %v", test.Output)
			break
		}
	}
}

var emptyBuf = make([]byte, 8192)

func benchmarkHashSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		digest, _ := NewDigest(nil, nil, nil, 32)
		digest.Write(emptyBuf[:size])
		digest.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkHashSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkHashSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkHashSize(b, 8192)
}
