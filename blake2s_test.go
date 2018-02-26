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
	Hash   string `json:"hash"`
	Input  string `json:"in"`
	Key    string `json:"key"`
	Output string `json:"out"`
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

var testVectors = []struct {
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

func TestPersonality(t *testing.T) {
	for _, test := range testVectors {
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
