package vault

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSetHeaderAndGetHeaderJSON(t *testing.T) {
	// Create a sample header
	sampleHeader := Header{
		Version: 1,
		Cipher:  "xchacha20poly1305",
		KDF: struct {
			Alg  string `json:"alg"`
			Salt []byte `json:"salt"`
			MKiB uint32 `json:"m_kib"`
			T    uint32 `json:"t"`
			P    uint8  `json:"p"`
		}{
			Alg:  "argon2id",
			Salt: []byte("random_salt"),
			MKiB: 65536,
			T:    3,
			P:    4,
		},
		Wraps: []Wrap{
			{
				ID:         "master",
				Kind:       "password",
				Nonce:      []byte("random_nonce"),
				Ciphertext: []byte("encrypted_master_key"),
			},
		},
		BodyNonce: []byte("body_nonce"),
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
		Revision:  42,
	}

	// Convert the sample header to JSON
	jsonData, err := json.Marshal(sampleHeader)
	if err != nil {
		t.Fatalf("Failed to marshal header to JSON: %v", err)
	}

	// Test SetHeader function
	header, err := SetHeader(jsonData)
	if err != nil {
		t.Fatalf("SetHeader failed: %v", err)
	}

	if header.Version != sampleHeader.Version || header.Cipher != sampleHeader.Cipher {
		t.Errorf("SetHeader returned unexpected values: got %v, want %v", header, sampleHeader)
	}

	// Test GetHeaderJSON function
	returnedJSON, err := GetHeaderJSON(header)
	if err != nil {
		t.Fatalf("GetHeaderJSON failed: %v", err)
	}

	if !json.Valid(returnedJSON) {
		t.Errorf("GetHeaderJSON returned invalid JSON")
	}
}
