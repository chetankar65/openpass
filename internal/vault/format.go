package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type Wrap struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ct"` /// this is the encrypted master key, which is used to encrypt the body of the vault
}

type Header struct {
	Version uint8  `json:"v"`
	Cipher  string `json:"cipher"`
	KDF     struct {
		Alg  string `json:"alg"`
		Salt []byte `json:"salt"`
		MKiB uint32 `json:"m_kib"`
		T    uint32 `json:"t"`
		P    uint8  `json:"p"`
	} `json:"kdf"`
	// The wraps field is a list of encrypted master keys. Its easier to add new auth methods this way. Password, fingerprint, yubikey, etc.
	// Each wrap has a unique ID and kind, and the nonce and ciphertext for the encrypted master key.
	Wraps     []Wrap `json:"wraps"`
	BodyNonce []byte `json:"body_nonce"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Revision  int    `json:"rev"`
}

func SetHeader(jsonData []byte) (Header, error) {
	var header Header
	err := json.Unmarshal(jsonData, &header)
	if err != nil {
		return Header{}, fmt.Errorf("failed to unmarshal header: %v", err)
	}
	return header, nil
}

func GetHeaderJSON(header Header) ([]byte, error) {
	jsonData, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %v", err)
	}
	return jsonData, nil
}

// CanonicalAAD returns the additional authenticated data for this header: the
// header JSON with every wraps[].ct blanked.

// The ct fields are excluded because each wrap's ciphertext is produced *using*
// this AAD, so including it would be circular. 
//
func (h Header) CanonicalAAD() ([]byte, error) {
	blanked := h
	blanked.Wraps = make([]Wrap, len(h.Wraps))
	copy(blanked.Wraps, h.Wraps)
	for i := range blanked.Wraps {
		blanked.Wraps[i].Ciphertext = nil
	}

	aad, err := json.Marshal(blanked)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header for AAD: %v", err)
	}
	return aad, nil
}

// WrapAAD returns the additional authenticated data for a single wrap. AAD covers only stable fields — the format version,
// the cipher, and the wrap's own id, kind and nonce.
func (h Header) WrapAAD(w Wrap) ([]byte, error) {
	// w is a copy, so blanking ct here does not disturb the caller's wrap.
	w.Ciphertext = nil

	aad, err := json.Marshal(struct {
		Version uint8  `json:"v"`
		Cipher  string `json:"cipher"`
		Wrap    Wrap   `json:"wrap"`
	}{
		Version: h.Version,
		Cipher:  h.Cipher,
		Wrap:    w,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrap for AAD: %v", err)
	}
	return aad, nil
}

// VerifyCanonical checks that raw is exactly the canonical encoding of h.
//
// Decode must call this on the header bytes it read, before using CanonicalAAD.
func VerifyCanonical(raw []byte, h Header) error {
	canonical, err := GetHeaderJSON(h)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return fmt.Errorf("header is not in canonical form: the file has been modified")
	}
	return nil
}
