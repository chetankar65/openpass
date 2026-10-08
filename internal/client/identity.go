package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Identity is a client's keypair. Every client — the CLI, the browser bridge,
// anything else — holds one and signs every request with it.
type Identity struct {
	ID   string
	Name string
	Kind string

	priv ed25519.PrivateKey
}

type identityFile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	PrivateKey []byte `json:"private_key"`
}

// LoadOrCreateIdentity reads the keypair at path, generating one if absent.
func LoadOrCreateIdentity(path, name, kind string) (*Identity, error) {
	if id, err := loadIdentity(path); err == nil {
		return id, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return createIdentity(path, name, kind)
}

func loadIdentity(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var f identityFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if len(f.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s holds a malformed key", path)
	}

	return &Identity{ID: f.ID, Name: f.Name, Kind: f.Kind, priv: f.PrivateKey}, nil
}

func createIdentity(path, name, kind string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a keypair: %w", err)
	}

	id := &Identity{ID: DeriveClientID(kind, pub), Name: name, Kind: kind, priv: priv}

	data, err := json.Marshal(identityFile{ID: id.ID, Name: name, Kind: kind, PrivateKey: priv})
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", path, err)
	}
	return id, nil
}

// DeriveClientID produces a stable id from a public key.
func DeriveClientID(kind string, pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return kind + "-" + hex.EncodeToString(sum[:6])
}

func (i *Identity) PublicKey() ed25519.PublicKey {
	return i.priv.Public().(ed25519.PublicKey)
}

// Auth is the signature block attached to every request.
type Auth struct {
	ClientID string `json:"client_id"`
	Nonce    string `json:"nonce"`
	TS       int64  `json:"ts"`
	Sig      string `json:"sig"`
}

// SigningString is what gets signed. Both sides build it from the exact params
// bytes on the wire, so there is no canonicalization to disagree about.
func SigningString(method string, params []byte, nonce string, ts int64) []byte {
	return []byte(method + "\n" + string(params) + "\n" + nonce + "\n" + strconv.FormatInt(ts, 10))
}

// Sign builds the auth block for one request.
func (i *Identity) Sign(method string, params []byte) (*Auth, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	nonce := base64.StdEncoding.EncodeToString(raw)
	ts := time.Now().Unix()

	sig := ed25519.Sign(i.priv, SigningString(method, params, nonce, ts))

	return &Auth{
		ClientID: i.ID,
		Nonce:    nonce,
		TS:       ts,
		Sig:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}
