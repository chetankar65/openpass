package vault

import (
	"errors"
	"fmt"
	"os"

	"github.com/chetankar/openpass/internal/crypto"
)

const (
	kdfAlgArgon2id = "argon2id"

	wrapIDMaster     = "master"
	wrapKindPassword = "password"
)

// Init creates a new vault at path and returns it along with its DEK.
//
// Passing nil params uses DefaultArgon2Params.
//
// The caller owns the returned DEK and must ClearSecret it when the vault is
// locked. Init does not zero password; that is the caller's buffer.
func Init(path string, password []byte, params *crypto.Argon2Params) (*Vault, *crypto.Secret, error) {
	if len(password) == 0 {
		return nil, nil, fmt.Errorf("cannot initialise a vault with an empty master password")
	}

	// Refuse rather than overwrite. Clobbering an existing vault is
	// unrecoverable, so it must never be the result of a mistyped path.
	if _, err := os.Stat(path); err == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrVaultExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("failed to check for an existing vault: %w", err)
	}

	if params == nil {
		params = crypto.DefaultArgon2Params()
	}
	if err := params.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid KDF parameters: %w", err)
	}

	salt, err := crypto.GenerateSalt(crypto.MinSaltLength)
	if err != nil {
		return nil, nil, err
	}

	kekBytes, err := params.DeriveKey(password, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive the key-encryption key: %w", err)
	}
	kek := crypto.SetSecret(kekBytes)
	zero(kekBytes)
	defer kek.ClearSecret()

	dek, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate the data-encryption key: %w", err)
	}

	v := NewVault()
	v.Header.Version = formatVersion
	v.Header.Cipher = cipherName
	v.Header.KDF.Alg = kdfAlgArgon2id
	v.Header.KDF.Salt = salt
	v.Header.KDF.MKiB = params.Memory
	v.Header.KDF.T = params.Time
	v.Header.KDF.P = params.Parallelism

	wrap, err := sealWrap(v.Header, wrapIDMaster, wrapKindPassword, kek, dek)
	if err != nil {
		dek.ClearSecret()
		return nil, nil, err
	}
	v.Header.Wraps = []Wrap{wrap}

	if err := Encode(path, v, dek); err != nil {
		dek.ClearSecret()
		return nil, nil, err
	}

	return v, dek, nil
}

// sealWrap encrypts the DEK under kek, producing one wrap of the key hierarchy.
//
// Creating a wrap requires already holding the DEK, which is why an attacker
// with only the vault file cannot add one: they would have to have opened it
// first.
func sealWrap(h Header, id, kind string, kek, dek *crypto.Secret) (Wrap, error) {
	wrap := Wrap{
		ID:    id,
		Kind:  kind,
		Nonce: crypto.GenerateNonce(),
	}

	aad, err := h.WrapAAD(wrap)
	if err != nil {
		return Wrap{}, err
	}

	ciphertext, err := crypto.Seal(kek.GetSecret(), wrap.Nonce, dek.GetSecret(), aad)
	if err != nil {
		return Wrap{}, fmt.Errorf("failed to seal the %s wrap: %w", id, err)
	}
	wrap.Ciphertext = ciphertext

	return wrap, nil
}
