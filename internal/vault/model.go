package vault

import (
	"time"

	"github.com/chetankar/openpass/internal/crypto"
)

type Entry struct {
	ID        string // uuidv4, stable
	Name      string // "GitHub", user-facing label
	Username  string
	Secret    crypto.Secret // the password itself
	URLs      []string      // full URLs; matching is on eTLD+1
	Notes     string
	Tags      []string
	Custom    map[string]crypto.Secret // arbitrary extra fields
	CreatedAt time.Time
	UpdatedAt time.Time
}

/*
 offset  size   field
 ------  -----  -------------------------------------------------
      0      8  magic        "OPENPASS"
      8      1  format_ver   0x01
      9      4  header_len   uint32 big-endian
     13      N  header       canonical JSON, UTF-8
   13+N      *  body         XChaCha20-Poly1305 ciphertext || tag
*/

type Vault struct {
	Magic     [8]byte /// "OPENPASS"
	FormatVer uint8   /// 0x01
	HeaderLen uint32  /// length of the header in bytes
	Header    Header  /// canonical JSON, UTF-8
	Body      []Entry /// list of entries in the vault
}

func NewVault() *Vault {
	return &Vault{
		Magic:     [8]byte{'O', 'P', 'E', 'N', 'P', 'A', 'S', 'S'},
		FormatVer: 0x01,
		HeaderLen: 0,
		Header:    Header{},
		Body:      []Entry{},
	}
}

// Add a new entry to the vault. The entry is appended to the body slice, and will be encrypted when the vault is saved.
func (v *Vault) AddEntry(entry Entry) error {
	v.Body = append(v.Body, entry)
	return nil
}

func (v *Vault) GetEntries() []Entry {
	return v.Body
}

