package vault

import (
	"testing"
	"time"
	"github.com/chetankar/openpass/internal/crypto"
	"bytes"
)

func TestVaultLifecycle(t *testing.T) {
	// Test adding an entry to the vault
	vault := NewVault()
	secret := crypto.Secret{Data: []byte("supersecret")}
	customSecret := crypto.Secret{Data: []byte("customsecret")}
	entry := Entry{
		ID:        "1",
		Name:      "example.com",
		Username:  "user",
		Secret:    secret,
		URLs:      []string{"https://example.com"},
		Notes:     "Sample entry",
		Tags:      []string{"tag1", "tag2"},
		Custom:    map[string]crypto.Secret{"custom_field": customSecret},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := vault.AddEntry(entry)
	if err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}

	if len(vault.GetEntries()) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(vault.GetEntries()))
	}

	retrievedEntry := vault.GetEntries()[0]
	if retrievedEntry.Name != "example.com" {
		t.Errorf("Expected entry name example.com, got %s", retrievedEntry.Name)
	}
	if retrievedEntry.Username != "user" {
		t.Errorf("Expected username user, got %s", retrievedEntry.Username)
	}
	if !bytes.Equal(retrievedEntry.Secret.Data, secret.Data) {
		t.Errorf("Expected secret %s, got %s", string(secret.Data), string(retrievedEntry.Secret.Data))
	}

	if !bytes.Equal(retrievedEntry.Custom["custom_field"].Data, customSecret.Data) {
		t.Errorf("Expected custom secret %s, got %s", string(customSecret.Data), string(retrievedEntry.Custom["custom_field"].Data))
	}
}