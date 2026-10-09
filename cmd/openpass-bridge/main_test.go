package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func framedRaw(data []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)
	return buf.Bytes()
}

func TestFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeMessage(&buf, incoming{ID: 7, Method: "status"}); err != nil {
		t.Fatal(err)
	}

	msg, err := readMessage(&buf)
	if err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}

	var got incoming
	if err := json.Unmarshal(msg, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 7 || got.Method != "status" {
		t.Errorf("round trip gave %+v", got)
	}
}

// A length header the browser never sent must not cause a huge allocation.
func TestReadMessageRejectsAbsurdLength(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	buf.WriteString("{}")

	if _, err := readMessage(&buf); err == nil {
		t.Error("a 4 GB length was accepted")
	}
}

func TestReadMessageRejectsZeroLength(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	if _, err := readMessage(&buf); err == nil {
		t.Error("a zero-length message was accepted")
	}
}

func TestReadMessageRejectsTruncated(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(100))
	buf.WriteString("short")

	if _, err := readMessage(&buf); err == nil {
		t.Error("a truncated message was accepted")
	}
}

// The bridge must refuse methods the extension has no business calling, even
// before the daemon gets a chance to.
func TestProxyRefusesUnlistedMethods(t *testing.T) {
	b := &bridge{}

	for _, method := range []string{"vault.delete", "vault.update", "unlock", "lock", "client.revoke", "vault.init", "events.subscribe"} {
		_, rerr := b.proxy(nil, incoming{Method: method})
		if rerr == nil {
			t.Errorf("%s was proxied", method)
			continue
		}
		if !strings.Contains(rerr.Message, "not available over the bridge") {
			t.Errorf("%s gave an unexpected error: %s", method, rerr.Message)
		}
	}
}

// The bridge surface is exactly what the extension needs. Anything added here
// also has to be allowed by the daemon's per-client policy.
func TestProxySurface(t *testing.T) {
	want := map[string]bool{
		"status":      true,
		"vault.match": true,
		"vault.get":   true,
		"vault.add":   true,
	}

	b := &bridge{}
	for method := range want {
		// A nil client would panic if the method were proxied, so this only
		// checks that the method is routed rather than refused outright.
		func() {
			defer func() { recover() }()
			if _, rerr := b.proxy(nil, incoming{Method: method}); rerr != nil &&
				strings.Contains(rerr.Message, "not available over the bridge") {
				t.Errorf("%s is not routed by the bridge", method)
			}
		}()
	}
}

// Malformed JSON must produce an error frame, not kill the bridge.
func TestRunSurvivesMalformedJSON(t *testing.T) {
	var in bytes.Buffer
	in.Write(framedRaw([]byte(`{"not":`)))

	var out bytes.Buffer
	b := &bridge{}
	_ = b.run(&in, &out)

	msg, err := readMessage(&out)
	if err != nil {
		t.Fatalf("no response frame was written: %v", err)
	}

	var resp outgoing
	if err := json.Unmarshal(msg, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil {
		t.Error("malformed JSON did not produce an error response")
	}
}
