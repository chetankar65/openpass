package daemon

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/chetankar/openpass/internal/client"
)

// With nothing watching, a reveal must be refused rather than hang or succeed.
func TestRevealDeniedWithNoWatcher(t *testing.T) {
	s, dir := startServer(t)

	cli, _ := dialAs(t, s, dir, "cli", "cli")
	if err := cli.Init([]byte(serverTestPassword)); err != nil {
		t.Fatal(err)
	}
	id, err := cli.Add(client.AddParams{Name: "GitHub", Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}

	ext, pair := dialAs(t, s, dir, "ext", "browser")
	if _, err := cli.ApproveClient(pair.Code); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ext.Get(id, true)
		done <- err
	}()

	select {
	case err := <-done:
		if !client.IsCode(err, codeDeniedByPolicy) {
			t.Errorf("err = %v, want DENIED_BY_POLICY", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request hung instead of being refused")
	}
}

// setupWithWatcher gives an approved browser client, an entry, and a watcher.
func setupWithWatcher(t *testing.T) (ext *client.Client, watcher *client.Client, entryID string) {
	t.Helper()

	s, dir := startServer(t)

	cli, _ := dialAs(t, s, dir, "cli", "cli")
	if err := cli.Init([]byte(serverTestPassword)); err != nil {
		t.Fatal(err)
	}

	id, err := cli.Add(client.AddParams{
		Name: "GitHub", Password: "hunter2", URLs: []string{"https://github.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	ext, pair := dialAs(t, s, dir, "ext", "browser")
	if _, err := cli.ApproveClient(pair.Code); err != nil {
		t.Fatal(err)
	}

	// The watcher reuses the CLI identity on its own connection.
	watcher, _ = dialAs(t, s, dir, "cli", "cli")
	if err := watcher.Subscribe(); err != nil {
		t.Fatal(err)
	}

	return ext, watcher, id
}

// answerOnce waits for one question and answers it.
func answerOnce(t *testing.T, w *client.Client, allow bool, ttl int) chan client.ApprovalRequest {
	t.Helper()

	seen := make(chan client.ApprovalRequest, 1)
	go func() {
		note, err := w.ReadNotification()
		if err != nil {
			return
		}
		var req client.ApprovalRequest
		if err := json.Unmarshal(note.Params, &req); err != nil {
			return
		}
		seen <- req
		w.Respond(req.ID, allow, ttl)
	}()
	return seen
}

func TestRevealAllowedWhenApproved(t *testing.T) {
	ext, watcher, id := setupWithWatcher(t)
	seen := answerOnce(t, watcher, true, 0)

	entry, err := ext.Get(id, true)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if entry.Password != "hunter2" {
		t.Errorf("password = %q, want hunter2", entry.Password)
	}

	select {
	case req := <-seen:
		// The human must be told what they are approving.
		if req.Entry != "GitHub" {
			t.Errorf("entry = %q, want GitHub", req.Entry)
		}
		if req.Domain != "github.com" {
			t.Errorf("domain = %q, want github.com", req.Domain)
		}
		if req.Client == "" {
			t.Error("the request does not say which client is asking")
		}
	case <-time.After(time.Second):
		t.Error("no approval question was delivered")
	}
}

func TestRevealDeniedWhenRejected(t *testing.T) {
	ext, watcher, id := setupWithWatcher(t)
	answerOnce(t, watcher, false, 0)

	if _, err := ext.Get(id, true); !client.IsCode(err, codeUserRejected) {
		t.Errorf("err = %v, want USER_REJECTED", err)
	}
}

// Metadata never needs approval; only the secret does.
func TestMetadataNeedsNoApproval(t *testing.T) {
	ext, _, id := setupWithWatcher(t)

	if _, err := ext.Get(id, false); err != nil {
		t.Errorf("reading metadata asked for approval: %v", err)
	}
	if _, err := ext.List(); err != nil {
		t.Errorf("list asked for approval: %v", err)
	}
	if _, err := ext.Match("https://github.com", false); err != nil {
		t.Errorf("match asked for approval: %v", err)
	}
}

// A grant lets the next fill through without a second prompt.
func TestGrantSkipsTheSecondPrompt(t *testing.T) {
	ext, watcher, id := setupWithWatcher(t)
	answerOnce(t, watcher, true, 300)

	if _, err := ext.Get(id, true); err != nil {
		t.Fatalf("first get failed: %v", err)
	}

	// Nothing is answering now; the grant has to carry this one.
	second := make(chan error, 1)
	go func() {
		_, err := ext.Get(id, true)
		second <- err
	}()

	select {
	case err := <-second:
		if err != nil {
			t.Errorf("second get was not covered by the grant: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("the second get prompted again despite the grant")
	}
}

// Without a grant, the next reveal asks again.
func TestNoGrantPromptsEveryTime(t *testing.T) {
	ext, watcher, id := setupWithWatcher(t)
	answerOnce(t, watcher, true, 0)

	if _, err := ext.Get(id, true); err != nil {
		t.Fatalf("first get failed: %v", err)
	}

	// A second question must arrive. Nobody answers it, so the reveal itself
	// will eventually time out; what matters is that the human was asked.
	asked := make(chan struct{}, 1)
	go func() {
		if _, err := watcher.ReadNotification(); err == nil {
			asked <- struct{}{}
		}
	}()
	go ext.Get(id, true)

	select {
	case <-asked:
	case <-time.After(3 * time.Second):
		t.Error("the second reveal did not ask again")
	}
}

func TestBrokerFailsClosedOnTimeout(t *testing.T) {
	b := NewBroker()
	_, unsubscribe := b.Subscribe()
	defer unsubscribe()

	// Park a request and never answer it.
	start := time.Now()
	err := b.askWithTimeout(ApprovalRequest{Entry: "x"}, 100*time.Millisecond)

	if !errors.Is(err, ErrApprovalStale) {
		t.Errorf("err = %v, want ErrApprovalStale", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waited %v before giving up", elapsed)
	}
}

func TestBrokerRejectsWithNoWatcher(t *testing.T) {
	b := NewBroker()

	if err := b.Ask(ApprovalRequest{Entry: "x"}); !errors.Is(err, ErrNoWatcher) {
		t.Errorf("err = %v, want ErrNoWatcher", err)
	}
}

func TestRevokeGrantsClearsThem(t *testing.T) {
	b := NewBroker()
	events, unsubscribe := b.Subscribe()
	defer unsubscribe()

	go func() {
		req := <-events
		b.Respond(req.ID, true, 300)
	}()

	if err := b.Ask(ApprovalRequest{ClientID: "c", Domain: "github.com"}); err != nil {
		t.Fatal(err)
	}

	b.RevokeGrants()

	// With the grant gone and nobody answering, this must not pass.
	if err := b.askWithTimeout(ApprovalRequest{ClientID: "c", Domain: "github.com"}, 100*time.Millisecond); err == nil {
		t.Error("a revoked grant still allowed a reveal")
	}
}
