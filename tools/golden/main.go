// Command golden writes byte-exact reference files produced by the Go
// implementation so the Rust port can prove format compatibility: ledger
// hash chains and signatures, export bundles, evidence documents, detached
// Charter signatures, policy-bundle signing payloads and scrubber output.
//
// Usage: go run ./tools/golden <out-dir>
//
// Every input is fixed (seeded keys, explicit timestamps), so re-running the
// generator is deterministic. It is removed with the rest of the Go tree once
// the Rust port is the only implementation.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Runewardd/runeward/internal/evidence"
	"github.com/Runewardd/runeward/internal/ledger"
	"github.com/Runewardd/runeward/internal/policybundle"
	"github.com/Runewardd/runeward/internal/profile"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: golden <out-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "golden:", err)
		os.Exit(1)
	}
}

func seededKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("runeward-golden:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func run(out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := ledgerFixtures(out); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	if err := charterFixtures(out); err != nil {
		return fmt.Errorf("charter: %w", err)
	}
	if err := bundleFixtures(out); err != nil {
		return fmt.Errorf("policy bundle: %w", err)
	}
	return scrubFixtures(out)
}

func ledgerFixtures(out string) error {
	dir := filepath.Join(out, "ledger")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	priv := seededKey("ledger")
	// The Go signer stores the raw 64-byte seed||pub private key.
	if err := os.WriteFile(filepath.Join(dir, "ledger.key"), priv, 0o600); err != nil {
		return err
	}
	signer, err := ledger.LoadOrCreateSigner(dir)
	if err != nil {
		return err
	}
	pub := signer.Public()
	if err := os.WriteFile(filepath.Join(dir, "ledger.pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}

	path := filepath.Join(dir, "ledger.jsonl")
	_ = os.Remove(path)
	l, err := ledger.Open(path)
	if err != nil {
		return err
	}
	defer l.Close()
	l.SetSigner(signer)

	base := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	plain := []ledger.Event{
		// Whole-second time: RFC3339Nano drops the fraction entirely.
		{Time: base, SessionID: "s-1", Sandbox: "cit-a", Profile: "quickstart", Tool: "shell", Action: "echo hi", Args: []string{"echo", "hi"}, Verdict: "allow", DurationMS: 12},
		// Trailing zeros in the fraction are stripped (".12").
		{Time: base.Add(120 * time.Millisecond), SessionID: "s-1", Sandbox: "cit-a", Profile: "quickstart", Tool: "shell", Action: "rm -rf /", Args: []string{"rm", "-rf", "/"}, Verdict: "deny", ExitCode: -1, Meta: map[string]string{"reason": "destructive", "actor": "alice", "run_id": "run-1"}},
		// Full nanosecond precision and non-ASCII payloads.
		{Time: base.Add(1*time.Second + 123456789*time.Nanosecond), SessionID: "s-2", Sandbox: "cit-b", Profile: "governed", Tool: "file", Action: "write café.txt", Verdict: "allow", Meta: map[string]string{"bytes": "5", "path": "/work/café.txt"}},
		{Time: base.Add(2*time.Second + 1000*time.Nanosecond), SessionID: "s-1", Sandbox: "cit-a", Profile: "quickstart", Tool: "egress", Action: "CONNECT api.github.com:443", Verdict: "require-approval", ExitCode: 0, DurationMS: 250},
		// Non-UTC input is normalised to UTC before hashing.
		{Time: base.Add(3 * time.Second).In(time.FixedZone("WAT", 3600)), SessionID: "s-2", Sandbox: "cit-b", Profile: "governed", Tool: "python", Action: "print(1)", Verdict: "allow", ExitCode: 3, DurationMS: 9_000_000_000},
	}
	for i, ev := range plain {
		if i == 3 {
			// Redact everything; keeps payload_hash of the original.
			ev = ledger.Redact(ev)
		}
		if i == 4 {
			ev = ledger.Redact(ev, "print(1)")
		}
		if _, err := l.Append(ev); err != nil {
			return err
		}
	}
	// An event with empty strings and an empty (non-nil) meta map.
	if _, err := l.Append(ledger.Event{Time: base.Add(4 * time.Second), Tool: "", Action: "", Verdict: "", Meta: map[string]string{}}); err != nil {
		return err
	}
	if err := l.Verify(); err != nil {
		return err
	}

	var all, sess bytes.Buffer
	if err := l.ExportBundle(&all, "", pub); err != nil {
		return err
	}
	if err := l.ExportBundle(&sess, "s-1", pub); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle-all.json"), all.Bytes(), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle-session-s-1.json"), sess.Bytes(), 0o644); err != nil {
		return err
	}

	var b ledger.Bundle
	if err := json.Unmarshal(all.Bytes(), &b); err != nil {
		return err
	}
	doc := evidence.New("v0.0.0-golden", "quickstart", ".runeward/quickstart.toml", "ghcr.io/runewardd/sandbox:latest", "/abs/.runeward/quickstart.toml",
		[]evidence.Finding{{Severity: "warning", Field: "network.default", Message: "egress is open"}}, b)
	doc.GeneratedAt = base.Add(5*time.Second + 500*time.Millisecond)
	doc.Policy.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("charter")))
	var ev bytes.Buffer
	if err := evidence.Write(&ev, doc); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "evidence.json"), ev.Bytes(), 0o644)
}

func charterFixtures(out string) error {
	dir := filepath.Join(out, "charter")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	priv := seededKey("charter")
	content := []byte("[host]\ntype = \"container\"\nimage = \"alpine:3.20\"\n\n[[policy]]\ntool = \"shell\"\nmatch = \"rm -rf *\"\nverdict = \"deny\"\n")
	sig, err := profile.NewSignature(content, priv).Marshal()
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"signed.toml":     content,
		"signed.toml.sig": sig,
		"charter.pub":     []byte(policybundle.EncodeKey(priv.Public().(ed25519.PublicKey)) + "\n"),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// bundleFixtures records the canonical OCI policy-bundle signing payload and
// its signature. The payload format mirrors policybundle.signingPayload.
func bundleFixtures(out string) error {
	priv := seededKey("bundle")
	pub := priv.Public().(ed25519.PublicKey)
	config := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(`{"engine":"rego","query":"data.runeward.decision"}`)))
	layer := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("package runeward\n")))
	payload := "runeward.policy.bundle.v1\nconfig=" + config + "\nlayer=" + layer
	fx := map[string]string{
		"private_key": policybundle.EncodeKey(priv),
		"public_key":  policybundle.EncodeKey(pub),
		"key_id":      policybundle.KeyID(pub),
		"payload":     payload,
		"signature":   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload))),
	}
	b, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "policy-bundle.json"), append(b, '\n'), 0o644)
}

func scrubFixtures(out string) error {
	type tc struct {
		In        string   `json:"in"`
		Sensitive []string `json:"sensitive,omitempty"`
		Out       string   `json:"out"`
	}
	inputs := []tc{
		{In: "curl -H 'Authorization: Bearer abc.def.ghi' https://x"},
		{In: "export OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnopqrstuvwxyzABCD"},
		{In: "token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB here"},
		{In: "aws AKIAIOSFODNN7EXAMPLE key"},
		{In: "password=hunter2 and secret: s3cr3t"},
		{In: "the value my-secret-value appears", Sensitive: []string{"my-secret-value"}},
		{In: "nothing to see here"},
		{In: "blob Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"},
	}
	for i := range inputs {
		inputs[i].Out = ledger.ScrubString(inputs[i].In, inputs[i].Sensitive...)
	}
	b, err := json.MarshalIndent(inputs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "scrub.json"), append(b, '\n'), 0o644)
}
