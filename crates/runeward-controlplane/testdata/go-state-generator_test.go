package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Runewardd/runeward/internal/backend"
	"github.com/Runewardd/runeward/internal/fleet"
	"github.com/Runewardd/runeward/internal/ledger"
	"github.com/Runewardd/runeward/internal/policy"
	"github.com/Runewardd/runeward/internal/profile"
)

// TestGenerateRustFixtures writes Go-produced control-plane state for the
// Rust port's compatibility test. Run with RW_FIXTURE_OUT=<dir>.
func TestGenerateRustFixtures(t *testing.T) {
	out := os.Getenv("RW_FIXTURE_OUT")
	if out == "" {
		t.Skip("RW_FIXTURE_OUT not set")
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	ts := func(sec int64, nsec int64) time.Time { return time.Unix(sec, nsec).UTC() }

	l, err := ledger.Open(filepath.Join(out, "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ledger.LoadOrCreateSigner(out)
	if err != nil {
		t.Fatal(err)
	}
	l.SetSigner(signer)
	defer l.Close()

	m := &Manager{
		stateDir:         out,
		ledger:           l,
		signer:           signer,
		approvals:        NewApprovalStore(),
		sessions:         map[string]*Session{},
		snapshots:        map[string]backend.SnapshotRef{},
		snapshotOwners:   map[string]string{},
		fleets:           map[string]*Fleet{},
		runs:             map[string]Run{},
		agentSessions:    map[string]*AgentSession{},
		agentSubscribers: map[string]map[chan AgentEvent]struct{}{},
		agentCancels:     map[string]context.CancelFunc{},
	}
	if m.leaseKey, err = loadOrCreateLeaseKey(out); err != nil {
		t.Fatal(err)
	}

	// runs.json
	fin1 := ts(1_700_000_100, 120_000_000)
	fin2 := ts(1_700_000_200, 0)
	m.runs["run-a"] = Run{ID: "run-a", CitadelID: "c-a", Tenant: "team <a&b>", Actor: "codex", Charter: "dev", Agent: "codex", Provider: "openai-compatible", Model: "m1", Status: "completed", CreatedAt: ts(1_700_000_000, 123_450_000), FinishedAt: &fin1}
	m.runs["run-b"] = Run{ID: "run-b", ParentRunID: "run-a", CitadelID: "c-b", Charter: "dev", Status: "failed", CreatedAt: ts(1_700_000_050, 1), FinishedAt: &fin2, Error: "boom \"quoted\" é"}
	if err := m.saveRuns(); err != nil {
		t.Fatal(err)
	}

	// fleets.json
	far := ts(4_102_444_800, 500_000_000) // 2100-01-01
	tasks := []fleet.Task{
		{ID: "t-pending", Payload: "write <docs> & tests", State: fleet.StatePending, CreatedAt: ts(1_700_000_000, 0), UpdatedAt: ts(1_700_000_000, 0)},
		{ID: "t-claimed", Payload: "b", State: fleet.StateClaimed, Owner: "w1", Attempts: 1, CreatedAt: ts(1_700_000_001, 10), UpdatedAt: ts(1_700_000_002, 999_999_999), LeaseExpiry: far, LeaseVersion: 3},
		{ID: "t-done", Payload: "c", State: fleet.StateDone, Owner: "w2", Attempts: 2, CreatedAt: ts(1_700_000_003, 0), UpdatedAt: ts(1_700_000_004, 0), Result: "ok"},
		{ID: "t-failed", Payload: "d", State: fleet.StateFailed, Owner: "w3", Attempts: 1, CreatedAt: ts(1_700_000_005, 0), UpdatedAt: ts(1_700_000_006, 0), Error: "nope"},
	}
	m.fleets["cohort-1"] = &Fleet{ID: "cohort-1", Profile: "crew", Owner: "team", Board: fleet.Load(tasks, time.Minute), Sandboxes: []string{"s1", "s2"}, Created: ts(1_700_000_000, 42)}
	m.fleets["cohort-2"] = &Fleet{ID: "cohort-2", Profile: "solo", Board: fleet.Load(nil, 0), Created: ts(1_700_000_010, 0)}
	if err := m.saveFleets(); err != nil {
		t.Fatal(err)
	}
	token, err := m.issueTaskLease("cohort-1", tasks[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "lease-token.txt"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}

	// snapshots.json
	m.snapshots["snap-1"] = backend.SnapshotRef{ID: "snap-1", Name: "before", Profile: "dev", Backend: "docker", Location: "/tmp/snapshots/snap-1.tar", Sha256: "abc123", Created: ts(1_700_000_300, 123_456_789)}
	m.snapshotOwners["snap-1"] = "team"
	m.snapshots["snap-2"] = backend.SnapshotRef{ID: "snap-2", Name: "x", Profile: "dev", Backend: "k8s", Location: "/tmp/snapshots/snap-2.tar", Created: ts(1_700_000_400, 100)}
	m.snapshotOwners["snap-2"] = ""
	if err := m.saveSnapshots(); err != nil {
		t.Fatal(err)
	}

	// agent-sessions.json and transcripts
	exit0, exit2 := 0, 2
	s1 := "0123456789abcdef0123456789abcdef"
	s2 := "fedcba9876543210fedcba9876543210"
	start1, end1 := ts(1_700_000_501, 5_000_000), ts(1_700_000_509, 0)
	m.agentSessions[s1] = &AgentSession{ID: s1, CitadelID: "c-a", Tenant: "team", Actor: "codex", Agent: "cursor", Model: "m", CohortID: "cohort-1", TaskID: "t-claimed", Command: []string{"agent", "-p", "fix <bug> & ship"}, Status: "running", CreatedAt: ts(1_700_000_500, 0), StartedAt: &start1}
	m.agentSessions[s2] = &AgentSession{ID: s2, CitadelID: "c-b", Status: "failed", ExitCode: &exit2, Error: "agent exited with status 2", CreatedAt: ts(1_700_000_600, 7), StartedAt: &start1, FinishedAt: &end1, TranscriptTruncated: true}
	m.appendAgentEvent(s1, "status", "running")
	m.appendAgentEvent(s1, "stdout", "héllo <world> & \"friends\"\n")
	m.appendAgentEvent(s1, "stderr", "warn line\n")
	m.appendAgentEvent(s1, "status", "completed")
	m.agentSessions[s1].Status = "completed"
	m.agentSessions[s1].ExitCode = &exit0
	m.agentSessions[s1].FinishedAt = &end1
	if err := m.saveAgentSessions(); err != nil {
		t.Fatal(err)
	}

	// ledger.jsonl
	p := &profile.Profile{Name: "dev"}
	guard, _ := policy.NewGuard(p.Limits)
	sess := &Session{Sandbox: &backend.Sandbox{ID: "c-a"}, Profile: p, Engine: policy.New(nil, profile.VerdictAllow), Guard: guard, Owner: "team", Actor: "codex", RunID: "run-a"}
	m.record(context.Background(), sess, "shell", "echo <hi>", []string{"echo", "<hi>"}, "allow", 0, 3, "")
	m.record(context.Background(), sess, "sandbox", "kill", nil, "allow", 0, 0, "")

	meta, _ := json.Marshal(map[string]any{"lease_cohort": "cohort-1", "lease_task": "t-claimed", "lease_actor": "w1", "lease_version": 3})
	if err := os.WriteFile(filepath.Join(out, "fixture-meta.json"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
}
