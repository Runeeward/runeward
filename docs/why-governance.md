# Why governance, not training

> How do you train an AI to follow compliance rules? How will it know it is
> about to — or already did — break one? We keep seeing agents delete production
> databases even after being told not to. Worse than a dropped database is a
> breach caused by an agent that skipped a security control because the person
> prompting it forgot to ask for it.

Rune Box's answer is a reframing: **you don't make the model trustworthy — you
make its environment enforce the rules.** Put the rules *outside* the agent, in
a deterministic layer it cannot prompt, reason, or apologize its way past.

## The problem with "train it to comply"

Training and prompting are *soft* controls. They are probabilistic, they can be
talked around, and they fail exactly when it matters — under an unusual prompt,
a jailbreak, or a confident wrong plan. Both approaches are also **allow-by-default**:
anything the instructions didn't forbid is implicitly permitted, so safety
depends on a human remembering to forbid every dangerous thing in advance.

That is why "we told it not to drop the database" is not a control, and why the
*forgotten* control is the scariest case: nobody prompted for it, so nothing
stopped it.

## Rune Box's model: mediate every action against a contract

The agent can only touch the world — shell, files, network, code execution —
through Rune Box's governed path. That path is driven by a **Charter**: a
declarative security contract, authored once by whoever owns security, enforced
on every action, and **deny-by-default**.

So "how does the agent know it is breaking compliance?" becomes moot. It does
not need to know. The enforcement layer knows, and refuses. The agent's
cooperation is never part of the security model.

## Will do / is doing / has done

The three phases in the question map directly onto three Rune Box mechanisms:

| Phase | Question | Rune Box mechanism |
| --- | --- | --- |
| **Will do** | Is this action allowed? | The policy engine renders `allow` / `deny` / `require-approval` **before** the action executes — regardless of what the agent was told. |
| **Is doing** | Is it going out of bounds mid-task? | Deny-by-default egress (only allowlisted hosts are reachable) plus guardrails: wall-clock, exec-count, egress-request caps, and retry-loop detection. |
| **Has done** | What actually happened? | A hash-chained, ed25519-signed, append-only audit ledger — independently verifiable and exportable as evidence. |

### "Will do": the policy gate

Deleting a production database is not blocked because the agent remembered the
instruction. It is blocked because a rule denies it, and the rule runs before
the command does:

```toml
[[policy]]
tool    = "shell"
match   = "*drop database*"
verdict = "deny"
reason  = "production data is off-limits to agents"

[[policy]]
tool    = "shell"
match   = "terraform apply*"
verdict = "require-approval"   # pauses for a human to approve, in-band
```

### "Is doing": egress and guardrails

Even mid-task, the agent can only reach hosts you allowlisted, so it cannot
exfiltrate to an unlisted destination. Cost and loop guardrails stop runaway or
looping behavior before it burns budget or does damage.

### "Has done": the tamper-evident ledger

Every action and its verdict is recorded and signed. You can verify the chain
offline and hand the export to an incident review or an auditor as proof a
control was in force.

## The forgotten control — where this matters most

This is the strongest argument for governance over training. "Prompt carefully"
and "train it to be safe" are both allow-by-default, so a control the operator
*forgot to ask for* is simply absent.

Rune Box inverts the default. The contract is **deny-by-default** and authored
once by the security owner — not re-derived from each prompt. The person driving
the agent can forget to ask for a control; they cannot accidentally *grant* one
the Charter never granted. The blast radius is exactly what the Charter allows,
and omissions fail safe.

> Rune Box doesn't ask the agent to remember the rules. It makes the rules a
> property of the environment the agent runs in — deny-by-default, enforced
> before every action, and recorded in a signed audit trail. Security stops
> depending on the model's judgment or the operator's memory.

## Compliance & evidence

A control is only useful to an auditor if you can *prove* it was in force. The
ledger is designed to be that proof: it is append-only, hash-chained, and
ed25519-signed, and it exports as a self-contained bundle that embeds the public
key so anyone can verify it **offline** — no access to your running control
plane required.

```bash
# Export the signed transcript from a running control plane
curl -s localhost:8080/v1/chronicle/export > transcript.json

# Verify the chain + signatures offline (e.g. on an auditor's machine)
runeward chronicle verify transcript.json
# ok: 128 events verified (hash chain + signatures intact)
```

You can also verify a live instance and scope a transcript to a single Citadel:

```bash
curl -s localhost:8080/v1/chronicle/verify          # verify the live ledger
curl -s localhost:8080/v1/citadels/$SB/chronicle    # one Citadel's events + verdicts
```

The mapping to a control framework is then concrete: the **Charter is the
documented control** (deny-by-default egress, per-action policy, approval gates,
guardrails), and the **verified transcript is the evidence** that every action
was evaluated against it. If a record were altered or dropped, verification
fails — silent tampering is not possible without breaking the chain.

## Identity vs execution governance

Rune Box answers one half of "can this agent do this?": **execution
governance** — what an agent may do when it runs *inside your trust boundary*,
enforced at the moment it acts, and recorded. The other half is **identity and
authorization** — *who* an agent is and whether it may reach a given resource
*across* organizational boundaries. That half belongs to identity systems and
protocols: OAuth/OIDC for user login, SPIFFE/WIMSE for workload identity inside
an enterprise, and emerging agent-identity efforts like
[AAuth](https://github.com/dickhardt/AAuth) that give each agent its own
key-bound, verifiable identity with no shared secrets.

The two are complementary, not competing, because they enforce at different
points:

| | Identity / authorization (AAuth, SPIFFE, OAuth) | Rune Box (execution governance) |
| --- | --- | --- |
| Question | Who is this agent, and may it reach that resource? | What may it do when it executes here, and what happened? |
| Where | At the edge, across trust domains | Inside the Citadel you control |
| When | Before the request leaves | At tool-execution time — physically able to block |

They compose well: an agent can carry a cryptographic identity for its outbound
calls *while* Rune Box isolates, gates, and audits everything it executes
locally — defense in depth (Rune Box's egress allowlist plus a key-bound caller
identity). It also names an honest gap. Rune Box today authenticates its own API
with bearer tokens and *injects* outbound secrets into the Citadel — exactly the
copyable-secret model that key-bound agent identity is designed to replace.
Adopting proof-of-possession identity for the API and for the Citadel's outbound
calls is tracked in the
[roadmap](https://github.com/Runewardd/runeward/blob/main/ROADMAP.md).

## Honest boundaries

Governance is defense-in-depth, not magic. Being precise about the limits is
what makes the claim credible:

- Rune Box governs **mediated actions** — what the agent does *through* its
  Citadel, tools, egress, and file ops. It is not model alignment and cannot
  police reasoning, nor an action it never mediates (e.g. an agent handed live
  production credentials and a network path you explicitly allowlisted).
- It is a **control plane**: someone still authors the contract and staffs the
  approvals inbox. Rune Box's job is to make that contract unbypassable and
  auditable, and to make the default *deny* so omissions are safe.
- For compliance frameworks, this shows up as **policy-as-code + audit
  evidence**: the Charter is the documented control, the Chronicle is proof it
  ran. Rune Box provides the mechanism and the evidence; it does not certify you.

See the [Security model](security-model.md) for exactly what is and isn't in
scope, and [Charters](profiles.md) to write your own contract.
