//! Charter subsumption: a conservative proof that a child Charter grants no
//! more power than its parent's.
//!
//! A delegated child, a fork or any other derived agent may run under a
//! different Charter than the one it was derived from only when that
//! Charter is *provably no broader*. [`check_subsumption`] decides this
//! dimension by dimension and is deliberately one-sided: it may refuse a
//! child that is in fact narrower (when containment cannot be decided
//! cheaply), but it never accepts a broader one. A refusal names the
//! dimension and the rule that could not be proven, so an operator can fix
//! the child Charter.
//!
//! What "no broader" means per dimension:
//!
//! - **Authority policy** (`[[policy]]`, `policy_default`): for *every*
//!   action, the child's verdict ranks at or below the parent's
//!   (deny < require-approval < allow). The built-in first-match-wins rules
//!   are compared exactly over a finite partition of the action space: tool
//!   names, every byte-string argument (a product automaton over all `match`
//!   globs) and every combination of `match_argv` outcomes (treated as
//!   independent, which over-approximates the real actions). Rule order is
//!   honoured, so a child allow that shadows a parent deny is caught and a
//!   child deny the parent lacked is fine. CEL, Rego and policy bundles are
//!   only accepted when their configuration is identical (bundles pinned by
//!   digest, Rego inline), when the child's rules deny everything, or when
//!   the parent's rules allow everything.
//! - **Network** (`[network]`, `[[endpoint]]`, `[[credential]]`): every
//!   hostname and IP the child's egress gate admits, the parent's admits;
//!   strict enforcement is kept; an endpoint the parent inspects is
//!   inspected at least as tightly in the child (same protocol, mode,
//!   credential, binaries, budgets, the parent's deny rules, and a prefix
//!   of its ordered allow rules); every child credential is one of the
//!   parent's.
//! - **Containment**: isolation floor, host type, image, user, entrypoint,
//!   OCI runtime, seccomp/AppArmor and `copy_from` are unchanged, the root
//!   stays read-only, `[filesystem]` grants are beneath the parent's and
//!   Landlock is no weaker, `[process]` identity is unchanged.
//! - **Capabilities**: persistent workspace, self-service schedules and the
//!   browser IDE only when the parent has them.
//! - **Rationing**: every cap the parent sets is set in the child and no
//!   higher; loop detection is at least as sensitive.
//! - **Secrets and evidence**: every `[[env]]` and `[[file]]` entry is one of
//!   the parent's; the Chronicle sink is unchanged, redaction is not
//!   disabled and every parent scrub pattern is kept.
//!
//! Not compared because they grant no authority: the Charter's name and
//! source, `prompt`, `capabilities` (image discovery), `packages` (installed
//! only by `--provision`), `[cohort]`, `host.workdir` (except as a
//! filesystem grant) and the workspace idle timeout.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::IpAddr;

use runeward_charter::{
    Charter, Endpoint, IsolationLevel, NetworkRule, PolicyRule, RequestRule, Verdict,
    parse_go_duration,
};

use crate::build::no_match_verdict;

/// Largest product automaton explored for one tool's `match` globs before
/// the proof gives up (and refuses).
pub const MAX_GLOB_STATES: usize = 50_000;
/// Most distinct `match_argv` globs per tool the proof enumerates.
pub const MAX_ARGV_GLOBS: usize = 10;

/// A child Charter could not be proven no broader than its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The Charter dimension (`policy`, `network`, `filesystem`, ...).
    pub dimension: &'static str,
    /// What the child grants (or may grant) beyond the parent, naming the
    /// rule involved.
    pub reason: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.dimension, self.reason)
    }
}

impl std::error::Error for Refusal {}

fn refuse<T>(dimension: &'static str, reason: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        dimension,
        reason: reason.into(),
    })
}

/// How a child Charter was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// The child's Charter is the parent's (same name, same content).
    Exact,
    /// A different Charter, proven no broader dimension by dimension.
    Subsumed(Vec<(&'static str, String)>),
}

impl Proof {
    /// `exact` or `subsumed`.
    pub fn method(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Subsumed(_) => "subsumed",
        }
    }

    /// A one-line account of what was proven, for the Chronicle.
    pub fn summary(&self) -> String {
        match self {
            Self::Exact => "identical charter".into(),
            Self::Subsumed(steps) => steps
                .iter()
                .map(|(d, note)| format!("{d}: {note}"))
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

/// Whether two Charters are the same contract: equal in everything but
/// their name, source path and discovered `capabilities`.
pub fn charters_equivalent(a: &Charter, b: &Charter) -> bool {
    let strip = |c: &Charter| Charter {
        name: String::new(),
        source: Default::default(),
        capabilities: Vec::new(),
        ..c.clone()
    };
    strip(a) == strip(b)
}

/// Proves that `child` grants no more than `parent` (see the module docs),
/// or explains which dimension and rule could not be proven.
///
/// `operator_default` is the control plane's `RUNEWARD_POLICY_DEFAULT`,
/// which decides the no-match verdict of a Charter without
/// `policy_default`. Same name and equivalent content is the exact fast
/// path.
pub fn check_subsumption(
    parent: &Charter,
    child: &Charter,
    operator_default: Option<&str>,
) -> Result<Proof, Refusal> {
    if parent.name == child.name && charters_equivalent(parent, child) {
        return Ok(Proof::Exact);
    }
    let steps = vec![
        ("policy", check_policy(parent, child, operator_default)?),
        ("network", check_network(parent, child)?),
        ("isolation", check_isolation(parent, child)?),
        ("host", check_host(parent, child)?),
        ("filesystem", check_filesystem(parent, child)?),
        ("process", check_process(parent, child)?),
        ("features", check_features(parent, child)?),
        ("rationing", check_rationing(parent, child)?),
        ("secrets", check_secrets(parent, child)?),
        ("chronicle", check_chronicle(parent, child)?),
    ];
    Ok(Proof::Subsumed(steps))
}

// ---------------------------------------------------------------------------
// Authority policy
// ---------------------------------------------------------------------------

/// deny (and anything unrecognised, which fails closed) < require-approval
/// < allow.
fn rank(v: &Verdict) -> u8 {
    match v {
        Verdict::Allow => 2,
        Verdict::RequireApproval => 1,
        _ => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineKind {
    Builtin,
    Cel,
    Rego,
    Bundle,
}

fn engine_kind(c: &Charter) -> EngineKind {
    if c.uses_policy_bundle() {
        EngineKind::Bundle
    } else if c.uses_rego() {
        EngineKind::Rego
    } else if c.uses_cel() {
        EngineKind::Cel
    } else {
        EngineKind::Builtin
    }
}

fn describe_rule(i: usize, r: &PolicyRule) -> String {
    let mut s = format!("policy[{i}] (tool {:?}", r.tool);
    if !r.match_glob.is_empty() {
        s.push_str(&format!(", match {:?}", r.match_glob));
    }
    if !r.match_argv.is_empty() {
        s.push_str(&format!(", match_argv {:?}", r.match_argv));
    }
    s.push_str(&format!(", {})", verdict_name(&r.verdict)));
    s
}

fn verdict_name(v: &Verdict) -> String {
    match v {
        Verdict::Unset => "unset (fails closed to deny)".into(),
        other => other.as_str().to_owned(),
    }
}

fn check_policy(
    p: &Charter,
    c: &Charter,
    operator_default: Option<&str>,
) -> Result<String, Refusal> {
    let dp = no_match_verdict(Some(p), operator_default);
    let dc = no_match_verdict(Some(c), operator_default);
    let (kp, kc) = (engine_kind(p), engine_kind(c));
    if kp == EngineKind::Builtin && kc == EngineKind::Builtin {
        return compare_rules(&p.policy, &dp, &c.policy, &dc);
    }
    if kp == kc {
        same_engine(p, c, kp)?;
        if rank(&dc) > rank(&dp) {
            return refuse(
                "policy",
                format!(
                    "the child's no-match verdict ({}) is broader than the parent's ({})",
                    dc.as_str(),
                    dp.as_str()
                ),
            );
        }
        return Ok(format!("identical {} engine", engine_name(kp)));
    }
    if kc == EngineKind::Builtin && extreme_verdict(&c.policy, &dc, true)? == 0 {
        return Ok(format!(
            "child denies every action (parent uses {})",
            engine_name(kp)
        ));
    }
    if kp == EngineKind::Builtin && extreme_verdict(&p.policy, &dp, false)? == 2 {
        return Ok(format!(
            "parent allows every action (child uses {})",
            engine_name(kc)
        ));
    }
    refuse(
        "policy",
        format!(
            "cannot compare a {} policy with a {} policy; use the parent's policy engine and configuration",
            engine_name(kc),
            engine_name(kp)
        ),
    )
}

fn engine_name(k: EngineKind) -> &'static str {
    match k {
        EngineKind::Builtin => "built-in rules",
        EngineKind::Cel => "CEL",
        EngineKind::Rego => "Rego",
        EngineKind::Bundle => "policy bundle",
    }
}

/// Non-builtin engines are compared by configuration only, and only when
/// the configuration pins the policy text.
fn same_engine(p: &Charter, c: &Charter, kind: EngineKind) -> Result<(), Refusal> {
    match kind {
        EngineKind::Cel => {
            if p.cel != c.cel {
                return refuse(
                    "policy",
                    "the child's CEL rules differ from the parent's; CEL containment is not decided, so they must be identical",
                );
            }
        }
        EngineKind::Rego => {
            if p.rego != c.rego {
                return refuse(
                    "policy",
                    "the child's Rego policy differs from the parent's; Rego containment is not decided, so it must be identical",
                );
            }
            if c.rego.module.is_empty() {
                return refuse(
                    "policy",
                    format!(
                        "rego.file {:?} may have changed since the parent started; inline the module to prove it identical",
                        c.rego.file
                    ),
                );
            }
        }
        EngineKind::Bundle => {
            if p.policy_bundle != c.policy_bundle {
                return refuse(
                    "policy",
                    "the child's policy bundle differs from the parent's",
                );
            }
            let r = c
                .policy_bundle
                .as_ref()
                .map(|b| b.r#ref.as_str())
                .unwrap_or_default();
            if !r.contains("@sha256:") {
                return refuse(
                    "policy",
                    format!(
                        "policy bundle {r:?} is not pinned by digest, so it may have moved since the parent started"
                    ),
                );
            }
        }
        EngineKind::Builtin => {}
    }
    Ok(())
}

/// One rule list and its no-match verdict.
struct RuleSet<'a> {
    rules: &'a [PolicyRule],
    default: &'a Verdict,
}

impl RuleSet<'_> {
    /// The deciding rule (or `None` for the default) and its verdict in a
    /// cell.
    fn eval(&self, cell: &Cell<'_>) -> (Option<usize>, Verdict) {
        for (i, r) in self.rules.iter().enumerate() {
            if !cell.tool_applies(&r.tool) {
                continue;
            }
            let arg_ok = r.match_glob.is_empty() || cell.glob_true(&r.match_glob);
            let argv_ok = r.match_argv.is_empty() || cell.argv_true(&r.match_argv);
            if arg_ok && argv_ok {
                return (Some(i), r.verdict.clone());
            }
        }
        (None, self.default.clone())
    }
}

/// One equivalence class of actions: a tool class, which `match` globs the
/// argument satisfies, and which `match_argv` globs some argv candidate
/// satisfies.
struct Cell<'a> {
    /// `Some(name)` for a named tool, `None` for every other tool.
    tool: Option<&'a str>,
    tool_witness: &'a str,
    globs: &'a [String],
    glob_vec: &'a [bool],
    arg_witness: &'a str,
    atoms: &'a [String],
    atom_mask: u32,
}

impl Cell<'_> {
    fn tool_applies(&self, rule_tool: &str) -> bool {
        rule_tool == "*" || self.tool == Some(rule_tool)
    }

    fn glob_true(&self, g: &str) -> bool {
        self.globs
            .iter()
            .position(|x| x == g)
            .is_some_and(|i| self.glob_vec[i])
    }

    fn argv_true(&self, g: &str) -> bool {
        self.atoms
            .iter()
            .position(|x| x == g)
            .is_some_and(|i| self.atom_mask & (1 << i) != 0)
    }

    fn describe(&self) -> String {
        let mut s = format!("{} {:?}", self.tool_witness, self.arg_witness);
        let argv: Vec<&str> = self
            .atoms
            .iter()
            .enumerate()
            .filter(|(i, _)| self.atom_mask & (1 << i) != 0)
            .map(|(_, a)| a.as_str())
            .collect();
        if !argv.is_empty() {
            s.push_str(&format!(" with an executable matching {argv:?}"));
        }
        s
    }
}

/// Visits every action cell for the given rule lists; `visit` returns
/// `Err` to stop.
fn for_each_cell<F>(sets: &[&[PolicyRule]], mut visit: F) -> Result<usize, Refusal>
where
    F: FnMut(&Cell<'_>) -> Result<(), Refusal>,
{
    let named: BTreeSet<&str> = sets
        .iter()
        .flat_map(|rs| rs.iter())
        .map(|r| r.tool.as_str())
        .filter(|t| *t != "*")
        .collect();
    let mut other = String::from("unlisted-tool");
    while named.contains(other.as_str()) {
        other.push('_');
    }
    let mut classes: Vec<Option<&str>> = named.iter().map(|t| Some(*t)).collect();
    classes.push(None);
    let mut cells = 0usize;
    for class in classes {
        let applies = |r: &&PolicyRule| r.tool == "*" || Some(r.tool.as_str()) == class;
        let globs: Vec<String> = sets
            .iter()
            .flat_map(|rs| rs.iter())
            .filter(applies)
            .map(|r| r.match_glob.clone())
            .filter(|g| !g.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let atoms: Vec<String> = sets
            .iter()
            .flat_map(|rs| rs.iter())
            .filter(applies)
            .map(|r| r.match_argv.clone())
            .filter(|g| !g.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let tool_witness = class.unwrap_or(other.as_str());
        if atoms.len() > MAX_ARGV_GLOBS {
            return refuse(
                "policy",
                format!(
                    "tool {tool_witness:?} has {} distinct match_argv globs; at most {MAX_ARGV_GLOBS} can be compared",
                    atoms.len()
                ),
            );
        }
        let vectors = glob_cells(&globs).map_err(|()| Refusal {
            dimension: "policy",
            reason: format!(
                "the match globs for tool {tool_witness:?} are too complex to compare (over {MAX_GLOB_STATES} automaton states)"
            ),
        })?;
        for (vec, witness) in &vectors {
            for mask in 0..(1u32 << atoms.len()) {
                cells += 1;
                visit(&Cell {
                    tool: class,
                    tool_witness,
                    globs: &globs,
                    glob_vec: vec,
                    arg_witness: witness,
                    atoms: &atoms,
                    atom_mask: mask,
                })?;
            }
        }
    }
    Ok(cells)
}

fn compare_rules(
    pr: &[PolicyRule],
    dp: &Verdict,
    cr: &[PolicyRule],
    dc: &Verdict,
) -> Result<String, Refusal> {
    let parent = RuleSet {
        rules: pr,
        default: dp,
    };
    let child = RuleSet {
        rules: cr,
        default: dc,
    };
    let cells = for_each_cell(&[pr, cr], |cell| {
        let (ci, cv) = child.eval(cell);
        let (pi, pv) = parent.eval(cell);
        if rank(&cv) <= rank(&pv) {
            return Ok(());
        }
        let by_child = match ci {
            Some(i) => format!("child {}", describe_rule(i, &cr[i])),
            None => format!("the child's no-match default ({})", dc.as_str()),
        };
        let by_parent = match pi {
            Some(i) => format!("the parent's {}", describe_rule(i, &pr[i])),
            None => "the parent's no-match default".to_owned(),
        };
        refuse(
            "policy",
            format!(
                "{by_child} yields {} for an action like {}, where {by_parent} yields {}",
                verdict_name(&cv),
                cell.describe(),
                verdict_name(&pv)
            ),
        )
    })?;
    Ok(format!(
        "built-in rules compared over {cells} action classes"
    ))
}

/// The highest (`max`) or lowest verdict rank a rule list can produce.
fn extreme_verdict(rules: &[PolicyRule], def: &Verdict, max: bool) -> Result<u8, Refusal> {
    let set = RuleSet {
        rules,
        default: def,
    };
    let mut out = if max { 0 } else { 2 };
    for_each_cell(&[rules], |cell| {
        let r = rank(&set.eval(cell).1);
        out = if max { out.max(r) } else { out.min(r) };
        Ok(())
    })?;
    Ok(out)
}

/// A `match` glob as an NFA: states `0..=len`, `*` loops and may be
/// skipped, `?` and literals consume one byte. Mirrors
/// [`crate::match_glob`] (byte-wise, `*` and `?` cross `/`).
struct GlobNfa {
    p: Vec<u8>,
}

impl GlobNfa {
    fn words(&self) -> usize {
        (self.p.len() + 1).div_ceil(64)
    }

    fn set(bits: &mut [u64], i: usize) {
        bits[i / 64] |= 1 << (i % 64);
    }

    fn has(bits: &[u64], i: usize) -> bool {
        bits[i / 64] & (1 << (i % 64)) != 0
    }

    fn close(&self, bits: &mut [u64]) {
        for i in 0..self.p.len() {
            if Self::has(bits, i) && self.p[i] == b'*' {
                Self::set(bits, i + 1);
            }
        }
    }

    fn start(&self) -> Vec<u64> {
        let mut b = vec![0; self.words()];
        Self::set(&mut b, 0);
        self.close(&mut b);
        b
    }

    /// One step on a byte class: `Some(b)` a literal byte, `None` any byte
    /// no glob mentions literally.
    fn step(&self, from: &[u64], byte: Option<u8>) -> Vec<u64> {
        let mut b = vec![0; self.words()];
        for i in 0..self.p.len() {
            if !Self::has(from, i) {
                continue;
            }
            match self.p[i] {
                b'*' => Self::set(&mut b, i),
                b'?' => Self::set(&mut b, i + 1),
                c if Some(c) == byte => Self::set(&mut b, i + 1),
                _ => {}
            }
        }
        self.close(&mut b);
        b
    }

    fn accepts(&self, bits: &[u64]) -> bool {
        Self::has(bits, self.p.len())
    }
}

/// Every reachable combination of glob outcomes over all byte strings,
/// each with a shortest witness string. `Err` when the product automaton
/// exceeds [`MAX_GLOB_STATES`].
fn glob_cells(globs: &[String]) -> Result<Vec<(Vec<bool>, String)>, ()> {
    let nfas: Vec<GlobNfa> = globs
        .iter()
        .map(|g| GlobNfa {
            p: g.as_bytes().to_vec(),
        })
        .collect();
    let literals: BTreeSet<u8> = globs
        .iter()
        .flat_map(|g| g.bytes())
        .filter(|b| *b != b'*' && *b != b'?')
        .collect();
    let other = b"xyzqjkvwXYZ0123456789_-."
        .iter()
        .copied()
        .chain(1u8..=255)
        .find(|b| !literals.contains(b));
    let mut alphabet: Vec<Option<u8>> = literals.iter().map(|b| Some(*b)).collect();
    if other.is_some() {
        alphabet.push(None);
    }
    let start: Vec<Vec<u64>> = nfas.iter().map(GlobNfa::start).collect();
    let mut seen: HashSet<Vec<Vec<u64>>> = HashSet::new();
    let mut out: HashMap<Vec<bool>, Vec<u8>> = HashMap::new();
    let mut queue = VecDeque::new();
    seen.insert(start.clone());
    queue.push_back((start, Vec::new()));
    while let Some((state, witness)) = queue.pop_front() {
        let vec: Vec<bool> = nfas.iter().zip(&state).map(|(n, s)| n.accepts(s)).collect();
        out.entry(vec).or_insert_with(|| witness.clone());
        for sym in &alphabet {
            let next: Vec<Vec<u64>> = nfas
                .iter()
                .zip(&state)
                .map(|(n, s)| n.step(s, *sym))
                .collect();
            if seen.contains(&next) {
                continue;
            }
            if seen.len() >= MAX_GLOB_STATES {
                return Err(());
            }
            seen.insert(next.clone());
            let mut w = witness.clone();
            w.push(sym.or(other).unwrap_or(b'x'));
            queue.push_back((next, w));
        }
    }
    let mut cells: Vec<(Vec<bool>, String)> = out
        .into_iter()
        .map(|(v, w)| (v, String::from_utf8_lossy(&w).into_owned()))
        .collect();
    cells.sort();
    Ok(cells)
}

// ---------------------------------------------------------------------------
// Network: egress gate, endpoints and credentials
// ---------------------------------------------------------------------------

fn has_broker(c: &Charter) -> bool {
    !c.endpoints.is_empty() || !c.credentials.is_empty()
}

/// Whether the sandbox's traffic goes through the egress gate at all; an
/// unproxied network is fully open.
fn proxied(c: &Charter) -> bool {
    c.network.deny_by_default() || has_broker(c)
}

/// The egress policy's verdict test: only `allow` (any case) permits, and
/// an unset rule verdict means allow.
fn rule_allows(r: &NetworkRule) -> bool {
    r.verdict.is_empty() || r.verdict.trim().eq_ignore_ascii_case("allow")
}

fn default_allows(c: &Charter) -> bool {
    let d = c.network.default.trim();
    d.is_empty() || d.eq_ignore_ascii_case("allow")
}

fn norm_host(h: &str) -> String {
    h.trim().to_lowercase()
}

/// The egress gate's hostname matcher: exact, or `*.suffix` for any
/// subdomain (never the bare domain).
fn hostname_matches(pattern: &str, host: &str) -> bool {
    let pattern = norm_host(pattern);
    let host = norm_host(host);
    if pattern.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.ends_with(&format!(".{suffix}")) && host.len() > suffix.len() + 1;
    }
    pattern == host
}

/// The first hostname rule's verdict for `host`, with its index.
fn first_hostname(c: &Charter, host: &str) -> Option<(usize, bool)> {
    c.network
        .rules
        .iter()
        .enumerate()
        .filter(|(_, r)| !r.hostname.is_empty())
        .find(|(_, r)| hostname_matches(&r.hostname, host))
        .map(|(i, r)| (i, rule_allows(r)))
}

fn ep_port(e: &Endpoint) -> u16 {
    if e.port == 0 { 443 } else { e.port }
}

fn first_endpoint<'a>(c: &'a Charter, host: &str, port: u16) -> Option<(usize, &'a Endpoint)> {
    if !has_broker(c) {
        return None;
    }
    c.endpoints
        .iter()
        .enumerate()
        .find(|(_, e)| ep_port(e) == port && hostname_matches(&e.host, host))
}

/// The gate's decision for a hostname destination: a broker endpoint is
/// reachable unless a hostname rule denies it; anything else must be
/// explicitly allowlisted.
fn host_allowed(c: &Charter, host: &str, port: u16) -> bool {
    let first = first_hostname(c, host).map(|(_, v)| v);
    if first_endpoint(c, host, port).is_some() {
        first != Some(false)
    } else {
        first == Some(true)
    }
}

/// Whether a hostname pattern could match the text of an IP literal, which
/// the IP analysis below does not model.
fn ip_capable(pattern: &str) -> bool {
    let p = norm_host(pattern);
    if let Some(suffix) = p.strip_prefix("*.") {
        return !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    }
    p.parse::<IpAddr>().is_ok() || p.contains(':')
}

fn describe_net_rule(i: usize, r: &NetworkRule) -> String {
    let target = if r.hostname.is_empty() {
        format!("cidr {:?}", r.cidr)
    } else {
        format!("hostname {:?}", r.hostname)
    };
    format!(
        "network.rule[{i}] ({target}, {})",
        if rule_allows(r) { "allow" } else { "deny" }
    )
}

fn check_network(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    check_credentials(p, c)?;
    if !proxied(p) {
        return Ok("parent egress is unrestricted".into());
    }
    if !proxied(c) {
        return refuse(
            "network",
            "the child's egress is unrestricted (no default = \"deny\" and no endpoints) but the parent's goes through the egress gate",
        );
    }
    if p.network.strict_egress() && !c.network.strict_egress() {
        return refuse(
            "network",
            "the parent enforces egress strictly (enforce = \"strict\") but the child does not",
        );
    }
    if p.network.default == c.network.default
        && p.network.rules == c.network.rules
        && p.endpoints == c.endpoints
    {
        return Ok("identical egress rules and endpoints".into());
    }
    let patterns: Vec<String> = [p, c]
        .iter()
        .flat_map(|x| {
            x.network
                .rules
                .iter()
                .map(|r| r.hostname.as_str())
                .chain(x.endpoints.iter().map(|e| e.host.as_str()))
        })
        .map(norm_host)
        .filter(|h| !h.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if let Some(ipish) = patterns.iter().find(|h| ip_capable(h)) {
        return refuse(
            "network",
            format!(
                "hostname or endpoint {ipish:?} can match IP literals, which are only compared when the egress rules and endpoints are identical"
            ),
        );
    }
    let hosts = check_hostnames(p, c, &patterns)?;
    let ips = check_ip_cells(p, c)?;
    Ok(format!(
        "{hosts} hostname/port classes and {ips} IP ranges admitted no wider"
    ))
}

fn check_credentials(p: &Charter, c: &Charter) -> Result<(), Refusal> {
    for cred in &c.credentials {
        match p.credentials.iter().find(|x| x.name == cred.name) {
            Some(pc) if pc == cred => {}
            Some(_) => {
                return refuse(
                    "network",
                    format!(
                        "credential {:?} differs from the parent's credential of that name",
                        cred.name
                    ),
                );
            }
            None => {
                return refuse(
                    "network",
                    format!("credential {:?} is not one of the parent's", cred.name),
                );
            }
        }
    }
    Ok(())
}

/// Representative hostnames: every exact pattern, a fresh subdomain of
/// every wildcard, and a host no pattern matches. Every hostname matches
/// exactly the same patterns as one of these.
fn host_representatives(patterns: &[String]) -> Vec<String> {
    let mut fresh = String::from("rw-probe");
    while patterns.iter().any(|p| p.contains(fresh.as_str())) {
        fresh.push('x');
    }
    let mut reps: BTreeSet<String> = BTreeSet::new();
    for p in patterns {
        match p.strip_prefix("*.") {
            Some(suffix) => reps.insert(format!("{fresh}.{suffix}")),
            None => reps.insert(p.clone()),
        };
    }
    reps.insert(format!("{fresh}.invalid"));
    reps.into_iter().collect()
}

fn check_hostnames(p: &Charter, c: &Charter, patterns: &[String]) -> Result<usize, Refusal> {
    let mut ports: BTreeSet<u16> = p
        .endpoints
        .iter()
        .chain(&c.endpoints)
        .map(ep_port)
        .collect();
    let other = (1..=u16::MAX).find(|x| !ports.contains(x)).unwrap_or(1);
    ports.insert(other);
    let mut classes = 0;
    for host in host_representatives(patterns) {
        for &port in &ports {
            classes += 1;
            if !host_allowed(c, &host, port) {
                continue;
            }
            let pe = first_endpoint(p, &host, port);
            if !host_allowed(p, &host, port) {
                let why = match first_hostname(p, &host) {
                    Some((i, _)) => {
                        format!("the parent's {}", describe_net_rule(i, &p.network.rules[i]))
                    }
                    None => "the parent's allowlist".into(),
                };
                let how = match (first_hostname(c, &host), first_endpoint(c, &host, port)) {
                    (_, Some((i, _))) => format!("child endpoint[{i}]"),
                    (Some((i, _)), None) => {
                        format!("child {}", describe_net_rule(i, &c.network.rules[i]))
                    }
                    (None, None) => "the child".into(),
                };
                return refuse(
                    "network",
                    format!("{how} admits {host}:{port}, which {why} refuses"),
                );
            }
            let ce = first_endpoint(c, &host, port);
            match (ce, pe) {
                (Some((ci, ce)), Some((pi, pe))) => endpoint_subsumed(ce, pe).map_err(|why| Refusal {
                    dimension: "network",
                    reason: format!(
                        "child endpoint[{ci}] ({:?}) is broader than the parent's endpoint[{pi}] ({:?}) for {host}:{port}: {why}",
                        ce.name, pe.name
                    ),
                })?,
                (None, Some((pi, pe))) if !endpoint_unrestricted(pe) => {
                    return refuse(
                        "network",
                        format!(
                            "the child reaches {host}:{port} without the request rules, binaries, budget or credential of the parent's endpoint[{pi}] ({:?})",
                            pe.name
                        ),
                    );
                }
                (Some((ci, ce)), None) if !ce.credential.is_empty() => {
                    return refuse(
                        "network",
                        format!(
                            "child endpoint[{ci}] ({:?}) injects credential {:?} into {host}:{port}, where the parent injects none",
                            ce.name, ce.credential
                        ),
                    );
                }
                _ => {}
            }
        }
    }
    Ok(classes)
}

fn protocol(e: &Endpoint) -> &str {
    if e.protocol.is_empty() {
        "tcp"
    } else {
        e.protocol.as_str()
    }
}

fn audit_mode(e: &Endpoint) -> bool {
    e.mode == "audit"
}

/// An endpoint with nothing to enforce behaves like a plain allowlisted
/// host.
fn endpoint_unrestricted(e: &Endpoint) -> bool {
    protocol(e) == "tcp" && e.binaries.is_empty() && e.max_calls == 0 && e.credential.is_empty()
}

fn effect_rank(effect: &str) -> u8 {
    match effect {
        "read" => 0,
        "write" => 1,
        // Untagged counts as irreversible.
        _ => 2,
    }
}

fn same_matcher(a: &RequestRule, b: &RequestRule) -> bool {
    a.method == b.method && a.path == b.path && a.tool == b.tool
}

/// Within budget: unlimited only when the parent is unlimited.
fn budget_within(child: u64, parent: u64) -> bool {
    parent == 0 || (child > 0 && child <= parent)
}

fn endpoint_subsumed(c: &Endpoint, p: &Endpoint) -> Result<(), String> {
    if protocol(c) != protocol(p) {
        return Err(format!(
            "protocol {:?} differs from the parent's {:?}",
            protocol(c),
            protocol(p)
        ));
    }
    if audit_mode(c) && !audit_mode(p) {
        return Err("audit mode only records what the parent enforces".into());
    }
    if c.credential != p.credential && !c.credential.is_empty() {
        return Err(format!(
            "injects credential {:?} where the parent injects {:?}",
            c.credential, p.credential
        ));
    }
    if !p.binaries.is_empty() {
        if c.binaries.is_empty() {
            return Err("allows any binary where the parent lists binaries".into());
        }
        if let Some(b) = c.binaries.iter().find(|b| !p.binaries.contains(b)) {
            return Err(format!("allows binary {b:?} the parent does not"));
        }
    }
    if !budget_within(c.max_calls, p.max_calls) {
        return Err(format!(
            "max_calls {} exceeds the parent's {}",
            c.max_calls, p.max_calls
        ));
    }
    if !c.health_path.is_empty() && c.health_path != p.health_path {
        return Err(format!("adds health_path {:?}", c.health_path));
    }
    if let Some((i, d)) = p
        .deny
        .iter()
        .enumerate()
        .find(|(_, d)| !c.deny.iter().any(|x| same_matcher(x, d)))
    {
        return Err(format!(
            "drops the parent's deny[{i}] (method {:?}, path {:?}, tool {:?})",
            d.method, d.path, d.tool
        ));
    }
    if p.allow.is_empty() {
        return Ok(());
    }
    if c.allow.is_empty() {
        return Err(
            "has no allow rules (allowing every request) where the parent lists some".into(),
        );
    }
    if c.allow.len() > p.allow.len() {
        return Err(format!(
            "has {} allow rules; only a prefix of the parent's {} ordered allow rules is provably no broader",
            c.allow.len(),
            p.allow.len()
        ));
    }
    for (i, (ca, pa)) in c.allow.iter().zip(&p.allow).enumerate() {
        if !same_matcher(ca, pa) {
            return Err(format!(
                "allow[{i}] (method {:?}, path {:?}, tool {:?}) is not the parent's allow[{i}]; only a prefix of the parent's ordered allow rules is provably no broader",
                ca.method, ca.path, ca.tool
            ));
        }
        if effect_rank(&ca.effect) < effect_rank(&pa.effect) {
            return Err(format!(
                "allow[{i}] tags effect {:?}, weaker than the parent's {:?}",
                ca.effect, pa.effect
            ));
        }
        if !budget_within(ca.max_calls, pa.max_calls) {
            return Err(format!(
                "allow[{i}] max_calls {} exceeds the parent's {}",
                ca.max_calls, pa.max_calls
            ));
        }
    }
    Ok(())
}

/// A parsed CIDR as an inclusive range in its family (v4 in the low 32
/// bits).
#[derive(Debug, Clone, Copy)]
struct Net {
    v6: bool,
    lo: u128,
    hi: u128,
}

fn parse_cidr(s: &str) -> Option<Net> {
    let (addr, prefix) = s.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    // Only canonical spellings, so the egress proxy's parser is certain to
    // read the same network.
    if format!("{addr}/{prefix}") != s {
        return None;
    }
    let (v6, bits, value) = match addr {
        IpAddr::V4(a) => (false, 32, u128::from(u32::from(a))),
        IpAddr::V6(a) => (true, 128, u128::from(a)),
    };
    if prefix > bits {
        return None;
    }
    let host_bits = bits - prefix;
    let mask: u128 = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let lo = value & !mask;
    Some(Net {
        v6,
        lo,
        hi: lo | mask,
    })
}

const V4_MAPPED_LO: u128 = 0xffff_0000_0000;
const V4_MAPPED_HI: u128 = 0xffff_ffff_ffff;

fn check_ip_cells(p: &Charter, c: &Charter) -> Result<usize, Refusal> {
    let mut nets: Vec<Vec<(usize, Net, bool)>> = Vec::new();
    for x in [p, c] {
        let mut v = Vec::new();
        for (i, r) in x.network.rules.iter().enumerate() {
            if r.cidr.is_empty() {
                continue;
            }
            let Some(n) = parse_cidr(&r.cidr) else {
                return refuse(
                    "network",
                    format!(
                        "{} is not a canonical CIDR, so its effect cannot be compared",
                        describe_net_rule(i, r)
                    ),
                );
            };
            v.push((i, n, rule_allows(r)));
        }
        nets.push(v);
    }
    let decide = |set: &[(usize, Net, bool)], x: &Charter, v6: bool, ip: u128| {
        set.iter()
            .find(|(_, n, _)| n.v6 == v6 && n.lo <= ip && ip <= n.hi)
            .map_or((None, default_allows(x)), |(i, _, a)| (Some(*i), *a))
    };
    let mut ranges = 0;
    for v6 in [false, true] {
        let max = if v6 { u128::MAX } else { u128::from(u32::MAX) };
        let mut points: BTreeSet<u128> = BTreeSet::from([0]);
        if v6 {
            points.insert(V4_MAPPED_LO);
            points.insert(V4_MAPPED_HI + 1);
        }
        for (_, n, _) in nets.iter().flatten().filter(|(_, n, _)| n.v6 == v6) {
            points.insert(n.lo);
            if n.hi < max {
                points.insert(n.hi + 1);
            }
        }
        for ip in points {
            // IPv4-mapped IPv6 addresses are canonicalised to IPv4 by the
            // gate; the IPv4 pass covers them.
            if v6 && (V4_MAPPED_LO..=V4_MAPPED_HI).contains(&ip) {
                continue;
            }
            ranges += 1;
            let (ci, ca) = decide(&nets[1], c, v6, ip);
            let (pi, pa) = decide(&nets[0], p, v6, ip);
            if ca && !pa {
                let addr = if v6 {
                    IpAddr::from(ip.to_be_bytes())
                } else {
                    IpAddr::from((ip as u32).to_be_bytes())
                };
                let how = match ci {
                    Some(i) => format!("child {}", describe_net_rule(i, &c.network.rules[i])),
                    None => "the child's default = \"allow\"".into(),
                };
                let why = match pi {
                    Some(i) => {
                        format!("the parent's {}", describe_net_rule(i, &p.network.rules[i]))
                    }
                    None => "the parent's default".into(),
                };
                return refuse(
                    "network",
                    format!("{how} admits IP {addr}, which {why} refuses"),
                );
            }
        }
    }
    Ok(ranges)
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

fn floor(c: &Charter) -> Result<IsolationLevel, Refusal> {
    if c.isolation.is_unset() {
        return Ok(IsolationLevel::Process);
    }
    c.isolation.minimum_level().ok_or_else(|| Refusal {
        dimension: "isolation",
        reason: format!("unknown isolation.minimum {:?}", c.isolation.minimum),
    })
}

fn check_isolation(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    let (fp, fc) = (floor(p)?, floor(c)?);
    if fc < fp {
        return refuse(
            "isolation",
            format!(
                "the child's floor ({}) is weaker than the parent's ({})",
                fc.as_str(),
                fp.as_str()
            ),
        );
    }
    Ok(format!("floor {} >= {}", fc.as_str(), fp.as_str()))
}

fn check_host(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    let (hp, hc) = (&p.host, &c.host);
    let same = [
        ("host.type", hp.host_type.as_str(), hc.host_type.as_str()),
        ("host.name", hp.name.as_str(), hc.name.as_str()),
        ("host.image", hp.image.as_str(), hc.image.as_str()),
        ("host.user", hp.user.as_str(), hc.user.as_str()),
        ("host.runtime", hp.runtime.as_str(), hc.runtime.as_str()),
        (
            "host.runtime_class",
            hp.runtime_class.as_str(),
            hc.runtime_class.as_str(),
        ),
        ("host.seccomp", hp.seccomp.as_str(), hc.seccomp.as_str()),
        ("host.apparmor", hp.apparmor.as_str(), hc.apparmor.as_str()),
    ];
    for (field, a, b) in same {
        if a != b {
            return refuse(
                "host",
                format!(
                    "{field} {b:?} differs from the parent's {a:?}; the sandbox boundary must be unchanged"
                ),
            );
        }
    }
    if hp.command != hc.command {
        return refuse(
            "host",
            "host.command differs from the parent's; an entrypoint runs outside policy",
        );
    }
    if !hc.copy_from.is_empty() && hc.copy_from != hp.copy_from {
        return refuse(
            "host",
            format!(
                "host.copy_from {:?} copies host files the parent does not",
                hc.copy_from
            ),
        );
    }
    if hp.read_only && !hc.read_only {
        return refuse(
            "host",
            "the parent's root filesystem is read-only; the child's is not",
        );
    }
    Ok("same boundary".into())
}

/// Splits an absolute path into segments; `None` for a relative path or
/// one with `.`/`..` segments, whose meaning cannot be compared.
fn path_segments(p: &str) -> Option<Vec<&str>> {
    let rest = p.strip_prefix('/')?;
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    if segs.iter().any(|s| *s == "." || *s == "..") {
        return None;
    }
    Some(segs)
}

/// Whether `path` is `base` or beneath it.
fn beneath(path: &str, base: &str) -> bool {
    match (path_segments(path), path_segments(base)) {
        (Some(p), Some(b)) => p.len() >= b.len() && p[..b.len()] == b[..],
        _ => false,
    }
}

fn workdir(c: &Charter) -> &str {
    if c.host.workdir.is_empty() {
        "/workspace"
    } else {
        &c.host.workdir
    }
}

fn landlock_rank(mode: &str) -> u8 {
    match mode {
        "off" => 0,
        "required" => 2,
        _ => 1,
    }
}

fn check_filesystem(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    let Some(pf) = p.filesystem.as_ref().filter(|f| f.landlock != "off") else {
        return Ok("parent filesystem is unconfined".into());
    };
    let Some(cf) = c.filesystem.as_ref() else {
        return refuse(
            "filesystem",
            "the parent confines the filesystem; the child has no [filesystem]",
        );
    };
    if landlock_rank(&cf.landlock) < landlock_rank(&pf.landlock) {
        return refuse(
            "filesystem",
            format!(
                "landlock {:?} is weaker than the parent's {:?}",
                cf.landlock, pf.landlock
            ),
        );
    }
    let mut rw: Vec<&str> = pf.read_write.iter().map(String::as_str).collect();
    if pf.include_workdir {
        rw.push(workdir(p));
    }
    let mut readable = rw.clone();
    readable.extend(pf.read_only.iter().map(String::as_str));
    let mut child_rw: Vec<(String, &str)> = cf
        .read_write
        .iter()
        .map(|x| (format!("read_write {x:?}"), x.as_str()))
        .collect();
    if cf.include_workdir {
        child_rw.push((format!("include_workdir ({:?})", workdir(c)), workdir(c)));
    }
    for (what, path) in &child_rw {
        if !rw.iter().any(|b| beneath(path, b)) {
            return refuse(
                "filesystem",
                format!("{what} is not beneath a path the parent may write"),
            );
        }
    }
    for path in &cf.read_only {
        if !readable.iter().any(|b| beneath(path, b)) {
            return refuse(
                "filesystem",
                format!("read_only {path:?} is not beneath a path the parent may read"),
            );
        }
    }
    Ok("grants beneath the parent's".into())
}

fn check_process(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    let Some(pp) = &p.process else {
        return Ok("parent sets no identity".into());
    };
    let empty = runeward_charter::Process::default();
    let cp = c.process.as_ref().unwrap_or(&empty);
    for (field, a, b) in [
        ("run_as_user", &pp.run_as_user, &cp.run_as_user),
        ("run_as_group", &pp.run_as_group, &cp.run_as_group),
    ] {
        if !a.is_empty() && a != b {
            return refuse(
                "process",
                format!("process.{field} {b:?} differs from the parent's {a:?}"),
            );
        }
    }
    Ok("same identity".into())
}

fn check_features(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    if c.persists_workspace() && !p.persists_workspace() {
        return refuse(
            "workspace",
            "the child persists its workspace; the parent does not",
        );
    }
    if c.schedule_self_service() && !p.schedule_self_service() {
        return refuse(
            "schedule",
            "the child lets agents schedule their own runs; the parent does not",
        );
    }
    if c.ide.enabled && !p.ide.enabled {
        return refuse(
            "ide",
            "the child enables the browser IDE; the parent does not",
        );
    }
    Ok("no added workspace, schedule or IDE capability".into())
}

// ---------------------------------------------------------------------------
// Rationing
// ---------------------------------------------------------------------------

fn duration_nanos(field: &str, raw: &str) -> Result<i64, Refusal> {
    if raw.trim().is_empty() {
        return Ok(0);
    }
    parse_go_duration(raw.trim())
        .map(|n| n.max(0))
        .map_err(|e| Refusal {
            dimension: "rationing",
            reason: format!("{field} {raw:?}: {e}"),
        })
}

/// The container memory parser (`512m`, `2g`); unparsable is unlimited, as
/// for the backend.
fn memory_bytes(raw: &str) -> i64 {
    let s = raw.trim();
    let Some(last) = s.chars().last() else {
        return 0;
    };
    let (mult, num): (i64, &str) = match last {
        'k' | 'K' => (1 << 10, &s[..s.len() - 1]),
        'm' | 'M' => (1 << 20, &s[..s.len() - 1]),
        'g' | 'G' => (1 << 30, &s[..s.len() - 1]),
        't' | 'T' => (1 << 40, &s[..s.len() - 1]),
        _ => (1, s),
    };
    num.trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n >= 0)
        .and_then(|n| n.checked_mul(mult))
        .unwrap_or(0)
}

fn cap_within<T: PartialOrd + Default + fmt::Display + Copy>(
    field: &str,
    child: T,
    parent: T,
) -> Result<(), Refusal> {
    let zero = T::default();
    if parent > zero && !(child > zero && child <= parent) {
        let shown = if child > zero {
            child.to_string()
        } else {
            "unlimited".into()
        };
        return refuse(
            "rationing",
            format!("{field} {shown} exceeds the parent's {parent}"),
        );
    }
    Ok(())
}

fn check_rationing(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    let (lp, lc) = (&p.limits, &c.limits);
    cap_within(
        "wall_clock (ns)",
        duration_nanos("wall_clock", &lc.wall_clock)?,
        duration_nanos("wall_clock", &lp.wall_clock)?,
    )?;
    cap_within("max_execs", lc.max_execs, lp.max_execs)?;
    cap_within(
        "memory (bytes)",
        memory_bytes(&lc.memory),
        memory_bytes(&lp.memory),
    )?;
    cap_within("cpus", lc.cpus, lp.cpus)?;
    cap_within("egress_requests", lc.egress_requests, lp.egress_requests)?;
    cap_within("max_tokens", lc.max_tokens, lp.max_tokens)?;
    cap_within("max_cost_usd", lc.max_cost_usd, lp.max_cost_usd)?;
    let pw = duration_nanos("loop_window", &lp.loop_window)?;
    if pw > 0 && lp.loop_threshold > 0 {
        let cw = duration_nanos("loop_window", &lc.loop_window)?;
        if cw < pw || lc.loop_threshold <= 0 || lc.loop_threshold > lp.loop_threshold {
            return refuse(
                "rationing",
                format!(
                    "loop detection ({} failures in {:?}) is less sensitive than the parent's ({} in {:?})",
                    lc.loop_threshold, lc.loop_window, lp.loop_threshold, lp.loop_window
                ),
            );
        }
    }
    Ok("every parent cap kept or tightened".into())
}

// ---------------------------------------------------------------------------
// Secrets and evidence
// ---------------------------------------------------------------------------

fn check_secrets(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    for e in &c.env {
        if !p.env.contains(e) {
            return refuse(
                "secrets",
                format!(
                    "env {:?} is not one of the parent's [[env]] entries",
                    e.name
                ),
            );
        }
    }
    for f in &c.files {
        if !p.files.contains(f) {
            return refuse(
                "secrets",
                format!(
                    "file {:?} is not one of the parent's [[file]] entries",
                    f.path
                ),
            );
        }
    }
    Ok(format!(
        "{} env and {} file entries from the parent",
        c.env.len(),
        c.files.len()
    ))
}

fn check_chronicle(p: &Charter, c: &Charter) -> Result<String, Refusal> {
    if p.audit.sink != c.audit.sink {
        return refuse(
            "chronicle",
            format!(
                "chronicle.sink {:?} differs from the parent's {:?}",
                c.audit.sink, p.audit.sink
            ),
        );
    }
    if p.audit.redact_enabled() && !c.audit.redact_enabled() {
        return refuse(
            "chronicle",
            "the child disables redaction; the parent redacts",
        );
    }
    let mine: BTreeSet<&str> = c.audit.scrub_patterns.iter().map(|s| s.trim()).collect();
    if let Some(missing) = p
        .audit
        .scrub_patterns
        .iter()
        .map(|s| s.trim())
        .find(|s| !s.is_empty() && !mine.contains(s))
    {
        return refuse(
            "chronicle",
            format!("drops the parent's scrub pattern {missing:?}"),
        );
    }
    Ok("same sink, redaction and scrub patterns kept".into())
}

#[cfg(test)]
#[path = "subsume_tests.rs"]
mod tests;
