use runeward_charter::{
    Audit, Credential, Endpoint, EnvVar, Filesystem, Ide, Isolation, Limits, Network, Process,
    RegoPolicy, RequestRule, Schedule, Workspace,
};

use super::*;
use crate::{Action, Evaluator, RuleEngine, match_glob};

fn rule(tool: &str, glob: &str, argv: &str, verdict: Verdict) -> PolicyRule {
    PolicyRule {
        tool: tool.into(),
        match_glob: glob.into(),
        match_argv: argv.into(),
        verdict,
        reason: String::new(),
    }
}

fn charter(name: &str, rules: Vec<PolicyRule>, default: Verdict) -> Charter {
    Charter {
        name: name.into(),
        policy: rules,
        policy_default: default,
        ..Charter::default()
    }
}

fn accepts(p: &Charter, c: &Charter) -> bool {
    check_subsumption(p, c, None).is_ok()
}

fn refusal(p: &Charter, c: &Charter) -> Refusal {
    check_subsumption(p, c, None).expect_err("child must be refused")
}

/// A small deterministic xorshift generator (no extra dependencies).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

const TOOLS: [&str; 4] = ["shell", "file.read", "net", "*"];
const GLOB_BYTES: [char; 6] = ['a', 'b', '/', ' ', '*', '?'];
const ARGV: [&str; 5] = ["a", "b", "*a", "/bin/a", "sh"];
const VERDICTS: [Verdict; 3] = [Verdict::Allow, Verdict::Deny, Verdict::RequireApproval];

fn random_rule(rng: &mut Rng) -> PolicyRule {
    let len = rng.below(4);
    let glob: String = (0..len).map(|_| *rng.pick(&GLOB_BYTES)).collect();
    let argv = if rng.chance(25) { *rng.pick(&ARGV) } else { "" };
    let tool = *rng.pick(&TOOLS);
    rule(tool, &glob, argv, rng.pick(&VERDICTS).clone())
}

fn random_charter(rng: &mut Rng, name: &str) -> Charter {
    let n = rng.below(5);
    let rules = (0..n).map(|_| random_rule(rng)).collect();
    let default = if rng.chance(50) {
        Verdict::Allow
    } else {
        Verdict::Deny
    };
    charter(name, rules, default)
}

/// Every action the oracle evaluates: four tools (one no rule names),
/// every argument up to four bytes over the glob alphabet, and argv
/// variants that exercise `match_argv` (including shell wrappers).
fn sample_actions() -> Vec<Action> {
    let alphabet = ['a', 'b', '/', ' '];
    let mut args = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..4 {
        let mut next = Vec::new();
        for s in &frontier {
            for c in alphabet {
                next.push(format!("{s}{c}"));
            }
        }
        args.extend(next.iter().cloned());
        frontier = next;
    }
    let argvs: Vec<Vec<&str>> = vec![
        vec![],
        vec!["/bin/a", "b"],
        vec!["sh", "-c", "a b"],
        vec!["env", "X=1", "sh", "-c", "/bin/a"],
        vec!["ba", "a"],
    ];
    let mut out = Vec::new();
    for tool in ["shell", "file.read", "net", "other"] {
        for arg in &args {
            for argv in &argvs {
                out.push(Action::new(tool, arg.clone()).with_args(argv.iter().copied()));
            }
        }
    }
    out
}

fn engine_verdict(c: &Charter, a: &Action) -> Verdict {
    RuleEngine::new(c.policy.clone(), no_match_verdict(Some(c), None))
        .evaluate(a)
        .verdict
}

/// Soundness against the real engine: whenever the proof accepts a child,
/// no sampled action gets a broader verdict from the child than from the
/// parent.
#[test]
fn accepted_children_are_never_broader_than_the_engine_says() {
    let actions = sample_actions();
    let mut rng = Rng(0x5eed_cafe_f00d_1234);
    let mut accepted = 0;
    for round in 0..400 {
        let parent = random_charter(&mut rng, "parent");
        let child = if round % 2 == 0 {
            random_charter(&mut rng, "child")
        } else {
            let mut c = tighten(&mut rng, &parent);
            // Then a random edit that may broaden.
            if !c.policy.is_empty() {
                let i = rng.below(c.policy.len());
                c.policy[i] = random_rule(&mut rng);
            }
            c
        };
        if check_subsumption(&parent, &child, None).is_err() {
            continue;
        }
        accepted += 1;
        for a in &actions {
            let (cv, pv) = (engine_verdict(&child, a), engine_verdict(&parent, a));
            assert!(
                rank(&cv) <= rank(&pv),
                "accepted a broader child\nparent: {:?}\nchild: {:?}\naction: {a:?} child {cv} parent {pv}",
                parent.policy,
                child.policy
            );
        }
    }
    assert!(accepted > 40, "only {accepted} children accepted");
}

/// Verdict-lowering edits only: insert a deny rule, lower a rule's
/// verdict, drop an allow rule, or lower the default.
fn tighten(rng: &mut Rng, parent: &Charter) -> Charter {
    let mut c = parent.clone();
    c.name = "child".into();
    for _ in 0..1 + rng.below(3) {
        match rng.below(4) {
            0 => {
                let mut r = random_rule(rng);
                r.verdict = Verdict::Deny;
                let at = rng.below(c.policy.len() + 1);
                c.policy.insert(at, r);
            }
            1 if !c.policy.is_empty() => {
                let i = rng.below(c.policy.len());
                c.policy[i].verdict = match c.policy[i].verdict {
                    Verdict::Allow => Verdict::RequireApproval,
                    _ => Verdict::Deny,
                };
            }
            2 => {
                if let Some(i) = c.policy.iter().position(|r| r.verdict == Verdict::Allow) {
                    c.policy.remove(i);
                }
            }
            _ => c.policy_default = Verdict::Deny,
        }
    }
    c
}

#[test]
fn tightened_policies_are_always_accepted() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..500 {
        let parent = random_charter(&mut rng, "parent");
        let child = tighten(&mut rng, &parent);
        if let Err(e) = check_subsumption(&parent, &child, None) {
            panic!(
                "refused a tightened child: {e}\nparent: {:?}\nchild: {:?}",
                parent.policy, child.policy
            );
        }
    }
}

/// The product automaton agrees with the engine's glob matcher: each
/// cell's witness has exactly the cell's outcomes, and every sampled
/// string falls in some cell.
#[test]
fn glob_cells_agree_with_match_glob() {
    let mut rng = Rng(0xfeed_beef_0bad_f00d);
    let samples: Vec<String> = sample_actions()
        .into_iter()
        .filter(|a| a.tool == "shell" && a.args.is_empty())
        .map(|a| a.arg)
        .collect();
    for _ in 0..200 {
        let globs: Vec<String> = (0..1 + rng.below(4))
            .map(|_| {
                let len = 1 + rng.below(4);
                (0..len).map(|_| *rng.pick(&GLOB_BYTES)).collect()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let cells = glob_cells(&globs).expect("small");
        for (vec, witness) in &cells {
            let got: Vec<bool> = globs.iter().map(|g| match_glob(g, witness)).collect();
            assert_eq!(&got, vec, "witness {witness:?} for {globs:?}");
        }
        for s in &samples {
            let v: Vec<bool> = globs.iter().map(|g| match_glob(g, s)).collect();
            assert!(
                cells.iter().any(|(c, _)| *c == v),
                "{s:?} not covered by {globs:?}"
            );
        }
    }
}

#[test]
fn identical_charter_is_exact_and_renamed_copy_is_subsumed() {
    let p = charter(
        "dev",
        vec![rule("shell", "rm *", "", Verdict::Deny)],
        Verdict::Allow,
    );
    assert_eq!(check_subsumption(&p, &p, None), Ok(Proof::Exact));
    let mut renamed = p.clone();
    renamed.name = "dev-copy".into();
    let proof = check_subsumption(&p, &renamed, None).expect("same contract");
    assert_eq!(proof.method(), "subsumed");
    assert!(proof.summary().contains("policy: "), "{}", proof.summary());
    // Discovered capabilities are not authority.
    let mut discovered = p.clone();
    discovered.capabilities = vec!["python".into()];
    assert_eq!(check_subsumption(&p, &discovered, None), Ok(Proof::Exact));
}

#[test]
fn precedence_child_deny_the_parent_lacked_is_fine() {
    let p = charter(
        "p",
        vec![rule("shell", "git *", "", Verdict::Allow)],
        Verdict::Deny,
    );
    let c = charter(
        "c",
        vec![
            rule("shell", "git push*", "", Verdict::Deny),
            rule("shell", "git *", "", Verdict::Allow),
        ],
        Verdict::Deny,
    );
    assert!(accepts(&p, &c));
}

#[test]
fn precedence_child_allow_shadowing_a_parent_deny_is_refused() {
    let p = charter(
        "p",
        vec![
            rule("shell", "git push*", "", Verdict::Deny),
            rule("shell", "git *", "", Verdict::Allow),
        ],
        Verdict::Deny,
    );
    // Same rules, reordered: the allow now shadows the deny.
    let c = charter(
        "c",
        vec![
            rule("shell", "git *", "", Verdict::Allow),
            rule("shell", "git push*", "", Verdict::Deny),
        ],
        Verdict::Deny,
    );
    let r = refusal(&p, &c);
    assert_eq!(r.dimension, "policy");
    assert!(r.reason.contains("child policy[0]"), "{r}");
    assert!(r.reason.contains("the parent's policy[0]"), "{r}");
    assert!(r.reason.contains("git push"), "{r}");
}

#[test]
fn precedence_wildcard_tool_and_default() {
    // A `*` deny in the parent covers tools the child names explicitly.
    let p = charter("p", vec![rule("*", "", "", Verdict::Deny)], Verdict::Allow);
    let c = charter(
        "c",
        vec![rule("file.read", "/etc/*", "", Verdict::Allow)],
        Verdict::Deny,
    );
    let r = refusal(&p, &c);
    assert!(r.reason.contains("file.read"), "{r}");
    // A child that falls through to a broader default is refused too.
    let p = charter(
        "p",
        vec![rule("shell", "", "", Verdict::Allow)],
        Verdict::Deny,
    );
    let c = charter(
        "c",
        vec![rule("shell", "", "", Verdict::Allow)],
        Verdict::Allow,
    );
    let r = refusal(&p, &c);
    assert!(r.reason.contains("no-match default"), "{r}");
    assert!(r.reason.contains("unlisted-tool"), "{r}");
}

#[test]
fn approval_ranks_between_allow_and_deny() {
    let p = charter(
        "p",
        vec![rule("shell", "", "", Verdict::RequireApproval)],
        Verdict::Deny,
    );
    let allow = charter(
        "c",
        vec![rule("shell", "", "", Verdict::Allow)],
        Verdict::Deny,
    );
    assert!(!accepts(&p, &allow));
    let deny = charter(
        "c",
        vec![rule("shell", "", "", Verdict::Deny)],
        Verdict::Deny,
    );
    assert!(accepts(&p, &deny));
}

#[test]
fn argv_rules_are_compared_conservatively() {
    let p = charter(
        "p",
        vec![rule("shell", "", "rm", Verdict::Deny)],
        Verdict::Allow,
    );
    // Same argv deny: accepted.
    let mut same = p.clone();
    same.name = "c".into();
    assert!(accepts(&p, &same));
    // Dropping it is broader.
    let dropped = charter("c", vec![], Verdict::Allow);
    assert!(!accepts(&p, &dropped));
    // A different (here: narrower in practice) argv glob cannot be related
    // to the parent's and is refused rather than guessed.
    let other = charter(
        "c",
        vec![rule("shell", "", "r*", Verdict::Deny)],
        Verdict::Allow,
    );
    assert!(!accepts(&p, &other));
}

#[test]
fn operator_default_decides_unset_defaults() {
    let p = charter("p", vec![], Verdict::Deny);
    let c = charter("c", vec![], Verdict::Unset);
    assert!(check_subsumption(&p, &c, None).is_err());
    assert!(check_subsumption(&p, &c, Some("allow")).is_err());
    assert!(check_subsumption(&p, &c, Some("deny")).is_ok());
}

#[test]
fn other_engines_need_identical_pinned_configuration() {
    let rego = |module: &str, file: &str| Charter {
        policy_engine: "rego".into(),
        rego: RegoPolicy {
            module: module.into(),
            file: file.into(),
            query: String::new(),
        },
        ..Charter::default()
    };
    let p = Charter {
        name: "p".into(),
        ..rego("package runeward", "")
    };
    let c = Charter {
        name: "c".into(),
        ..rego("package runeward", "")
    };
    assert!(accepts(&p, &c));
    let c2 = Charter {
        name: "c".into(),
        ..rego("package runeward\n# changed", "")
    };
    assert_eq!(refusal(&p, &c2).dimension, "policy");
    let pf = Charter {
        name: "p".into(),
        ..rego("", "/etc/policy.rego")
    };
    let cf = Charter {
        name: "c".into(),
        ..rego("", "/etc/policy.rego")
    };
    assert!(refusal(&pf, &cf).reason.contains("rego.file"));

    // A deny-everything built-in child fits under any engine; an
    // allow-everything built-in parent admits any engine.
    let deny_all = charter("c", vec![], Verdict::Deny);
    assert!(accepts(&p, &deny_all));
    let allow_all = charter("p", vec![], Verdict::Allow);
    assert!(accepts(&allow_all, &c));
    let some_allow = charter(
        "c",
        vec![rule("shell", "ls", "", Verdict::Allow)],
        Verdict::Deny,
    );
    assert!(refusal(&p, &some_allow).reason.contains("cannot compare"));
}

#[test]
fn complex_globs_are_refused_not_guessed() {
    let many: Vec<PolicyRule> = (0..MAX_ARGV_GLOBS + 1)
        .map(|i| rule("shell", "", &format!("bin{i}"), Verdict::Deny))
        .collect();
    let p = charter("p", many.clone(), Verdict::Allow);
    let mut c = p.clone();
    c.name = "c".into();
    c.policy.push(rule("shell", "x", "", Verdict::Deny));
    let r = refusal(&p, &c);
    assert!(r.reason.contains("match_argv"), "{r}");
}

// --- Network ---------------------------------------------------------------

fn net_rule(verdict: &str, host: &str, cidr: &str) -> NetworkRule {
    NetworkRule {
        verdict: verdict.into(),
        hostname: host.into(),
        cidr: cidr.into(),
    }
}

fn with_net(name: &str, default: &str, rules: Vec<NetworkRule>) -> Charter {
    Charter {
        name: name.into(),
        network: Network {
            default: default.into(),
            rules,
            enforce: String::new(),
        },
        ..Charter::default()
    }
}

#[test]
fn network_tightening_is_accepted() {
    let p = with_net(
        "p",
        "deny",
        vec![
            net_rule("allow", "*.example.com", ""),
            net_rule("allow", "pypi.org", ""),
            net_rule("allow", "", "10.0.0.0/8"),
        ],
    );
    let c = with_net(
        "c",
        "deny",
        vec![
            net_rule("deny", "secret.example.com", ""),
            net_rule("allow", "api.example.com", ""),
            net_rule("allow", "", "10.1.0.0/16"),
        ],
    );
    let proof = check_subsumption(&p, &c, None).expect("narrower");
    assert!(proof.summary().contains("network: "), "{}", proof.summary());
    // An open parent constrains nothing.
    let open = with_net("p", "", vec![]);
    assert!(accepts(&open, &with_net("c", "", vec![])));
    assert!(accepts(&open, &p));
}

#[test]
fn network_broadening_is_refused() {
    let p = with_net("p", "deny", vec![net_rule("allow", "api.example.com", "")]);
    for (case, c, needle) in [
        (
            "open default",
            with_net("c", "", vec![net_rule("allow", "api.example.com", "")]),
            "unrestricted",
        ),
        (
            "wildcard widens an exact host",
            with_net("c", "deny", vec![net_rule("allow", "*.example.com", "")]),
            "*.example.com",
        ),
        (
            "new host",
            with_net("c", "deny", vec![net_rule("allow", "evil.test", "")]),
            "evil.test",
        ),
        (
            "cidr",
            with_net("c", "deny", vec![net_rule("allow", "", "10.0.0.0/8")]),
            "10.0.0.0",
        ),
        (
            "allow shadows a parent deny",
            with_net("c", "deny", vec![net_rule("", "api.example.com", "")]),
            "",
        ),
    ] {
        if case == "allow shadows a parent deny" {
            // An unset verdict means allow: same as the parent, accepted.
            assert!(accepts(&p, &c), "{case}");
            continue;
        }
        let r = refusal(&p, &c);
        assert_eq!(r.dimension, "network", "{case}: {r}");
        assert!(r.reason.contains(needle), "{case}: {r}");
    }

    // Rule order matters: the parent denies a subdomain before allowing
    // the wildcard; the child only allows the wildcard.
    let p = with_net(
        "p",
        "deny",
        vec![
            net_rule("deny", "admin.example.com", ""),
            net_rule("allow", "*.example.com", ""),
        ],
    );
    let c = with_net("c", "deny", vec![net_rule("allow", "*.example.com", "")]);
    let r = refusal(&p, &c);
    assert!(r.reason.contains("admin.example.com"), "{r}");
    assert!(r.reason.contains("network.rule[0]"), "{r}");

    // Strict enforcement must be kept.
    let mut strict = with_net("p", "deny", vec![]);
    strict.network.enforce = "strict".into();
    let r = refusal(&strict, &with_net("c", "deny", vec![]));
    assert!(r.reason.contains("strictly"), "{r}");

    // IP-shaped hostnames are only compared when everything is identical.
    let p = with_net("p", "deny", vec![net_rule("allow", "10.0.0.1", "")]);
    let c = with_net("c", "deny", vec![]);
    assert!(refusal(&p, &c).reason.contains("IP literals"));
    // Non-canonical CIDRs are refused.
    let p = with_net("p", "deny", vec![net_rule("allow", "", "10.0.0.0/8")]);
    let c = with_net("c", "deny", vec![net_rule("allow", "", "10.0.0.0/08")]);
    assert!(refusal(&p, &c).reason.contains("canonical"));
    // IPv6 ranges are compared too.
    let p = with_net("p", "deny", vec![net_rule("allow", "", "2001:db8::/48")]);
    let ok = with_net(
        "c",
        "deny",
        vec![net_rule("allow", "", "2001:db8:0:1::/64")],
    );
    assert!(accepts(&p, &ok));
    let wide = with_net("c", "deny", vec![net_rule("allow", "", "2001:db8::/32")]);
    assert!(!accepts(&p, &wide));
}

fn endpoint(host: &str) -> Endpoint {
    Endpoint {
        name: host.into(),
        host: host.into(),
        protocol: "rest".into(),
        allow: vec![
            RequestRule {
                method: "GET".into(),
                path: "/repos/**".into(),
                effect: "read".into(),
                ..RequestRule::default()
            },
            RequestRule {
                method: "POST".into(),
                path: "/repos/*/issues".into(),
                effect: "write".into(),
                max_calls: 5,
                ..RequestRule::default()
            },
        ],
        deny: vec![RequestRule {
            path: "/repos/*/hooks/**".into(),
            ..RequestRule::default()
        }],
        credential: "gh".into(),
        ..Endpoint::default()
    }
}

fn cred() -> Credential {
    Credential {
        name: "gh".into(),
        source: "op://Dev/github/token".into(),
        placeholder_env: "GITHUB_TOKEN".into(),
        inject: "bearer".into(),
    }
}

fn brokered(name: &str, eps: Vec<Endpoint>, creds: Vec<Credential>) -> Charter {
    Charter {
        endpoints: eps,
        credentials: creds,
        ..with_net(name, "deny", vec![])
    }
}

#[test]
fn endpoints_may_only_tighten() {
    let p = brokered("p", vec![endpoint("api.github.com")], vec![cred()]);

    let mut tighter = endpoint("api.github.com");
    tighter.allow.truncate(1);
    tighter.deny.push(RequestRule {
        path: "/repos/acme/secret/**".into(),
        ..RequestRule::default()
    });
    tighter.max_calls = 10;
    assert!(accepts(&p, &brokered("c", vec![tighter], vec![cred()])));
    // Dropping the endpoint entirely is narrower too.
    assert!(accepts(&p, &brokered("c", vec![], vec![])));

    type Edit = Box<dyn Fn(&mut Endpoint)>;
    let cases: Vec<(&str, Edit, &str)> = vec![
        ("drops a deny rule", Box::new(|e| e.deny.clear()), "deny[0]"),
        (
            "allows everything",
            Box::new(|e| e.allow.clear()),
            "no allow rules",
        ),
        (
            "reorders allow rules",
            Box::new(|e| e.allow.reverse()),
            "prefix",
        ),
        (
            "weakens an effect",
            Box::new(|e| e.allow[1].effect = "read".into()),
            "effect",
        ),
        (
            "lifts a rule budget",
            Box::new(|e| e.allow[1].max_calls = 0),
            "max_calls",
        ),
        ("audit mode", Box::new(|e| e.mode = "audit".into()), "audit"),
        (
            "protocol",
            Box::new(|e| e.protocol = "tcp".into()),
            "protocol",
        ),
        (
            "health path",
            Box::new(|e| e.health_path = "/status".into()),
            "health_path",
        ),
    ];
    for (case, edit, needle) in cases {
        let mut e = endpoint("api.github.com");
        edit(&mut e);
        let r = refusal(&p, &brokered("c", vec![e], vec![cred()]));
        assert_eq!(r.dimension, "network", "{case}");
        assert!(r.reason.contains(needle), "{case}: {r}");
    }

    // Binaries: a listed parent restricts the child to a subset.
    let mut pb = endpoint("api.github.com");
    pb.binaries = vec!["/usr/bin/gh".into()];
    let p = brokered("p", vec![pb.clone()], vec![cred()]);
    let mut any = pb.clone();
    any.binaries.clear();
    assert!(
        refusal(&p, &brokered("c", vec![any], vec![cred()]))
            .reason
            .contains("any binary")
    );
    let mut more = pb.clone();
    more.binaries.push("/usr/bin/curl".into());
    assert!(
        refusal(&p, &brokered("c", vec![more], vec![cred()]))
            .reason
            .contains("curl")
    );

    // A new endpoint host is new egress.
    let r = refusal(
        &p,
        &brokered(
            "c",
            vec![pb.clone(), endpoint("uploads.github.com")],
            vec![cred()],
        ),
    );
    assert!(r.reason.contains("uploads.github.com"), "{r}");

    // Reaching the parent's endpoint host without the endpoint (via a
    // plain network allow) skips its request rules.
    let mut p = p.clone();
    p.network.rules = vec![net_rule("allow", "api.github.com", "")];
    let bypass = with_net("c", "deny", vec![net_rule("allow", "api.github.com", "")]);
    let r = refusal(&p, &bypass);
    assert!(r.reason.contains("without the request rules"), "{r}");
}

#[test]
fn credentials_must_be_the_parents() {
    let p = brokered("p", vec![endpoint("api.github.com")], vec![cred()]);
    let mut other = cred();
    other.source = "env://OTHER".into();
    let r = refusal(
        &p,
        &brokered("c", vec![endpoint("api.github.com")], vec![other]),
    );
    assert!(r.reason.contains("credential \"gh\" differs"), "{r}");
    let mut extra = cred();
    extra.name = "npm".into();
    let r = refusal(
        &p,
        &brokered("c", vec![endpoint("api.github.com")], vec![cred(), extra]),
    );
    assert!(
        r.reason.contains("\"npm\" is not one of the parent's"),
        "{r}"
    );
    // A child that attaches a credential where the parent's open network
    // attaches none is refused.
    let mut open_parent = with_net("p", "deny", vec![net_rule("allow", "api.github.com", "")]);
    open_parent.credentials = vec![cred()];
    let mut injecting = endpoint("api.github.com");
    injecting.allow.clear();
    injecting.deny.clear();
    let r = refusal(&open_parent, &brokered("c", vec![injecting], vec![cred()]));
    assert!(r.reason.contains("injects credential"), "{r}");
}

// --- Containment, features, rationing, secrets, evidence ---------------------

fn base(name: &str) -> Charter {
    Charter {
        name: name.into(),
        ..Charter::default()
    }
}

#[test]
fn containment_dimensions() {
    let mut p = base("p");
    p.isolation = Isolation {
        minimum: "kernel".into(),
    };
    p.host.image = "ghcr.io/acme/agent:1".into();
    p.host.read_only = true;
    p.filesystem = Some(Filesystem {
        read_only: vec!["/usr".into()],
        read_write: vec!["/tmp".into()],
        include_workdir: true,
        landlock: "best-effort".into(),
    });
    p.process = Some(Process {
        run_as_user: "1500".into(),
        run_as_group: String::new(),
    });

    let mut tighter = p.clone();
    tighter.name = "c".into();
    tighter.isolation.minimum = "vm".into();
    tighter.filesystem = Some(Filesystem {
        read_only: vec!["/usr/lib".into(), "/tmp/cache".into()],
        read_write: vec!["/tmp/work".into()],
        include_workdir: false,
        landlock: "required".into(),
    });
    assert!(accepts(&p, &tighter));

    type Edit = Box<dyn Fn(&mut Charter)>;
    let cases: Vec<(&str, Edit, &str)> = vec![
        (
            "weaker floor",
            Box::new(|c| c.isolation.minimum = "container".into()),
            "isolation",
        ),
        (
            "other image",
            Box::new(|c| c.host.image = "evil:latest".into()),
            "host",
        ),
        (
            "writable root",
            Box::new(|c| c.host.read_only = false),
            "host",
        ),
        (
            "entrypoint",
            Box::new(|c| c.host.command = vec!["sh".into()]),
            "host",
        ),
        (
            "copy_from",
            Box::new(|c| c.host.copy_from = "~/".into()),
            "host",
        ),
        (
            "runtime",
            Box::new(|c| c.host.runtime_class = "runc".into()),
            "host",
        ),
        (
            "no filesystem",
            Box::new(|c| c.filesystem = None),
            "filesystem",
        ),
        (
            "write outside",
            Box::new(|c| {
                c.filesystem
                    .as_mut()
                    .expect("fs")
                    .read_write
                    .push("/etc".into())
            }),
            "filesystem",
        ),
        (
            "read outside",
            Box::new(|c| {
                c.filesystem
                    .as_mut()
                    .expect("fs")
                    .read_only
                    .push("/home".into())
            }),
            "filesystem",
        ),
        (
            "write a read-only path",
            Box::new(|c| {
                c.filesystem
                    .as_mut()
                    .expect("fs")
                    .read_write
                    .push("/usr".into())
            }),
            "filesystem",
        ),
        (
            "dot-dot escape",
            Box::new(|c| {
                c.filesystem
                    .as_mut()
                    .expect("fs")
                    .read_write
                    .push("/tmp/../etc".into())
            }),
            "filesystem",
        ),
        (
            "landlock off",
            Box::new(|c| c.filesystem.as_mut().expect("fs").landlock = "off".into()),
            "filesystem",
        ),
        (
            "other workdir",
            Box::new(|c| c.host.workdir = "/home/agent".into()),
            "filesystem",
        ),
        ("other uid", Box::new(|c| c.process = None), "process"),
        (
            "persist",
            Box::new(|c| {
                c.workspace = Some(Workspace {
                    persist: true,
                    idle_timeout: String::new(),
                })
            }),
            "workspace",
        ),
        (
            "schedules",
            Box::new(|c| c.schedule = Some(Schedule { self_service: true })),
            "schedule",
        ),
        (
            "ide",
            Box::new(|c| {
                c.ide = Ide {
                    enabled: true,
                    ..Ide::default()
                }
            }),
            "ide",
        ),
    ];
    for (case, edit, dimension) in cases {
        let mut c = p.clone();
        c.name = "c".into();
        edit(&mut c);
        let r = refusal(&p, &c);
        assert_eq!(r.dimension, dimension, "{case}: {r}");
    }
}

#[test]
fn rationing_caps_only_tighten() {
    let mut p = base("p");
    p.limits = Limits {
        wall_clock: "30m".into(),
        max_execs: 100,
        memory: "1g".into(),
        cpus: 2.0,
        egress_requests: 50,
        loop_window: "5m".into(),
        loop_threshold: 3,
        max_tokens: 10_000,
        max_cost_usd: 5.0,
    };
    let mut c = p.clone();
    c.name = "c".into();
    c.limits = Limits {
        wall_clock: "10m".into(),
        max_execs: 10,
        memory: "512m".into(),
        cpus: 1.0,
        egress_requests: 5,
        loop_window: "10m".into(),
        loop_threshold: 2,
        max_tokens: 100,
        max_cost_usd: 1.0,
    };
    assert!(accepts(&p, &c));

    type Edit = Box<dyn Fn(&mut Limits)>;
    let cases: Vec<(&str, Edit)> = vec![
        ("wall_clock", Box::new(|l| l.wall_clock = "1h".into())),
        ("wall_clock", Box::new(|l| l.wall_clock = String::new())),
        ("max_execs", Box::new(|l| l.max_execs = 0)),
        ("memory", Box::new(|l| l.memory = "2g".into())),
        ("cpus", Box::new(|l| l.cpus = 4.0)),
        ("egress_requests", Box::new(|l| l.egress_requests = 51)),
        ("max_tokens", Box::new(|l| l.max_tokens = 20_000)),
        ("max_cost_usd", Box::new(|l| l.max_cost_usd = 0.0)),
        ("loop", Box::new(|l| l.loop_threshold = 4)),
        ("loop", Box::new(|l| l.loop_window = "1m".into())),
    ];
    for (field, edit) in cases {
        let mut c = p.clone();
        c.name = "c".into();
        edit(&mut c.limits);
        let r = refusal(&p, &c);
        assert_eq!(r.dimension, "rationing", "{field}: {r}");
        assert!(r.reason.contains(field), "{field}: {r}");
    }
}

#[test]
fn secrets_and_chronicle() {
    let mut p = base("p");
    p.env = vec![
        EnvVar {
            name: "TOKEN".into(),
            op: "op://Dev/x/token".into(),
            ..EnvVar::default()
        },
        EnvVar {
            name: "MODE".into(),
            value: "ci".into(),
            ..EnvVar::default()
        },
    ];
    p.audit = Audit {
        sink: String::new(),
        redact: None,
        scrub_patterns: vec!["sk-[a-z]+".into()],
    };
    let mut fewer = p.clone();
    fewer.name = "c".into();
    fewer.env.truncate(1);
    fewer.audit.scrub_patterns.push("extra".into());
    assert!(accepts(&p, &fewer));

    let mut new_secret = fewer.clone();
    new_secret.env.push(EnvVar {
        name: "AWS".into(),
        op: "aws://prod".into(),
        ..EnvVar::default()
    });
    assert_eq!(refusal(&p, &new_secret).dimension, "secrets");
    let mut unredacted_literal = fewer.clone();
    unredacted_literal.env[0].op = "op://Dev/x/other".into();
    assert_eq!(refusal(&p, &unredacted_literal).dimension, "secrets");

    for edit in [
        (|c: &mut Charter| c.audit.redact = Some(false)) as fn(&mut Charter),
        |c| c.audit.scrub_patterns.clear(),
        |c| c.audit.sink = "/tmp/elsewhere".into(),
    ] {
        let mut c = fewer.clone();
        edit(&mut c);
        assert_eq!(refusal(&p, &c).dimension, "chronicle");
    }
}

/// Tightening in every dimension at once is still accepted, and the proof
/// names every dimension.
#[test]
fn proof_names_every_dimension() {
    let p = with_net("p", "deny", vec![net_rule("allow", "*.example.com", "")]);
    let mut c = with_net("c", "deny", vec![net_rule("allow", "api.example.com", "")]);
    c.policy = vec![rule("*", "", "", Verdict::Deny)];
    c.isolation.minimum = "vm".into();
    c.limits.max_execs = 5;
    let proof = check_subsumption(&p, &c, None).expect("tighter");
    let summary = proof.summary();
    for d in [
        "policy",
        "network",
        "isolation",
        "host",
        "filesystem",
        "process",
        "features",
        "rationing",
        "secrets",
        "chronicle",
    ] {
        assert!(
            summary.contains(&format!("{d}: ")),
            "{d} missing from {summary}"
        );
    }
}
