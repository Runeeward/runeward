//! Shared Cohort memory: small, named, versioned notes every agent of a
//! Cohort can read and write, kept on disk in the control-plane state
//! (`cohort-memory/<cohort id>.json`), never inside a sandbox.
//!
//! Writes use optimistic concurrency: a put may name the version it
//! expects (`Some(0)`: the key must not exist yet) and fails with
//! `version_conflict` when another agent got there first. Every write is
//! attributed to the acting principal, size-capped, and Chronicled as tool
//! `memory`; when the Cohort's Charter redacts (`[chronicle] redact`, on by
//! default) the ledger holds a SHA-256 of the text instead of the text.
//!
//! Search ranks entries by tag match, key match, text match and recency,
//! and caps the result by bytes, so a fresh agent can be handed the most
//! relevant slice without replaying transcripts.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use runeward_charter::Verdict;
use runeward_ledger::Event;
use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::actor::actor_or;
use crate::error::{Error, Result};
use crate::fleet::Fleet;
use crate::manager::{Manager, blocking};
use crate::sessions::lock;
use crate::statefile::marshal_indent;
use crate::timefmt::nullable;

pub(crate) const MEMORY_DIR_NAME: &str = "cohort-memory";

/// Longest memory key, in bytes.
pub const MAX_MEMORY_KEY_BYTES: usize = 256;
/// Largest memory entry text, in bytes.
pub const MAX_MEMORY_TEXT_BYTES: usize = 16 << 10;
/// Most tags per entry.
pub const MAX_MEMORY_TAGS: usize = 16;
/// Longest tag, in bytes.
pub const MAX_MEMORY_TAG_BYTES: usize = 64;
/// Most entries per Cohort.
pub const MAX_MEMORY_ENTRIES: usize = 1_000;
/// Most text bytes per Cohort.
pub const MAX_MEMORY_TOTAL_BYTES: usize = 4 << 20;
/// Default byte budget of a search result or claim context slice.
pub const DEFAULT_MEMORY_SLICE_BYTES: usize = 8 << 10;
/// Most entries one search returns.
pub const MAX_MEMORY_RESULTS: usize = 100;

/// One shared memory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEntry {
    #[serde(default, deserialize_with = "nullable")]
    pub key: String,
    #[serde(default, deserialize_with = "nullable")]
    pub text: String,
    /// The principal that last wrote the entry.
    #[serde(default, deserialize_with = "nullable")]
    pub author: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tags: Vec<String>,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub created_at: Time,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub updated_at: Time,
    /// Starts at 1 and increases on every write.
    #[serde(default, deserialize_with = "nullable")]
    pub version: u64,
}

/// A memory write.
#[derive(Debug, Clone, Default)]
pub struct MemoryPut {
    pub key: String,
    pub text: String,
    pub tags: Vec<String>,
    /// `None` writes unconditionally; `Some(0)` requires the key to be new;
    /// `Some(n)` requires the current version to be `n`.
    pub expected_version: Option<u64>,
}

/// A memory search.
#[derive(Debug, Clone, Default)]
pub struct MemoryQuery {
    /// Free text matched against keys, tags and text.
    pub query: String,
    /// Entries with any of these tags rank higher (and, with no query,
    /// are the only ones returned).
    pub tags: Vec<String>,
    /// Most entries (default 20, at most 100).
    pub limit: usize,
    /// Byte budget for the returned texts (default 8 KiB).
    pub max_bytes: usize,
}

/// Lazily loaded per-Cohort memory.
#[derive(Debug, Default)]
pub(crate) struct MemoryStore {
    cohorts: tokio::sync::Mutex<HashMap<String, BTreeMap<String, MemoryEntry>>>,
}

fn valid_cohort_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Lowercase alphanumeric words of at least two characters.
pub(crate) fn terms(s: &str) -> Vec<String> {
    let mut out: Vec<String> = s
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 2)
        .map(str::to_lowercase)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Scores an entry: tag matches weigh most, then key matches, then text
/// matches; recency (decaying over days) breaks ties.
fn score(e: &MemoryEntry, terms: &[String], tags: &[String], now: Time) -> (f64, bool) {
    let etags: Vec<String> = e.tags.iter().map(|t| t.to_lowercase()).collect();
    let tag_hits = etags
        .iter()
        .filter(|t| tags.iter().any(|w| w == *t) || terms.iter().any(|w| w == *t))
        .count();
    let key = e.key.to_lowercase();
    let key_hits = terms.iter().filter(|t| key.contains(t.as_str())).count();
    let text = e.text.to_lowercase();
    let text_hits = terms.iter().filter(|t| text.contains(t.as_str())).count();
    let age_h = (now - e.updated_at).num_seconds().max(0) as f64 / 3600.0;
    let recency = 1.0 / (1.0 + age_h / 24.0);
    let matched = tag_hits + key_hits + text_hits > 0;
    #[allow(clippy::cast_precision_loss)]
    let s = 4.0 * tag_hits as f64 + 2.0 * key_hits as f64 + 0.5 * text_hits as f64 + recency;
    (s, matched)
}

/// Ranks `entries` for a query and keeps the best ones within the limits.
/// With `require_match`, entries that match nothing are dropped (unless
/// there is nothing to match against).
pub(crate) fn rank(
    entries: impl IntoIterator<Item = MemoryEntry>,
    q: &MemoryQuery,
    require_match: bool,
) -> Vec<MemoryEntry> {
    let now = gotime::now();
    let terms = terms(&q.query);
    let tags: Vec<String> = q.tags.iter().map(|t| t.trim().to_lowercase()).collect();
    let filtering = require_match && !(terms.is_empty() && tags.is_empty());
    let mut scored: Vec<(f64, MemoryEntry)> = entries
        .into_iter()
        .filter_map(|e| {
            let (s, matched) = score(&e, &terms, &tags, now);
            (!filtering || matched).then_some((s, e))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.total_cmp(&a.0)
            .then_with(|| b.1.updated_at.cmp(&a.1.updated_at))
            .then_with(|| a.1.key.cmp(&b.1.key))
    });
    let limit = match q.limit {
        0 => 20,
        n => n.min(MAX_MEMORY_RESULTS),
    };
    let budget = match q.max_bytes {
        0 => DEFAULT_MEMORY_SLICE_BYTES,
        n => n,
    };
    let mut used = 0;
    let mut out = Vec::new();
    for (_, e) in scored {
        if out.len() >= limit {
            break;
        }
        let size = e.text.len() + e.key.len();
        if used + size > budget {
            continue;
        }
        used += size;
        out.push(e);
    }
    out
}

fn validate_put(p: &MemoryPut) -> Result<()> {
    let key = p.key.trim();
    if key.is_empty() {
        return Err(Error::bad_input("memory key is required"));
    }
    if key.len() > MAX_MEMORY_KEY_BYTES || key.chars().any(char::is_control) {
        return Err(Error::bad_input(format!(
            "memory key must be at most {MAX_MEMORY_KEY_BYTES} bytes without control characters"
        )));
    }
    if p.text.len() > MAX_MEMORY_TEXT_BYTES {
        return Err(Error::bad_input(format!(
            "memory text exceeds {MAX_MEMORY_TEXT_BYTES} bytes"
        )));
    }
    if p.tags.len() > MAX_MEMORY_TAGS {
        return Err(Error::bad_input(format!(
            "at most {MAX_MEMORY_TAGS} tags per memory entry"
        )));
    }
    if p.tags.iter().any(|t| {
        t.trim().is_empty() || t.len() > MAX_MEMORY_TAG_BYTES || t.chars().any(char::is_control)
    }) {
        return Err(Error::bad_input(format!(
            "memory tags must be non-empty and at most {MAX_MEMORY_TAG_BYTES} bytes"
        )));
    }
    Ok(())
}

impl Manager {
    fn memory_fleet(&self, cohort: &str) -> Result<Arc<Fleet>> {
        if !valid_cohort_id(cohort) {
            return Err(Error::not_found(format!("cohort {cohort:?} not found")));
        }
        self.fleet(cohort)
            .ok_or_else(|| Error::not_found(format!("cohort {cohort:?} not found")))
    }

    /// Loads a Cohort's memory into `map` if it is not there yet.
    async fn ensure_memory_loaded(
        &self,
        map: &mut HashMap<String, BTreeMap<String, MemoryEntry>>,
        cohort: &str,
    ) -> Result<()> {
        if map.contains_key(cohort) {
            return Ok(());
        }
        let state = Arc::clone(&self.state);
        let name = format!("{cohort}.json");
        let data = blocking(move || Ok(state.read_in(MEMORY_DIR_NAME, &name)?)).await?;
        let entries: Vec<MemoryEntry> = match data {
            Some(d) => serde_json::from_slice::<Option<Vec<MemoryEntry>>>(&d)
                .map_err(|e| Error::other(format!("decode cohort memory: {e}")))?
                .unwrap_or_default(),
            None => Vec::new(),
        };
        map.insert(
            cohort.to_owned(),
            entries.into_iter().map(|e| (e.key.clone(), e)).collect(),
        );
        Ok(())
    }

    async fn save_memory(
        &self,
        cohort: &str,
        entries: &BTreeMap<String, MemoryEntry>,
    ) -> Result<()> {
        let data = marshal_indent(&entries.values().collect::<Vec<_>>())?;
        let state = Arc::clone(&self.state);
        let name = format!("{cohort}.json");
        blocking(move || state.write_in(MEMORY_DIR_NAME, &name, &data)).await
    }

    /// Whether a Cohort's Chronicle events must carry hashes instead of
    /// text (its Charter's `[chronicle] redact`; on when unknown).
    pub(crate) async fn fleet_redacts(&self, f: &Fleet) -> bool {
        let live = f
            .members()
            .iter()
            .find_map(|id| self.session_opt(id))
            .map(|s| s.charter.audit.redact_enabled());
        match live {
            Some(r) => r,
            None => self
                .load_profile(&f.profile)
                .await
                .map_or(true, |c| c.audit.redact_enabled()),
        }
    }

    /// Chronicles a Cohort context write (memory, notes, briefs) with the
    /// actor and tenant, hashing `text` when the Charter redacts.
    pub(crate) async fn record_context(
        &self,
        f: &Fleet,
        tool: &str,
        action: &str,
        args: Vec<String>,
        text: &str,
        extra: &[(&str, String)],
    ) {
        let mut ev = Event {
            session_id: format!("fleet:{}", f.id),
            profile: f.profile.clone(),
            tool: tool.into(),
            action: action.into(),
            args,
            verdict: Verdict::Allow.as_str().into(),
            ..Event::default()
        };
        ev.meta.insert("cohort".into(), f.id.clone());
        let actor = actor_or("");
        if !actor.is_empty() {
            ev.meta.insert("actor".into(), actor);
        }
        if !f.owner.is_empty() {
            ev.meta.insert("tenant".into(), f.owner.clone());
        }
        for (k, v) in extra {
            ev.meta.insert((*k).into(), v.clone());
        }
        if !text.is_empty() {
            ev.meta.insert("bytes".into(), text.len().to_string());
            if self.fleet_redacts(f).await {
                ev.meta.insert("text_sha256".into(), sha256_hex(text));
            } else {
                ev.meta.insert("text".into(), text.into());
            }
        }
        runeward_obs::record_action(tool, Verdict::Allow.as_str(), 0);
        self.append_audit(ev).await;
    }

    /// Writes a shared memory entry for a Cohort (see the module docs).
    pub async fn memory_put(&self, cohort: &str, put: MemoryPut) -> Result<MemoryEntry> {
        validate_put(&put)?;
        let f = self.memory_fleet(cohort)?;
        let key = put.key.trim().to_owned();
        let mut tags: Vec<String> = put.tags.iter().map(|t| t.trim().to_owned()).collect();
        tags.sort();
        tags.dedup();
        let author = actor_or("");
        let author = if author.is_empty() {
            "anonymous".to_owned()
        } else {
            author
        };
        let mut all = self.memory.cohorts.lock().await;
        self.ensure_memory_loaded(&mut all, cohort).await?;
        let entries = all.entry(cohort.to_owned()).or_default();
        let current = entries.get(&key).cloned();
        let have = current.as_ref().map_or(0, |e| e.version);
        if let Some(want) = put.expected_version
            && want != have
        {
            return Err(Error::conflict(
                "version_conflict",
                format!("memory {key:?} is at version {have}, not {want}"),
            ));
        }
        let total: usize = entries
            .values()
            .filter(|e| e.key != key)
            .map(|e| e.text.len())
            .sum();
        if total + put.text.len() > MAX_MEMORY_TOTAL_BYTES {
            return Err(Error::bad_input(format!(
                "cohort memory would exceed {MAX_MEMORY_TOTAL_BYTES} bytes"
            )));
        }
        if current.is_none() && entries.len() >= MAX_MEMORY_ENTRIES {
            return Err(Error::bad_input(format!(
                "cohort memory holds at most {MAX_MEMORY_ENTRIES} entries"
            )));
        }
        let now = gotime::now();
        let entry = MemoryEntry {
            key: key.clone(),
            text: put.text,
            author,
            tags,
            created_at: current.as_ref().map_or(now, |e| e.created_at),
            updated_at: now,
            version: have + 1,
        };
        entries.insert(key.clone(), entry.clone());
        if let Err(e) = self.save_memory(cohort, entries).await {
            match current {
                Some(c) => entries.insert(key, c),
                None => entries.remove(&key),
            };
            return Err(Error::other(format!("persist cohort memory: {e}")));
        }
        drop(all);
        let extra = [
            ("version", entry.version.to_string()),
            ("tags", entry.tags.join(",")),
        ];
        self.record_context(
            &f,
            "memory",
            "put",
            vec![entry.key.clone()],
            &entry.text,
            &extra,
        )
        .await;
        Ok(entry)
    }

    /// One memory entry, or `None`.
    pub async fn memory_get(&self, cohort: &str, key: &str) -> Result<Option<MemoryEntry>> {
        self.memory_fleet(cohort)?;
        let mut all = self.memory.cohorts.lock().await;
        self.ensure_memory_loaded(&mut all, cohort).await?;
        Ok(all.get(cohort).and_then(|m| m.get(key.trim())).cloned())
    }

    /// Deletes an entry (optionally only at `expected_version`); reports
    /// whether it existed.
    pub async fn memory_delete(
        &self,
        cohort: &str,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<bool> {
        let f = self.memory_fleet(cohort)?;
        let key = key.trim();
        let mut all = self.memory.cohorts.lock().await;
        self.ensure_memory_loaded(&mut all, cohort).await?;
        let entries = all.entry(cohort.to_owned()).or_default();
        let Some(current) = entries.get(key).cloned() else {
            return Ok(false);
        };
        if let Some(want) = expected_version
            && want != current.version
        {
            return Err(Error::conflict(
                "version_conflict",
                format!(
                    "memory {key:?} is at version {}, not {want}",
                    current.version
                ),
            ));
        }
        entries.remove(key);
        if let Err(e) = self.save_memory(cohort, entries).await {
            entries.insert(key.to_owned(), current);
            return Err(Error::other(format!("persist cohort memory: {e}")));
        }
        drop(all);
        let extra = [("version", current.version.to_string())];
        self.record_context(&f, "memory", "delete", vec![key.to_owned()], "", &extra)
            .await;
        Ok(true)
    }

    /// Ranked search over a Cohort's memory (see [`MemoryQuery`]).
    pub async fn memory_search(&self, cohort: &str, q: &MemoryQuery) -> Result<Vec<MemoryEntry>> {
        self.memory_fleet(cohort)?;
        let entries = self.memory_entries(cohort).await?;
        Ok(rank(entries, q, true))
    }

    /// Every entry of a Cohort's memory, by key.
    pub async fn memory_list(&self, cohort: &str) -> Result<Vec<MemoryEntry>> {
        self.memory_fleet(cohort)?;
        self.memory_entries(cohort).await
    }

    pub(crate) async fn memory_entries(&self, cohort: &str) -> Result<Vec<MemoryEntry>> {
        let mut all = self.memory.cohorts.lock().await;
        self.ensure_memory_loaded(&mut all, cohort).await?;
        Ok(all
            .get(cohort)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default())
    }

    /// Drops a removed Cohort's memory from memory and disk.
    pub(crate) async fn forget_memory(&self, cohort: &str) {
        self.memory.cohorts.lock().await.remove(cohort);
        if !valid_cohort_id(cohort) {
            return;
        }
        let state = Arc::clone(&self.state);
        let name = format!("{cohort}.json");
        if let Err(e) = blocking(move || Ok(state.remove_in(MEMORY_DIR_NAME, &name)?)).await {
            tracing::warn!(cohort = %cohort, error = %e, "runeward: remove cohort memory");
        }
    }

    /// Reports whether `id` names a live Cohort (for transports).
    pub fn cohort_exists(&self, id: &str) -> bool {
        lock(&self.fleets).contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, text: &str, tags: &[&str], hours_old: i64) -> MemoryEntry {
        let t = gotime::now() - chrono::Duration::hours(hours_old);
        MemoryEntry {
            key: key.into(),
            text: text.into(),
            author: "a".into(),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            created_at: t,
            updated_at: t,
            version: 1,
        }
    }

    #[test]
    fn ranks_tags_then_keys_then_recency_within_budget() {
        let entries = vec![
            entry("misc", "unrelated", &[], 0),
            entry("db-schema", "tables: users, orders", &[], 48),
            entry("conventions", "use rustfmt", &["db"], 72),
            entry("old-db-notes", "migrations live in db/", &[], 500),
        ];
        let q = MemoryQuery {
            query: "db migration".into(),
            ..MemoryQuery::default()
        };
        let got: Vec<String> = rank(entries.clone(), &q, true)
            .into_iter()
            .map(|e| e.key)
            .collect();
        assert_eq!(got, ["conventions", "old-db-notes", "db-schema"]);

        // Without a match requirement everything ranks; recency orders the
        // unmatched ones.
        let all: Vec<String> = rank(entries.clone(), &MemoryQuery::default(), false)
            .into_iter()
            .map(|e| e.key)
            .collect();
        assert_eq!(all[0], "misc");
        assert_eq!(all.len(), 4);

        let tight = MemoryQuery {
            query: "db".into(),
            max_bytes: 40,
            ..MemoryQuery::default()
        };
        let kept = rank(entries, &tight, true);
        let used: usize = kept.iter().map(|e| e.text.len() + e.key.len()).sum();
        assert!(used <= 40 && !kept.is_empty(), "{kept:?}");
    }

    #[test]
    fn validates_puts() {
        let ok = MemoryPut {
            key: "k".into(),
            text: "t".into(),
            ..MemoryPut::default()
        };
        assert!(validate_put(&ok).is_ok());
        for bad in [
            MemoryPut::default(),
            MemoryPut {
                key: "x".repeat(MAX_MEMORY_KEY_BYTES + 1),
                ..ok.clone()
            },
            MemoryPut {
                key: "a\nb".into(),
                ..ok.clone()
            },
            MemoryPut {
                text: "x".repeat(MAX_MEMORY_TEXT_BYTES + 1),
                ..ok.clone()
            },
            MemoryPut {
                tags: vec![String::new()],
                ..ok.clone()
            },
            MemoryPut {
                tags: (0..=MAX_MEMORY_TAGS).map(|i| i.to_string()).collect(),
                ..ok.clone()
            },
        ] {
            assert!(validate_put(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            terms("Fix the DB-migration, a b"),
            ["db", "fix", "migration", "the"]
        );
    }
}
