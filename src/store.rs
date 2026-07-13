//! Session and used-token stores. In-memory implementations back the traits
//! for v1; a durable store can be swapped in without touching handlers.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::domain::{SessionStatus, SigningSession, SigningSessionId};

/// Persistence boundary for signing sessions, keyed by session id.
pub trait SigningSessionStore: Send + Sync {
    fn insert(&self, session: SigningSession);
    fn get(&self, id: &SigningSessionId) -> Option<SigningSession>;
    fn update_status(&self, id: &SigningSessionId, status: SessionStatus, denial: Option<String>);
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory session store.
#[derive(Default)]
pub struct InMemSessionStore {
    sessions: RwLock<HashMap<String, SigningSession>>,
}

impl InMemSessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SigningSessionStore for InMemSessionStore {
    fn insert(&self, session: SigningSession) {
        self.sessions
            .write()
            .expect("session store lock poisoned")
            .insert(session.id.0.clone(), session);
    }

    fn get(&self, id: &SigningSessionId) -> Option<SigningSession> {
        self.sessions
            .read()
            .expect("session store lock poisoned")
            .get(&id.0)
            .cloned()
    }

    fn update_status(&self, id: &SigningSessionId, status: SessionStatus, denial: Option<String>) {
        if let Some(s) = self
            .sessions
            .write()
            .expect("session store lock poisoned")
            .get_mut(&id.0)
        {
            s.status = status;
            s.denial_reason = denial;
        }
    }

    fn len(&self) -> usize {
        self.sessions
            .read()
            .expect("session store lock poisoned")
            .len()
    }
}

/// Single-use enforcement for policy decision tokens.
///
/// `try_use` returns true exactly once per token id; subsequent calls (replay)
/// return false. Entries can be pruned once their token has expired.
pub trait UsedTokenStore: Send + Sync {
    fn try_use(&self, token_id: &str, expires_at_unix: u64) -> bool;
    fn prune(&self, now_unix: u64);
}

/// In-memory used-token store.
#[derive(Default)]
pub struct InMemUsedTokenStore {
    used: RwLock<HashMap<String, u64>>,
}

impl InMemUsedTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl UsedTokenStore for InMemUsedTokenStore {
    fn try_use(&self, token_id: &str, expires_at_unix: u64) -> bool {
        let mut used = self.used.write().expect("token store lock poisoned");
        if used.contains_key(token_id) {
            return false;
        }
        used.insert(token_id.to_string(), expires_at_unix);
        true
    }

    fn prune(&self, now_unix: u64) {
        self.used
            .write()
            .expect("token store lock poisoned")
            .retain(|_, exp| *exp > now_unix);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{unix_now, Chain, KeyId};

    fn session(id: &str) -> SigningSession {
        SigningSession {
            id: SigningSessionId(id.to_string()),
            key_id: KeyId("k1".into()),
            chain: Chain::Evm,
            request_hash: "abc".into(),
            status: SessionStatus::Pending,
            denial_reason: None,
            created_at_unix: unix_now(),
        }
    }

    #[test]
    fn session_store_crud() {
        let store = InMemSessionStore::new();
        assert!(store.is_empty());
        store.insert(session("s1"));
        assert_eq!(store.len(), 1);

        let got = store.get(&SigningSessionId("s1".into())).unwrap();
        assert_eq!(got.status, SessionStatus::Pending);

        store.update_status(
            &SigningSessionId("s1".into()),
            SessionStatus::Denied,
            Some("expired".into()),
        );
        let got = store.get(&SigningSessionId("s1".into())).unwrap();
        assert_eq!(got.status, SessionStatus::Denied);
        assert_eq!(got.denial_reason.as_deref(), Some("expired"));

        assert!(store.get(&SigningSessionId("missing".into())).is_none());
        // updating a missing session is a no-op
        store.update_status(
            &SigningSessionId("missing".into()),
            SessionStatus::Failed,
            None,
        );
    }

    #[test]
    fn used_token_single_use() {
        let store = InMemUsedTokenStore::new();
        assert!(store.try_use("t1", 100));
        assert!(!store.try_use("t1", 100));
        assert!(store.try_use("t2", 100));
    }

    #[test]
    fn used_token_prune() {
        let store = InMemUsedTokenStore::new();
        assert!(store.try_use("t1", 100));
        assert!(store.try_use("t2", 200));
        store.prune(150);
        // t1 expired and was pruned; but replays of pruned expired tokens are
        // rejected earlier by the freshness check, so re-use here is fine.
        assert!(store.try_use("t1", 300));
        assert!(!store.try_use("t2", 300));
    }

    #[test]
    fn used_token_concurrent_single_use() {
        use std::sync::Arc;
        let store = Arc::new(InMemUsedTokenStore::new());
        let mut handles = Vec::new();
        let successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..16 {
            let store = store.clone();
            let successes = successes.clone();
            handles.push(std::thread::spawn(move || {
                if store.try_use("same-token", u64::MAX) {
                    successes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(successes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
