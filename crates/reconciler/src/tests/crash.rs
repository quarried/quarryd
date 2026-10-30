use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

static ARMED: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());
static HIT: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());
static DELAYED: Mutex<BTreeMap<(String, String), Duration>> = Mutex::new(BTreeMap::new());

pub fn delay(instance_id: &str, label: &str, duration: Duration)
{
    DELAYED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert((instance_id.to_owned(), label.to_owned()), duration);
}

pub fn arm(instance_id: &str, label: &str)
{
    ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert((instance_id.to_owned(), label.to_owned()));
}

pub fn hit(instance_id: &str, label: &str) -> bool
{
    let key = (instance_id.to_owned(), label.to_owned());
    let delay = DELAYED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&key);
    if let Some(delay) = delay
    {
        HIT.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone());
        // A slow external provisioning action finishes after the lease expires.
        // The fixture has four workers, so grants and test assertions can run
        // while this one supervisor is held at the external-action boundary.
        std::thread::sleep(delay);
    }
    let armed = ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&key);
    if armed
    {
        HIT.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
    }
    armed
}

pub fn was_hit(instance_id: &str, label: &str) -> bool
{
    HIT.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&(instance_id.to_owned(), label.to_owned()))
}
