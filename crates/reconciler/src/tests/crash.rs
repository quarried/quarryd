use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

static ARMED: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());
static HIT: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());

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
