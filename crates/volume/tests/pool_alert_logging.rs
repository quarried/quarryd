use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};
use volume::{FileVolume, PoolAlert, Volume, Volumes};

const MIB: u64 = 1024 * 1024;

#[derive(Default)]
struct LevelCounts
{
    info: AtomicUsize,
    warn: AtomicUsize,
    error: AtomicUsize,
}

impl LevelCounts
{
    fn snapshot(&self) -> (usize, usize, usize)
    {
        (
            self.info.load(Ordering::SeqCst),
            self.warn.load(Ordering::SeqCst),
            self.error.load(Ordering::SeqCst),
        )
    }
}

struct CountingSubscriber(Arc<LevelCounts>);

impl Subscriber for CountingSubscriber
{
    fn enabled(&self, _: &Metadata<'_>) -> bool
    {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id
    {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>)
    {
        let level = *event.metadata().level();
        let counter = if level == Level::ERROR
        {
            &self.0.error
        }
        else if level == Level::WARN
        {
            &self.0.warn
        }
        else if level == Level::INFO
        {
            &self.0.info
        }
        else
        {
            return;
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

#[tokio::test]
async fn pool_status_logs_alert_transitions()
{
    let counts = Arc::new(LevelCounts::default());
    let _guard = tracing::subscriber::set_default(CountingSubscriber(counts.clone()));
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FileVolume::new(dir.path().to_path_buf(), 100 * MIB));
    let volumes = Volumes::new(backend.clone());

    backend.create("a", 50 * MIB).await.unwrap();
    assert_eq!(
        volumes.pool_status().await.unwrap().alert,
        PoolAlert::Normal
    );
    assert_eq!(counts.snapshot(), (0, 0, 0));

    backend.create("b", 30 * MIB).await.unwrap();
    assert_eq!(
        volumes.pool_status().await.unwrap().alert,
        PoolAlert::Warning
    );
    assert_eq!(counts.snapshot(), (0, 1, 0));
    volumes.pool_status().await.unwrap();
    assert_eq!(counts.snapshot(), (0, 1, 0));

    backend.create("c", 10 * MIB).await.unwrap();
    assert_eq!(
        volumes.pool_status().await.unwrap().alert,
        PoolAlert::Critical
    );
    assert_eq!(counts.snapshot(), (0, 1, 1));
    volumes.pool_status().await.unwrap();
    assert_eq!(counts.snapshot(), (0, 1, 1));

    backend.delete("c").await.unwrap();
    backend.delete("b").await.unwrap();
    assert_eq!(
        volumes.pool_status().await.unwrap().alert,
        PoolAlert::Normal
    );
    assert_eq!(counts.snapshot(), (1, 1, 1));
}
