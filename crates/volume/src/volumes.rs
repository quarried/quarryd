use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::{PoolUsage, Volume, VolumeError, VolumeInfo};

pub const WARNING_PERCENT: f64 = 80.0;
pub const CRITICAL_PERCENT: f64 = 90.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolAlert
{
    Normal,
    Warning,
    Critical,
}

impl PoolAlert
{
    pub fn from_used_percent(used_percent: f64) -> PoolAlert
    {
        if used_percent >= CRITICAL_PERCENT
        {
            PoolAlert::Critical
        }
        else if used_percent >= WARNING_PERCENT
        {
            PoolAlert::Warning
        }
        else
        {
            PoolAlert::Normal
        }
    }

    fn to_code(self) -> u8
    {
        match self
        {
            PoolAlert::Normal => 0,
            PoolAlert::Warning => 1,
            PoolAlert::Critical => 2,
        }
    }

    fn from_code(code: u8) -> PoolAlert
    {
        match code
        {
            0 => PoolAlert::Normal,
            1 => PoolAlert::Warning,
            _ => PoolAlert::Critical,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PoolStatus
{
    pub usage: PoolUsage,
    pub alert: PoolAlert,
}

pub struct Volumes
{
    backend: Arc<dyn Volume>,
    last_alert: AtomicU8,
}

impl Volumes
{
    pub fn new(backend: Arc<dyn Volume>) -> Volumes
    {
        Volumes {
            backend,
            last_alert: AtomicU8::new(PoolAlert::Normal.to_code()),
        }
    }

    pub fn backend(&self) -> &Arc<dyn Volume>
    {
        &self.backend
    }

    pub async fn ensure(&self, name: &str, size_bytes: u64) -> Result<VolumeInfo, VolumeError>
    {
        if let Some(existing) = self.backend.get(name).await?
        {
            return Ok(existing);
        }
        self.admit().await?;
        self.backend.create(name, size_bytes).await
    }

    pub async fn ensure_blank(&self, name: &str, size_bytes: u64)
    -> Result<VolumeInfo, VolumeError>
    {
        if let Some(existing) = self.backend.get(name).await?
        {
            return Ok(existing);
        }
        self.admit().await?;
        self.backend.create_blank(name, size_bytes).await
    }

    pub async fn remove(&self, name: &str) -> Result<(), VolumeError>
    {
        self.backend.delete(name).await
    }

    pub async fn pool_status(&self) -> Result<PoolStatus, VolumeError>
    {
        let usage = self.backend.pool_usage().await?;
        let alert = PoolAlert::from_used_percent(usage.used_percent);
        let previous =
            PoolAlert::from_code(self.last_alert.swap(alert.to_code(), Ordering::SeqCst));
        if previous != alert
        {
            let used_percent = usage.used_percent;
            match alert
            {
                PoolAlert::Critical => tracing::error!(
                    used_percent,
                    "thin pool is at or above {CRITICAL_PERCENT}%; new volumes are refused"
                ),
                PoolAlert::Warning =>
                {
                    tracing::warn!(used_percent, "thin pool is at or above {WARNING_PERCENT}%")
                }
                PoolAlert::Normal => tracing::info!(
                    used_percent,
                    "thin pool usage is back below {WARNING_PERCENT}%"
                ),
            }
        }
        Ok(PoolStatus { usage, alert })
    }

    async fn admit(&self) -> Result<(), VolumeError>
    {
        let status = self.pool_status().await?;
        if status.alert == PoolAlert::Critical
        {
            return Err(VolumeError::PoolFull {
                used_percent: status.usage.used_percent,
            });
        }
        Ok(())
    }
}
