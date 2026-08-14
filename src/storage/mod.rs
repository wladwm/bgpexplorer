use crate::bgpattrs::BgpAttrs;
use crate::bgpsvc::{BgpSessionDesc, BgpSessionId};
use crate::timestamp::Timestamp;
use async_trait::async_trait;
use std::sync::Arc;
use zettabgp::prelude::BgpAddrs;

#[cfg(feature = "clickhouse")]
pub mod clickhouse;
#[cfg(feature = "mysql")]
pub mod mysql;
pub mod textfile;

enum StorageItem {
    Update((Timestamp, BgpSessionId, Arc<BgpAddrs>, Arc<BgpAttrs>)),
    Withdraw((Timestamp, BgpSessionId, Arc<BgpAddrs>)),
}
pub struct StorageQueue {
    pub storage: Arc<dyn Storage + std::marker::Send + std::marker::Sync + 'static>,
    tx: tokio::sync::mpsc::Sender<StorageItem>,
}
impl StorageQueue {
    pub fn new(
        storage: Arc<dyn Storage + std::marker::Send + std::marker::Sync + 'static>,
        queue_size: usize,
    ) -> StorageQueue {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<StorageItem>(queue_size);
        let strg = storage.clone();
        let _ = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    StorageItem::Update(q) => {
                        if let Err(e) = strg.store_update(q.1, q.3, q.0, &q.2).await {
                            warn!("storage.store_updates error: {:?}", e);
                        }
                    }
                    StorageItem::Withdraw(q) => {
                        if let Err(e) = strg.store_withdraw(q.1, q.0, &q.2).await {
                            warn!("storage.store_withdraw error: {:?}", e);
                        }
                    }
                }
            }
        });
        StorageQueue { storage, tx }
    }
    pub fn store_update(
        &self,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        v: Arc<BgpAddrs>,
    ) {
        if let Err(e) = self
            .tx
            .try_send(StorageItem::Update((when, session, v, rattr)))
        {
            error!(
                "Unable to store update({}/{}) - {:?}",
                self.tx.capacity(),
                self.tx.max_capacity(),
                e
            );
        }
    }
    pub fn store_withdraw(&self, session: BgpSessionId, when: Timestamp, v: Arc<BgpAddrs>) {
        if let Err(e) = self.tx.try_send(StorageItem::Withdraw((when, session, v))) {
            error!(
                "Unable to store withdraw({}/{}) - {:?}",
                self.tx.capacity(),
                self.tx.max_capacity(),
                e
            );
        }
    }
}

#[async_trait]
pub trait Storage {
    async fn open(&mut self) -> anyhow::Result<()>;
    async fn shutdown(&self) -> anyhow::Result<()>;
    async fn register_session(
        &self,
        sess: Arc<BgpSessionDesc>,
        offer: BgpSessionId,
    ) -> anyhow::Result<BgpSessionId>;
    async fn store_update(
        &self,
        session: BgpSessionId,
        rattr: Arc<BgpAttrs>,
        when: Timestamp,
        v: &BgpAddrs,
    ) -> anyhow::Result<()>;
    async fn store_withdraw(
        &self,
        session: BgpSessionId,
        when: Timestamp,
        v: &BgpAddrs,
    ) -> anyhow::Result<()>;
}

pub struct NoStorage {}
impl std::default::Default for NoStorage {
    fn default() -> Self {
        NoStorage {}
    }
}
#[async_trait]
impl Storage for NoStorage {
    async fn open(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn shutdown(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn register_session(
        &self,
        _sess: Arc<BgpSessionDesc>,
        offer: BgpSessionId,
    ) -> anyhow::Result<BgpSessionId> {
        Ok(offer)
    }
    async fn store_update(
        &self,
        _session: BgpSessionId,
        _rattr: Arc<BgpAttrs>,
        _when: Timestamp,
        _v: &BgpAddrs,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn store_withdraw(
        &self,
        _session: BgpSessionId,
        _when: Timestamp,
        _v: &BgpAddrs,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
