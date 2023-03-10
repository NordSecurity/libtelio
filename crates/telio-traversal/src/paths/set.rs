use futures::{
    future::{join_all, pending, select_all},
    FutureExt,
};
use telio_crypto::PublicKey;
use telio_model::{api_config::PathType, HashMap};
use telio_proto::DataMsg;
use telio_task::io::chan::{Rx, Tx};
use telio_utils::{telio_log_error, telio_log_warn};
use tokio::sync::mpsc::OwnedPermit;

use super::Path;

#[derive(Default)]
pub struct PathSet {
    pub prio: Vec<PathType>,
    pub paths: HashMap<PathType, Path>,
    pub changes: PathChanges,
    pub permits: PathPermits,
}

#[derive(Default)]
pub struct PathChanges {
    changes: HashMap<PathType, Rx<(PublicKey, bool)>>,
}

#[derive(Default)]
pub struct PathPermits {
    permits: HashMap<PathType, PathPermit>,
}

#[derive(Debug)]
struct PathPermit {
    perm: Option<OwnedPermit<(PublicKey, DataMsg)>>,
    tx: Tx<(PublicKey, DataMsg)>,
}

impl PathSet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_next(&mut self, path_type: PathType, mut path: Path) -> &mut Self {
        self.prio.push(path_type);
        self.permits.insert(path_type, &path);
        self.changes.insert(path_type, &mut path);
        self.paths.insert(path_type, path);
        self
    }
}

impl PathChanges {
    pub fn insert(&mut self, pt: PathType, path: &mut Path) {
        if let Some(change) = path.changes.take() {
            self.changes.insert(pt, change);
        }
    }

    pub async fn recv(&mut self) -> Option<(PathType, PublicKey, bool)> {
        if self.changes.is_empty() {
            return pending().await;
        }

        select_all(self.changes.iter_mut().map(|(pt, c)| {
            async move {
                let (pk, con) = c.recv().await?;
                Some((*pt, pk, con))
            }
            .boxed()
        }))
        .await
        .0
    }
}

impl PathPermits {
    pub fn insert(&mut self, pt: PathType, path: &Path) {
        self.permits.insert(
            pt,
            PathPermit {
                tx: path.channel.tx.clone(),
                perm: None,
            },
        );
    }

    pub async fn ready_all(&mut self) {
        join_all(self.permits.iter_mut().map(|(pt, p)| {
            async move {
                if p.perm.is_none() {
                    p.perm = p.tx.clone().reserve_owned().await.map_or_else(
                        |e| {
                            telio_log_error!("Failed to ready {:?}: {}", pt, e);
                            None
                        },
                        Some,
                    );
                }
            }
            .boxed()
        }))
        .await;
    }

    pub fn send(&mut self, to: PathType, msg: (PublicKey, DataMsg)) {
        if let Some(p) = self.permits.get_mut(&to) {
            if let Some(perm) = p.perm.take() {
                perm.send(msg);
            } else {
                telio_log_warn!("Send called on {:?} without ready_all, tx: {:?}", to, p.tx);
            }
        }
    }
}
