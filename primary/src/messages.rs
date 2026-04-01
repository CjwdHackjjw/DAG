// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// 冻结提案信息
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FreezeProposal {
    pub target_path: PublicKey,  // 被冻结的路径
    pub stall_round: Round,      // 停滞轮次
    pub observer: PublicKey,     // 观察节点
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: BTreeMap<Digest, WorkerId>,
    pub parents: BTreeSet<Digest>,
    pub id: Digest,
    pub signature: Signature,
    pub path_id: PublicKey,                      // 该节点的提案路径标识
    pub freeze_proposal: Option<FreezeProposal>, // 冻结提案信息
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: BTreeMap<Digest, WorkerId>,
        parents: BTreeSet<Digest>,
        signature_service: &mut SignatureService,
    ) -> Self {
        Self::new_with_freeze(author, round, payload, parents, None, signature_service).await
    }

    pub async fn new_with_freeze(
        author: PublicKey,
        round: Round,
        payload: BTreeMap<Digest, WorkerId>,
        parents: BTreeSet<Digest>,
        freeze_proposal: Option<FreezeProposal>,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            parents,
            id: Digest::default(),
            signature: Signature::default(),
            path_id: author,  // 默认路径 ID 就是作者
            freeze_proposal,
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id.clone()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure each authority only proposes on its own path.
        ensure!(self.path_id == self.author, DagError::MalformedHeader(self.id.clone()));

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        // Ensure all worker ids are correct.
        for worker_id in self.payload.values() {
            committee
                .worker(&self.author, &worker_id)
                .map_err(|_| DagError::MalformedHeader(self.id.clone()))?;
        }

        // Check the signature.
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(&self.path_id);
        hasher.update(self.round.to_le_bytes());
        for (x, y) in &self.payload {
            hasher.update(x);
            hasher.update(y.to_le_bytes());
        }
        for x in &self.parents {
            hasher.update(x);
        }
        if let Some(fp) = &self.freeze_proposal {
            hasher.update(&fp.target_path);
            hasher.update(fp.stall_round.to_le_bytes());
            hasher.update(&fp.observer);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({}, {})",
            self.id,
            self.round,
            self.author,
            self.payload.keys().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub signature: Signature,
    pub timestamp: u64,  // 投票者的本地时间戳（毫秒）
    pub freeze_support: bool,  // 是否支持冻结
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        Self::new_with_freeze(header, author, false, signature_service).await
    }

    pub async fn new_with_freeze(
        header: &Header,
        author: &PublicKey,
        freeze_support: bool,
        signature_service: &mut SignatureService,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let vote = Self {
            id: header.id.clone(),
            round: header.round,
            origin: header.author,
            author: *author,
            signature: Signature::default(),
            timestamp,
            freeze_support,
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.round,
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub header: Header,
    pub votes: Vec<(PublicKey, Signature)>,
    pub timestamp: u64,  // 所有投票时间戳的中位数
    pub freeze_votes: HashMap<PublicKey, bool>,  // 冻结投票结果（节点 -> 是否支持冻结）
    pub frozen_paths: HashSet<PublicKey>,  // 被冻结的节点路径集合
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|name| Self {
                header: Header {
                    author: *name,
                    path_id: *name,
                    ..Header::default()
                },
                ..Self::default()
            })
            .collect()
    }

    /// 计算时间戳中位数
    pub fn calculate_median_timestamp(timestamps: &[u64]) -> u64 {
        if timestamps.is_empty() {
            return 0;
        }
        let mut sorted = timestamps.to_vec();
        sorted.sort();
        sorted[sorted.len() / 2]
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        // Check the embedded header.
        self.header.verify(committee)?;

        // Ensure the certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(DagError::from)?;

        // Validate freeze metadata consistency.
        if self.header.freeze_proposal.is_some() {
            // freeze_votes must match certificate signers exactly when freeze proposal exists.
            ensure!(
                self.freeze_votes.len() == self.votes.len(),
                DagError::MalformedHeader(self.header.id.clone())
            );
            for (name, _) in &self.votes {
                ensure!(
                    self.freeze_votes.contains_key(name),
                    DagError::MalformedHeader(self.header.id.clone())
                );
            }

            let mut support_weight = 0;
            for (name, support) in &self.freeze_votes {
                if *support {
                    support_weight += committee.stake(name);
                }
            }

            if support_weight >= committee.quorum_threshold() {
                if let Some(fp) = &self.header.freeze_proposal {
                    ensure!(
                        self.frozen_paths.len() == 1 && self.frozen_paths.contains(&fp.target_path),
                        DagError::MalformedHeader(self.header.id.clone())
                    );
                }
            } else {
                ensure!(
                    self.frozen_paths.is_empty(),
                    DagError::MalformedHeader(self.header.id.clone())
                );
            }
        } else {
            ensure!(
                self.freeze_votes.is_empty() && self.frozen_paths.is_empty(),
                DagError::MalformedHeader(self.header.id.clone())
            );
        }

        Ok(())
    }

    pub fn round(&self) -> Round {
        self.header.round
    }

    pub fn origin(&self) -> PublicKey {
        self.header.author
    }
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header.id);
        hasher.update(self.round().to_le_bytes());
        hasher.update(&self.origin());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.digest(),
            self.round(),
            self.origin(),
            self.header.id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header.id == other.header.id;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}
