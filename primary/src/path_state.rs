// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::Certificate;
use crate::primary::Round;
use crypto::{Digest, PublicKey};
use std::collections::HashSet;

/// 路径状态：用于管理每条提案路径的状态
#[derive(Clone, Debug)]
pub struct PathState {
    /// 路径标识（节点公钥）
    pub path_id: PublicKey,
    
    /// 该路径最新的证书
    pub latest_certificate: Option<Certificate>,
    
    /// 该路径是否被冻结
    pub is_frozen: bool,
    
    /// 冻结发生的轮次
    pub freeze_round: Round,
    
    /// 可执行的 header digest 集合
    pub executable_headers: HashSet<Digest>,
}

impl PathState {
    /// 创建新的路径状态
    pub fn new(path_id: PublicKey) -> Self {
        Self {
            path_id,
            latest_certificate: None,
            is_frozen: false,
            freeze_round: 0,
            executable_headers: HashSet::new(),
        }
    }

    /// 更新最新证书
    pub fn update_latest_certificate(&mut self, certificate: Certificate) {
        self.latest_certificate = Some(certificate);
    }

    /// 标记 header 为可执行
    pub fn mark_executable(&mut self, digest: Digest) {
        self.executable_headers.insert(digest);
    }

    /// 检查 header 是否可执行
    pub fn is_executable(&self, digest: &Digest) -> bool {
        self.executable_headers.contains(digest)
    }

    /// 标记路径为冻结
    pub fn freeze(&mut self, freeze_round: Round) {
        self.is_frozen = true;
        self.freeze_round = freeze_round;
    }
}
