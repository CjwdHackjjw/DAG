// Copyright(C) Facebook, Inc. and its affiliates.
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use primary::{Certificate, Round};
use std::cmp::{max, Ordering};
use std::collections::{BinaryHeap, HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

/// DAG 在内存中的表示：
/// 外层 key 是轮次（Round），内层 key 是提案路径标识（节点公钥），
/// value 是 (证书摘要, 证书) 的元组。
type Dag = HashMap<Round, HashMap<PublicKey, (Digest, Certificate)>>;

/// 可执行 Header 的包装结构，用于放入时间戳最小堆。
/// 当一个 header 对应的 certificate 到来后，其同路径的前驱 header
/// 会被标记为"可执行"，并以此结构加入排序队列。
#[derive(PartialEq, Clone)]
struct ExecutableHeader {
    /// 该 header 对应 certificate 的时间戳中位数（毫秒）
    timestamp: u64,
    /// 该 header 所在轮次
    round: Round,
    /// 所属提案路径（节点公钥）
    path_id: PublicKey,
    /// header 的摘要
    digest: Digest,
    /// 完整证书，用于最终输出
    certificate: Certificate,
}

impl Ord for ExecutableHeader {
    fn cmp(&self, other: &Self) -> Ordering {
        // Rust 的 BinaryHeap 是最大堆，这里反转比较使时间戳最小的在堆顶，
        // 即优先处理时间戳最早的可执行 header。
        // 时间戳相同时，轮次更高的优先（更新的提案优先判定）。
        other.timestamp.cmp(&self.timestamp)
            .then_with(|| other.round.cmp(&self.round))
    }
}

impl PartialOrd for ExecutableHeader {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for ExecutableHeader {}

/// 每条提案路径的共识状态。
/// 每个节点负责一条路径，共识层为每条路径独立维护此状态。
struct PathState {
    /// 路径标识（对应节点的公钥）
    path_id: PublicKey,
    /// 该路径是否已被冻结（节点宕机后经过观察节点冻结提案通过）
    is_frozen: bool,
    /// 冻结生效的轮次（该轮次及之后的 header 不再参与共识）
    freeze_round: Round,
    /// 已标记为可执行的 header 集合：digest -> (round, timestamp, certificate)
    /// 可执行 = 该 header 的下一轮同路径证书已到来
    executable_headers: HashMap<Digest, (Round, u64, Certificate)>,
    /// 当前已知最高轮次的可执行 header 的轮次
    highest_executable_round: Round,
    /// 当前已知最高轮次的可执行 header 的摘要（用于共识判定）
    highest_executable_digest: Option<Digest>,
}

impl PathState {
    fn new(path_id: PublicKey) -> Self {
        Self {
            path_id,
            is_frozen: false,
            freeze_round: 0,
            executable_headers: HashMap::new(),
            highest_executable_round: 0,
            highest_executable_digest: None,
        }
    }

    /// 将指定证书对应的 header 标记为可执行，并更新最高轮次记录。
    fn mark_executable(&mut self, cert: &Certificate) {
        let digest = cert.header.id.clone();
        let round = cert.round();
        let timestamp = cert.timestamp;
        self.executable_headers.insert(digest.clone(), (round, timestamp, cert.clone()));
        // 只更新最高轮次记录，旧轮次的可执行 header 仍保留在集合中
        if round > self.highest_executable_round {
            self.highest_executable_round = round;
            self.highest_executable_digest = Some(digest);
        }
    }

    /// 判断某个 header（通过摘要标识）是否已被标记为可执行。
    fn is_executable(&self, digest: &Digest) -> bool {
        self.executable_headers.contains_key(digest)
    }

    /// 冻结该路径：从 freeze_round 起不再参与共识判定。
    fn freeze(&mut self, freeze_round: Round) {
        self.is_frozen = true;
        self.freeze_round = freeze_round;
    }
}

/// 共识全局状态，包含 DAG 视图、各路径状态、可执行队列和已提交记录。
struct State {
    /// 全网已提交的最高轮次（所有路径的最大值）
    last_committed_round: Round,
    /// 各路径已提交的最高轮次
    last_committed: HashMap<PublicKey, Round>,
    /// 内存中的 DAG：存储所有已收到的证书，按轮次和路径索引
    dag: Dag,
    /// 各路径的独立状态
    path_states: HashMap<PublicKey, PathState>,
    /// 可执行 header 的时间戳排序队列（最小堆，堆顶为时间戳最早的）
    executable_queue: BinaryHeap<ExecutableHeader>,
    /// 已提交（已执行）的 header 摘要集合，防止重复提交
    executed: HashSet<Digest>,
}

impl State {
    /// 用创世证书初始化共识状态。
    /// 创世证书代表每条路径在 round=0 的起点，不参与提交，但用于 DAG 初始化。
    fn new(genesis: Vec<Certificate>) -> Self {
        let genesis_map = genesis
            .into_iter()
            .map(|x| (x.origin(), (x.digest(), x)))
            .collect::<HashMap<_, _>>();
        // 为每条路径初始化 PathState
        let mut path_states = HashMap::new();
        for (name, _) in &genesis_map {
            path_states.insert(*name, PathState::new(*name));
        }
        Self {
            last_committed_round: 0,
            last_committed: genesis_map.iter().map(|(x, (_, y))| (*x, y.round())).collect(),
            // DAG 第 0 轮存放所有创世证书
            dag: [(0, genesis_map)].iter().cloned().collect(),
            path_states,
            executable_queue: BinaryHeap::new(),
            executed: HashSet::new(),
        }
    }

    /// 当新证书到来时，递归地将该证书同路径的前驱 header 标记为可执行。
    ///
    /// 核心逻辑：
    /// - 一个 header 在"其同路径的下一轮证书到来"时变为可执行
    /// - 例如：A3 的证书到来 → A2 变为可执行 → 递归检查 A2 的 parent 中同路径的 A1
    /// - 只处理同路径（path_id 相同）的前驱，不同路径的引用仅用于网络同步
    /// - 递归终止条件：遇到已经是可执行的 header（避免重复处理）
    fn update_executable(&mut self, cert: &Certificate, queue: &mut BinaryHeap<ExecutableHeader>) {
        let cur_round = cert.round();
        let cur_path = cert.header.path_id;

        for parent_digest in &cert.header.parents {
            // 同路径的前驱 parent 一定在 cur_round-1 轮次：
            // 每个节点只在自己路径上提案，且必须等自己路径上一轮证书到来才能提案，
            // 因此同路径 parent 轮次严格等于 cur_round-1。
            // 不同路径的 parent 可能来自任意轮次，但不触发可执行性更新（只用于网络同步）。
            let parent_cert = self.dag
                .get(&(cur_round.saturating_sub(1)))
                .and_then(|m| m.values().find(|(d, _)| d == parent_digest))
                .map(|(_, c)| c.clone());

            if let Some(pc) = parent_cert {
                // 只处理同路径的前驱
                if pc.header.path_id == cur_path {
                    let hdr_digest = pc.header.id.clone();
                    let ps = self.path_states
                        .entry(cur_path)
                        .or_insert_with(|| PathState::new(cur_path));
                    if !ps.is_executable(&hdr_digest) {
                        ps.mark_executable(&pc);
                        queue.push(ExecutableHeader {
                            timestamp: pc.timestamp,
                            round: pc.round(),
                            path_id: cur_path,
                            digest: hdr_digest,
                            certificate: pc.clone(),
                        });
                        // 递归：检查 parent 的同路径前驱是否也应变为可执行
                        self.update_executable(&pc, queue);
                    }
                }
            }
        }
    }

    /// 处理冻结结果：当某条路径被冻结时，确保其最后一个有效 header 被标记为可执行，
    /// 然后正式冻结该路径。
    /// 规则：停滞轮次为 i，冻结轮次为 i+1。
    /// 冻结通过时必须确保 i-1 轮的 header 已标记为可执行（保证历史提案不丢失）。
    fn apply_frozen_paths(&mut self, cert: &Certificate, queue: &mut BinaryHeap<ExecutableHeader>) {
        let fp = match &cert.header.freeze_proposal {
            Some(fp) => fp.clone(),
            None => return, // 该证书不含冻结提案，跳过
        };
        for frozen_path in &cert.frozen_paths {
            // 步骤1：确保 stall_round-1 的 header 已变为可执行
            // （若节点在 i 轮停滞，则 i-1 轮的 header 是其最后一个有效 header）
            if fp.stall_round > 0 {
                let prev = self.dag
                    .get(&(fp.stall_round.saturating_sub(1)))
                    .and_then(|m| m.get(frozen_path))
                    .map(|(_, c)| c.clone());
                if let Some(prev_cert) = prev {
                    let ps = self.path_states
                        .entry(*frozen_path)
                        .or_insert_with(|| PathState::new(*frozen_path));
                    if !ps.is_executable(&prev_cert.header.id) {
                        ps.mark_executable(&prev_cert);
                        queue.push(ExecutableHeader {
                            timestamp: prev_cert.timestamp,
                            round: prev_cert.round(),
                            path_id: *frozen_path,
                            digest: prev_cert.header.id.clone(),
                            certificate: prev_cert,
                        });
                    }
                }
            }
            // 步骤2：正式冻结该路径，freeze_round = stall_round + 1
            // 此后该路径在 freeze_round 及之后的 header 不再参与共识
            let ps = self.path_states
                .entry(*frozen_path)
                .or_insert_with(|| PathState::new(*frozen_path));
            ps.freeze(fp.stall_round + 1);
            debug!("Path {:?} frozen at round {}", frozen_path, fp.stall_round + 1);
        }
    }

    /// 判断一条已冻结路径上的所有可执行 header 是否都已被提交。
    /// 若是，则该路径可以从共识判定中完全排除。
    fn is_frozen_fully_executed(&self, path_id: &PublicKey) -> bool {
        match self.path_states.get(path_id) {
            Some(ps) if ps.is_frozen =>
                ps.executable_headers.keys().all(|d| self.executed.contains(d)),
            _ => false,
        }
    }

    /// 共识判定：尝试提交一批已排序的可执行 header。
    ///
    /// 判定流程：
    /// 1. 前置条件：所有参与判定的路径（未冻结完毕的路径）都必须有可执行 header，
    ///    否则说明某条路径还未推进到足够轮次，跳过本次判定（等待更多证书到来）。
    /// 2. 从各路径的"最高轮次可执行 header"中，选时间戳最早的作为提交目标（target）。
    ///    时间戳相同时选轮次更高的（更新的提案）。
    /// 3. 从排序队列中取出 target 及所有时间戳 ≤ target 的未执行 header，
    ///    组成本次执行集合。这保证了"集合外的 header 一定比集合内的更晚提出"。
    /// 4. 按时间戳升序提交执行集合，更新已提交记录。
    fn try_commit(&mut self) -> Vec<Certificate> {
        // 步骤1：前置条件检查
        // 遍历所有路径，确保每条参与判定的路径都有可执行 header。
        // "参与判定"的路径 = 未冻结的路径 + 冻结但还有未执行 header 的路径。
        for (path_id, ps) in &self.path_states {
            if ps.is_frozen && self.is_frozen_fully_executed(path_id) {
                continue; // 已冻结且全部执行完毕，从判定中排除
            }
            if ps.highest_executable_digest.is_none() {
                // 该路径还没有任何可执行 header，等待其证书到来后再判定
                return Vec::new();
            }
        }

        // 步骤2：选出提交目标（target）
        // 遍历各路径，取每条路径"最高轮次的可执行 header"，
        // 从中选时间戳最早的作为 target。
        // 语义：target 是当前所有路径中"最滞后但最早提出"的 header，
        // 它之前的所有 header 都可以安全提交（因为 target 已被多数节点见到）。
        let mut target: Option<ExecutableHeader> = None;
        for (path_id, ps) in &self.path_states {
            if ps.is_frozen && self.is_frozen_fully_executed(path_id) {
                continue;
            }
            if let Some(d) = &ps.highest_executable_digest {
                if let Some((round, timestamp, cert)) = ps.executable_headers.get(d) {
                    let candidate = ExecutableHeader {
                        timestamp: *timestamp,
                        round: *round,
                        path_id: *path_id,
                        digest: d.clone(),
                        certificate: cert.clone(),
                    };
                    let replace = match &target {
                        None => true,
                        // 优先选时间戳更早的；时间戳相同时选轮次更高的
                        Some(t) => candidate.timestamp < t.timestamp
                            || (candidate.timestamp == t.timestamp && candidate.round > t.round),
                    };
                    if replace { target = Some(candidate); }
                }
            }
        }

        let target = match target {
            Some(t) => t,
            None => return Vec::new(),
        };

        // target 已经执行过则跳过（防止重复提交）
        if self.executed.contains(&target.digest) {
            return Vec::new();
        }

        // 步骤3：构建执行集合
        // 从时间戳排序队列中取出所有时间戳 ≤ target.timestamp 的未执行 header，
        // 连同 target 本身组成执行集合。
        // 保证：执行集合之外的 header 时间戳都比 target 更大，即更晚提出。
        let mut execution_set: Vec<ExecutableHeader> = Vec::new();
        let mut remaining = BinaryHeap::new();
        while let Some(e) = self.executable_queue.pop() {
            let before_target = e.timestamp < target.timestamp
                || (e.timestamp == target.timestamp && e.round <= target.round);
            if before_target {
                if !self.executed.contains(&e.digest) {
                    execution_set.push(e);
                }
            } else {
                // 时间戳更大的留在队列中，等下次判定
                remaining.push(e);
            }
        }
        self.executable_queue = remaining;

        // 确保 target 本身在执行集合中（可能 target 不在队列里而是直接从 path_states 选出）
        if !execution_set.iter().any(|e| e.digest == target.digest) {
            if !self.executed.contains(&target.digest) {
                execution_set.push(target);
            }
        }

        // 步骤4：按时间戳升序排序后提交
        // 时间戳相同时按轮次升序（确定性排序）
        execution_set.sort_by_key(|e| (e.timestamp, e.round));
        let certs: Vec<Certificate> = execution_set.iter().map(|e| e.certificate.clone()).collect();

        // 更新已提交记录
        for e in &execution_set {
            self.executed.insert(e.digest.clone());
            self.last_committed
                .entry(e.path_id)
                .and_modify(|r| *r = max(*r, e.round))
                .or_insert(e.round);
        }
        self.last_committed_round = *self.last_committed.values().max().unwrap_or(&0);
        certs
    }
}

/// 共识引擎主结构。
/// 接收来自 primary 层的证书，维护 DAG 和路径状态，
/// 按时间戳顺序输出已提交的证书序列。
pub struct Consensus {
    /// 委员会配置（包含所有节点信息）
    committee: Committee,
    /// 垃圾回收深度：超过此深度的旧轮次数据可以清理
    gc_depth: Round,
    /// 接收来自 primary core 的证书
    rx_primary: Receiver<Certificate>,
    /// 向 primary core 回传已提交的证书（用于触发 GC）
    tx_primary: Sender<Certificate>,
    /// 向上层应用输出已提交的证书序列
    tx_output: Sender<Certificate>,
    /// 创世证书集合（每条路径各一个，round=0）
    genesis: Vec<Certificate>,
}

impl Consensus {
    /// 启动共识引擎（在独立 tokio 任务中运行）。
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
    ) {
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                gc_depth,
                rx_primary,
                tx_primary,
                tx_output,
                genesis: Certificate::genesis(&committee),
            }
            .run()
            .await;
        });
    }

    /// 共识主循环：持续接收证书并驱动共识推进。
    async fn run(&mut self) {
        let mut state = State::new(self.genesis.clone());

        while let Some(certificate) = self.rx_primary.recv().await {
            debug!("Processing {:?}", certificate);
            let round = certificate.round();
            let origin = certificate.origin();

            // 步骤1：将新证书加入 DAG
            // 按轮次和路径索引存储，供 update_executable 递归查找使用
            state
                .dag
                .entry(round)
                .or_insert_with(HashMap::new)
                .insert(origin, (certificate.digest(), certificate.clone()));

            // 步骤2：处理冻结结果
            // 若该证书包含冻结提案且超过 2f+1 节点支持，则冻结对应路径
            if !certificate.frozen_paths.is_empty() {
                let cert_clone = certificate.clone();
                let mut tmp_queue = BinaryHeap::new();
                state.apply_frozen_paths(&cert_clone, &mut tmp_queue);
                // 将新增的可执行 header 合并到全局排序队列
                for e in tmp_queue { state.executable_queue.push(e); }
            }

            // 步骤3：更新同路径前驱的可执行性
            // 新证书到来意味着其同路径的前驱 header 可以变为可执行
            let mut tmp_queue = BinaryHeap::new();
            state.update_executable(&certificate, &mut tmp_queue);
            for e in tmp_queue { state.executable_queue.push(e); }

            // 步骤4：尝试共识判定
            // 检查是否满足提交条件（所有路径都有可执行 header），若满足则提交
            let sequence = state.try_commit();

            if sequence.is_empty() {
                continue; // 条件不满足，等待更多证书
            }

            // 步骤5：输出已提交的证书序列
            for cert in sequence {
                #[cfg(not(feature = "benchmark"))]
                info!("Committed {}", cert.header);

                // benchmark 模式下记录每个 payload digest，用于性能分析
                #[cfg(feature = "benchmark")]
                for digest in cert.header.payload.keys() {
                    info!("Committed {} -> {:?}", cert.header, digest);
                }

                // 通知 primary core 该证书已提交（触发垃圾回收）
                self.tx_primary
                    .send(cert.clone())
                    .await
                    .expect("Failed to send certificate to primary");

                // 输出给上层应用
                if let Err(e) = self.tx_output.send(cert).await {
                    warn!("Failed to output certificate: {}", e);
                }
            }
        }
    }
}
