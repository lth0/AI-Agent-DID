# AgentDID 三方案、63 项独立安全实验：逐步学习与改造手册

## 1. 文档用途

本文把“21 个场景 × 3 个方案 = 63 个独立实验”的整体改造拆成可以逐次学习、逐次修改、逐次验证的小步骤。建议每次只做一个步骤；本步验证通过后，再在自己的分支上提交一次小型 commit，然后进入下一步。

本文是执行清单，不是最终完成报告。下表记录当前已复核状态；其余步骤仍按待执行处理。即使仓库中已经存在同名文件或部分实现，也必须按该步骤的验证命令重新核验，不能仅凭文件存在就标记完成。

第一里程碑明确命名为：**三方案协议与适配器**。该里程碑只在步骤 007 至步骤 039 的代码、链上解析接线、在线入口接线与测试全部通过后完成。当前已完成三方案核心、本地 Hardhat DID 注册与真实解析，以及代表性链上实验；在线入口和完整 63 项执行仍待后续步骤验收。

## 当前执行状态（2026-07-20）

| 范围 | 当前状态 | 当前证据或缺口 |
|---|---|---|
| 共享内存 DID/VC/VP 协议核心 | 已完成并复核 | infrastructure/agentdid_protocol.py；14 个 unittest 通过 |
| 三个显式 Adapter | 已完成并复核 | Original、Baseline、Lineage 三个正式 Adapter；7 个 unittest 通过 |
| A04 真实独立能力评测 | 已完成并复核 | integer-addition-v1 实际执行 100 个确定性样例，再与能力 VC 交叉核验 |
| A05 当前状态策略 | 已完成并复核 | 有效签名状态与真实工件摘要不一致时由 Baseline 层拒绝 |
| A06 上下文连续性策略 | 已完成并复核 | 有效签名的新快照若重置哈希或版本，由 Baseline 层拒绝 |
| L01-L14 同语义控制场景 | 已完成无链版本并复核 | 21 场景均生成签名控制材料；4 个场景 unittest 通过；尚未接真实 Lineage 链执行 |
| 证据哈希链与 Merkle 路径绑定 | 已完成并复核 | 2 个 unittest 验证 audit 前序哈希链，以及文件路径和内容共同进入 Merkle 叶子 |
| Hardhat DID 链上注册与解析 | 已完成并复核 | 通过 did-resolver 与 ethr-did-resolver 解析链上注册和 delegate；1 个真实 Hardhat 集成测试通过 |
| 当前新增测试合计 | 已完成并复核 | 协议 14 + Adapter 7 + 场景 4 + 证据 2 + Hardhat DID 1 = 28，目标 Conda 环境中 Ran 28 tests，OK |
| 代表性三方案端到端实验 | 已完成并复核 | H00、A02、A04、L01 × 3 方案共 12 项；均为 COMPLETED，预期判定一致，12 个独立 Merkle 根与 12 次 Hardhat 锚定均可反向核验 |
| Sepolia DID 链上注册与解析 | 待完成 | Registry 预检、解析和禁止回退尚待接线 |
| 在线 /auth、/probe、/context_hash 接线 | 待完成 | 当前三方案核心尚未完整接入在线演示入口 |
| run_all 与 63 个独立子进程 | 待完成 | 尚未形成可验收的 21 × 3 独立进程运行 |
| 63 个独立 Merkle 根与链上锚定 | 待完成 | 代表性 12 项已锚定；完整矩阵尚缺其余 51 项 |
| 第一里程碑“三方案协议与适配器” | **尚未完整验收** | 三方案核心、本地链 DID 解析和代表性端到端链路已完成；在线入口、Sepolia 与步骤 039 全量门槛仍未通过 |

当前 28 个新增测试的 PowerShell 复核命令为：

    conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.test_agentdid_protocol _experiments.security_comparison.test_three_schemes _experiments.security_comparison.test_scenarios _experiments.security_comparison.test_evidence
    conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.test_hardhat_did_resolution

## 2. 全程不可破坏的约束

1. 正式矩阵只包含 Original-AgentDID、Baseline-AgentDID、Lineage-AgentDID。
2. Shared-Root、ACL、OpenFGA、Plain-Delegation 可以保留作历史代码或兼容入口，但不得进入正式 63 项结果。
3. 三个方案必须先运行完全相同的 DID/VC/VP 协议验证，然后才进入各自策略层。
4. A01 至 A03 必须在共享协议层拒绝；A04 至 A06 必须保持密码学有效，只由 Baseline 及 Lineage 的严格语义层拒绝。
5. L01 至 L14 必须保持 DID、VC、VP 与 Baseline 宽权限策略有效，只由 Lineage 层拒绝。
6. 每项实验必须由独立子进程运行，并拥有独立 nonce、VC ID、VP、ReplayGuard、上下文、请求哈希、Lineage 子密钥、credential JTI、epoch 和预算 ID。
7. 每项实验无论接受还是安全拒绝，都必须生成完整链下证据、独立 Merkle 根，并完成一次链上锚定。
8. INFRA_ERROR 只表示基础设施失败，不能当作攻击被阻止，也不能计入 PESR 分母。
9. 本地模式只使用 Hardhat；Sepolia 模式禁止自动回退本地链。
10. 任何结果、PESR、HAR、延迟、Gas 或交易数量都必须由实际输出计算，不能在运行时代码中硬编码。

## 3. 固定预期向量

| 场景组 | Original-AgentDID | Baseline-AgentDID | Lineage-AgentDID |
|---|---:|---:|---:|
| H00 合法请求 | 接受 | 接受 | 接受 |
| A01-A03 身份或重放攻击 | 拒绝 | 拒绝 | 拒绝 |
| A04-A06 语义、状态或上下文攻击 | 接受 | 拒绝 | 拒绝 |
| L01-L14 谱系攻击 | 接受 | 接受 | 拒绝 |

攻击总数为 20，不包含 H00。若 20 个攻击均完成且无 INFRA_ERROR，预期攻击接受数分别为 17、14、0，因此预期 PESR 分别为 17/20、14/20、0/20。预期值只用于测试断言和最终对照，实际汇总必须读取 decision.json 计算。

## 4. 每步执行方式

每步固定包含六项：

- 学习目标：本步要理解的安全或工程概念。
- 本步只修改：严格限制本次改动范围。
- 具体改动：按顺序实施的代码动作。
- 验证命令：本步完成后立即执行。
- 预期结果：验证输出应达到的状态。
- 完成条件：可以提交本步并进入下一步的唯一门槛。

所有命令均按 PowerShell 写法给出，并默认在 D:\experinment\AgentDID 执行。Python 命令统一优先使用 agentdid Conda 环境、-B 和标准库 unittest，不依赖未安装的 pytest。尚未创建的测试模块仍先按文中路径创建，再使用对应 unittest module 或 discover 命令；测试选择器可以随最终测试函数命名微调，但不得用跳过测试代替修复。Windows 下 Hardhat 命令统一使用 npx.cmd。

## 阶段 0：锁定基线与边界

### 步骤 001：建立只读基线清单

- **学习目标**：理解改造前已有入口、测试、协议代码、Lineage 代码与合约之间的关系。
- **本步只修改**：仅修改本文档中的个人执行勾选；不修改任何 Python、Solidity 或配置文件。
- **具体改动**：用 rg --files 列出 infrastructure、agents、_demo_2v2、_experiments、contracts、config；记录已有 security_comparison 文件；记录旧入口与测试位置。
- **验证命令**：

      rg --files infrastructure agents _demo_2v2 _experiments contracts config

- **预期结果**：能够定位 infrastructure/validator.py、infrastructure/lineage、_demo_2v2/start_network.py、_demo_2v2/trigger_audit.py、_experiments/security_reproduction、_experiments/lineage 与 contracts/AgentLineageRegistry.sol。
- **完成条件**：对每个目标模块都能说明“复用、补齐、迁移或退出正式结果”中的哪一种处理方式。

---

### 步骤 002：记录当前回归测试基线

- **学习目标**：学会把“原有功能未被破坏”转换为可重复的测试证据。
- **本步只修改**：仅允许把测试日志写到 .codex/baseline；不改业务代码。
- **具体改动**：分别运行 Lineage Python、AgentDID 安全与 Hardhat 合约测试；记录通过、失败、跳过和测试数量；已有失败必须单独登记，不能在后续归因给新方案。
- **验证命令**：

      conda run -n agentdid python -B -m unittest discover -s _experiments/lineage -p "test_*.py" -v
      conda run -n agentdid python -B -m unittest discover -s _experiments/security_reproduction -p "test_*.py" -v
      npx.cmd hardhat test

- **预期结果**：得到三组可追溯基线；目标基线为 23 个 Lineage Python、14 个 AgentDID 安全与 9 个合约测试继续通过。
- **完成条件**：基线结果已保存，并能区分“改造前失败”和“改造后回归”。

---

### 步骤 003：固定三方案和 21 场景词汇

- **学习目标**：理解“方案”“场景”“实验”三个层级，避免把 21 场景误写成 63 个共享状态分支。
- **本步只修改**：_experiments/security_comparison/cases.py。
- **具体改动**：定义三个稳定方案键 original、baseline、lineage；定义显示名称；定义 H00、A01-A06、L01-L14；为每个 CaseSpec 记录 family、attack_name、说明与预期检测层。
- **验证命令**：

      conda run -n agentdid python -B -c "from _experiments.security_comparison.cases import CASES, SCHEMES; print(len(CASES), len(SCHEMES), len(CASES)*len(SCHEMES))"

- **预期结果**：输出 21、3、63；case_id 无重复且顺序稳定。
- **完成条件**：场景目录键、CLI 键和汇总键都只引用这一个目录源。

---

### 步骤 004：定义稳定错误码与终态

- **学习目标**：理解安全拒绝与基础设施失败必须在数据模型上分离。
- **本步只修改**：_experiments/security_comparison/models.py 或现有等价模型文件。
- **具体改动**：定义 COMPLETED、INFRA_ERROR 等执行状态；定义 ACCEPT、REJECT 决策；为 DID、VC、VP、Baseline、Lineage、ANCHOR、INFRA 各层建立稳定错误码前缀；禁止用异常文本代替错误码。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_models

- **预期结果**：合法决策、策略拒绝和基础设施错误可被序列化并明确区分。
- **完成条件**：汇总器无需解析自然语言 reason 就能判断终态和检测层。

---

### 步骤 005：定义单实验输入与输出模型

- **学习目标**：理解父进程与独立子进程之间需要稳定的数据契约。
- **本步只修改**：_experiments/security_comparison/models.py。
- **具体改动**：增加 ExperimentConfig、ExperimentResult、SchemeDecision、ChainReceiptRef；明确 run_id、experiment_id、scheme、case_id、chain_mode、seed、output_dir、状态、错误码和计时字段；对未知字段采用显式版本控制。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_models

- **预期结果**：模型能够 JSON 往返，缺失必填字段时稳定失败。
- **完成条件**：run_one 的输入和 decision.json 的输出不再依赖进程内对象。

---

### 步骤 006：集中链模式配置

- **学习目标**：理解本地链与 Sepolia 的差异应由配置对象表达，而不是散落的 if 语句。
- **本步只修改**：_experiments/security_comparison/chain.py 与 config 中专用示例配置。
- **具体改动**：定义 ChainConfig；包含 mode、rpc_url、chain_id、DID Registry、Lineage Registry、confirmations、relayer 地址；敏感值只从环境变量读取；序列化时主动脱敏。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_chain_config

- **预期结果**：hardhat 配置固定 chain ID 31337；sepolia 配置固定 chain ID 11155111；缺失关键项时预检前即失败。
- **完成条件**：任何业务模块都不直接读取 RPC Token 或私钥环境变量。

---

## 第一里程碑：三方案协议与适配器

> 状态：部分核心已完成，但尚未完整验收。共享内存协议、三个显式 Adapter、A04-A06 策略与无链 L01-L14 控制场景已有 25 个 unittest 通过；Hardhat/Sepolia DID 链上解析、在线入口接线及步骤 039 全量门槛仍待完成。

### 步骤 007：建立规范化 JSON 与摘要函数

- **学习目标**：理解签名、请求哈希、证据哈希和 Merkle 叶子必须共享同一规范化规则。
- **本步只修改**：infrastructure/agentdid_protocol.py，必要时复用 infrastructure/security.py。
- **具体改动**：定义 UTF-8、键排序、紧凑分隔符、禁止 NaN 的 canonical JSON；定义 SHA-256 十六进制格式；补充相同语义不同键顺序摘要一致的测试。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_protocol_hashing

- **预期结果**：键顺序不影响摘要，值类型变化会改变摘要，不可序列化值被拒绝。
- **完成条件**：后续签名与证据模块都只调用这一套规范化函数。

---

### 步骤 008：明确控制密钥与操作密钥

- **学习目标**：理解 DID 控制关系与一次请求的 authentication 关系不是同一个密钥用途。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：定义 ProtocolIdentity；分别保存控制地址、操作地址及对应私钥；提供仅公开字段的序列化；禁止在 repr、日志和 JSON 中输出私钥。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_protocol_identity

- **预期结果**：控制密钥和操作密钥可以相同或不同；公开序列化不含 private、secret、token 字段。
- **完成条件**：DID 文档生成和签名函数不再接收含义不明的单一 key 参数。

---

### 步骤 009：生成 did:ethr DID 文档

- **学习目标**：理解 DID Core 中 verificationMethod、assertionMethod 与 authentication 的引用关系。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：按链网络生成 did:ethr；构造控制和操作 verification method；assertionMethod 指向控制或发行密钥；authentication 指向操作密钥；检查引用必须存在于 verificationMethod。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_did_document

- **预期结果**：本地链与 Sepolia DID 网络标识正确，所有 relationship 引用均可解析。
- **完成条件**：错误 relationship、未知 key fragment 和 DID 不一致都有稳定错误码。

---

### 步骤 010：抽象 DID 解析器接口

- **学习目标**：理解协议验证器不应关心 DID 文档来自内存、Hardhat 还是 Sepolia。
- **本步只修改**：infrastructure/agentdid_protocol.py 或 infrastructure/did_resolver.py。
- **具体改动**：定义 resolve(did) 接口与 DidResolutionResult；包含 document、source、chain_id、block_number、error；共享验证器只依赖该接口。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_did_resolver

- **预期结果**：内存假解析器可用于单元测试，解析失败不产生空 DID 文档。
- **完成条件**：共享验证器中不存在针对 hardhat 或 sepolia 的分支。

---

### 步骤 011：实现 Hardhat DID 注册与解析

- **学习目标**：理解本地集成测试也必须走真实链状态，而非永远信任内存文档。
- **本步只修改**：_experiments/security_comparison/chain.py 与 DID Registry 客户端封装。
- **具体改动**：添加控制 DID 注册、delegate 设置、交易回执校验和按区块解析；把交易哈希、区块号、Gas 与解析来源写入结果；重复注册使用显式幂等检查。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_hardhat_did_resolution

- **预期结果**：注册后的 operation delegate 能从 Hardhat DID Registry 解析，并与本地预期地址一致。
- **完成条件**：交易失败、回执 status 非 1 或解析结果不匹配都被视为 INFRA_ERROR。

---

### 步骤 012：实现 Sepolia DID 严格解析

- **学习目标**：理解远程链解析失败不能被本地文档静默掩盖。
- **本步只修改**：DID Registry 客户端与 _experiments/security_comparison/preflight.py。
- **具体改动**：从 Sepolia Registry 读取 owner/delegate 事件；校验 chain ID、合约字节码与确认数；任何 RPC 或 Registry 失败直接返回预检失败，禁止调用本地解析器。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_sepolia_did_resolver

- **预期结果**：使用模拟 RPC 时可覆盖成功、错误 chain ID、无字节码和超时四种分支。
- **完成条件**：代码中没有 sepolia 失败后切换 localhost 的路径。

---

### 步骤 013：验证 DID relationship 签名

- **学习目标**：理解“签名数学上正确”不等于“签名者被允许用于当前 proof purpose”。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：实现按 proofPurpose 查找 verification method；VC 只能用 assertionMethod；VP、状态和上下文只能用 authentication；校验 key fragment 所属 DID。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_did_relationships

- **预期结果**：用 authentication key 签 VC 或用 assertionMethod key 签 VP 时均被拒绝。
- **完成条件**：relationship 不匹配在签名恢复成功的情况下仍返回稳定拒绝码。

---

### 步骤 014：建立 VC Data Model 2.0 最小结构

- **学习目标**：理解 VC 信封字段与 credentialSubject 业务字段的边界。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：生成 context、type、id、issuer、validFrom、validUntil、credentialSubject、credentialStatus 和 proof；验证必要字段类型；VC ID 每次生成唯一 URN。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vc_structure

- **预期结果**：合法 VC 可序列化；缺失 issuer、subject id 或 proof 时被拒绝。
- **完成条件**：业务 claims 只能位于 credentialSubject，不能覆盖 VC 信封字段。

---

### 步骤 015：签发与验证 VC assertion proof

- **学习目标**：理解 proof options 也必须进入签名数据。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：VC proof 写入 type、cryptosuite、created、verificationMethod、proofPurpose；以去除 proof 后的 VC 加规范化 proof options 作为签名输入；使用 secp256k1。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vc_proof

- **预期结果**：改动 credentialSubject、created、verificationMethod 或 proofPurpose 任一字段都会使验证失败。
- **完成条件**：签名函数与验证函数共享同一签名输入构造器。

---

### 步骤 016：加入可信 Issuer 白名单

- **学习目标**：理解有效签名只能证明某个 Issuer 签过，不能自动证明该 Issuer 被系统信任。
- **本步只修改**：infrastructure/agentdid_protocol.py 与验证器配置。
- **具体改动**：验证前检查 issuer DID 在 trusted_issuers；解析其 DID 文档；校验 proof verificationMethod 属于该 Issuer；不允许 presented DID document 自行扩展信任。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_trusted_issuer

- **预期结果**：未知 Issuer 的有效签名 VC 被拒绝；可信 Issuer 的合法 VC 通过。
- **完成条件**：错误码能区分 ISSUER_UNTRUSTED 与 VC_PROOF_INVALID。

---

### 步骤 017：加入 credential subject 与 holder 绑定

- **学习目标**：理解 A03 的核心是受害者 VC 被攻击者放入自己的 VP，而不是 VC 签名被破坏。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：对每个 VC 检查 credentialSubject.id 等于 VP holder；若协议允许多 subject，则显式定义唯一目标 subject 规则；拒绝跨持有者 VC。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_subject_holder_binding

- **预期结果**：受害者 VC 在受害者 VP 中通过，在攻击者 VP 中以稳定错误码拒绝。
- **完成条件**：A03 不依赖重复 VC 或篡改签名即可被检出。

---

### 步骤 018：验证 VC 有效期

- **学习目标**：理解 validFrom、validUntil 与时钟容差的安全边界。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：统一 UTC 时间解析；加入可配置但有限的 clock_skew；拒绝尚未生效、已过期和倒置时间窗；测试注入固定时钟，避免 sleep。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vc_validity

- **预期结果**：边界时刻可确定复现，测试不依赖机器当前时间漂移。
- **完成条件**：所有时间错误都有稳定错误码和被检查字段。

---

### 步骤 019：签发 Bitstring Status List

- **学习目标**：理解状态列表本身也是需要 Issuer 证明的 VC。
- **本步只修改**：infrastructure/agentdid_protocol.py 或独立 status_list 模块。
- **具体改动**：生成 StatusListCredential；实现 bit index 编码、撤销位设置和读取；状态列表由可信 Issuer 的 assertionMethod 签名；每个 VC 指向明确 index。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_status_list

- **预期结果**：未撤销 index 为 false，撤销后为 true，不同 index 互不影响。
- **完成条件**：状态列表 ID、purpose、index 与签名全部可验证。

---

### 步骤 020：把状态列表接入 VC 验证顺序

- **学习目标**：理解状态检查必须建立在 VC 签名、Issuer 信任和状态列表签名都有效的基础上。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：按固定顺序验证 statusListCredential、statusPurpose、statusListIndex、encodedList 和撤销位；缺失列表与已撤销使用不同错误码。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vc_status_verification

- **预期结果**：合法未撤销 VC 通过；被撤销、列表签名错误、索引越界分别拒绝。
- **完成条件**：验证 trace 能记录使用的 status list ID 与 index，但不泄露敏感内容。

---

### 步骤 021：生成含 proof options 的 VP

- **学习目标**：理解 VP 是 holder 对“一组 VC + 本次会话约束”的证明。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：生成 context、type、holder、verifiableCredential、proof；proof 包含 authentication、created、challenge、domain 或 audience、verificationMethod；challenge 与 audience 进入签名输入。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vp_creation

- **预期结果**：相同 VC 在不同 challenge 或 audience 下产生不同签名。
- **完成条件**：VP 签名输入构造器有独立测试，且不依赖字段插入顺序。

---

### 步骤 022：验证 VP holder 与 authentication

- **学习目标**：理解 A01 是攻击者用自己的密钥声称受害者 DID，数学签名可有效但 DID relationship 无效。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：恢复 VP 签名地址；校验 verificationMethod 属于 holder DID 且被列入 authentication；校验外部 expected_holder；禁止仅凭 recovered address 接受。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vp_holder_authentication

- **预期结果**：受害者 holder 加攻击者签名被拒绝；合法 holder operation key 通过。
- **完成条件**：A01 以 DID_AUTHENTICATION_MISMATCH 或等价稳定码失败。

---

### 步骤 023：验证 challenge 与 audience 签名绑定

- **学习目标**：理解仅在 VP 外层比较 challenge 不够，字段必须不可被签名后替换。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：验证签名覆盖 challenge 和 audience；再与调用方 expected_challenge、expected_audience 比较；分别返回缺失、签名错误和值不匹配错误码。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vp_proof_options

- **预期结果**：替换 challenge 或 audience 会先破坏证明；使用完整旧 VP 则因 expected 值不匹配被拒绝。
- **完成条件**：A02 所需的新 challenge 重放路径可确定复现。

---

### 步骤 024：验证 VP created 新鲜度

- **学习目标**：理解 challenge 一次性之外仍需要限制陈旧证明的接受窗口。
- **本步只修改**：infrastructure/agentdid_protocol.py。
- **具体改动**：解析 proof.created；限制未来时间和最大年龄；注入时钟；把允许窗口写入配置与 trace。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_vp_created

- **预期结果**：合法窗口内通过，过旧或明显未来的 VP 被拒绝。
- **完成条件**：测试不使用真实等待，时间判断可确定执行。

---

### 步骤 025：实现单实验 ReplayGuard

- **学习目标**：理解 VP challenge 一次性使用与跨实验状态隔离必须同时成立。
- **本步只修改**：infrastructure/security.py 与共享验证器接线。
- **具体改动**：ReplayGuard 记录 holder、challenge、audience 的组合键；首次消费成功，重复消费拒绝；每个 ExperimentBundle 新建实例，不使用全局单例。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_replay_guard

- **预期结果**：同一实验第二次验证被拒绝；不同实验使用相同文本 challenge 也不会共享 guard 状态。
- **完成条件**：独立状态清单能记录 replay_guard_id，而不输出内部敏感内容。

---

### 步骤 026：输出共享协议验证 trace

- **学习目标**：理解“最终拒绝”之外还要证明哪些非目标层已经通过。
- **本步只修改**：infrastructure/agentdid_protocol.py 与 SchemeDecision 模型。
- **具体改动**：按 DID resolution、VP proof、proof options、replay、每个 VC 的 issuer、proof、subject、validity、status 顺序记录检查；记录耗时、稳定码与摘要，不记录正文。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_protocol_trace

- **预期结果**：成功 trace 完整列出通过项；失败 trace 精确停在首个失败层。
- **完成条件**：后续 L01-L14 测试可据 trace 断言共享协议全部通过。

---

### 步骤 027：定义统一适配器接口

- **学习目标**：理解三个方案必须共享输入和输出，差异只能位于策略层。
- **本步只修改**：_experiments/security_comparison/adapters.py。
- **具体改动**：定义 SchemeAdapter.evaluate(bundle)；输出同一 SchemeDecision；禁止适配器各自重建 VC/VP；协议验证由公共函数在策略分派前执行一次。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_adapter_interface

- **预期结果**：三适配器都能接受同型 bundle 并返回同型 decision。
- **完成条件**：代码审查可证明任何 scheme 都无法绕过共享协议验证。

---

### 步骤 028：建立每实验协议材料工厂

- **学习目标**：理解“同一场景、不同方案”既需要协议等价，也需要每项实验自身 ID 独立。
- **本步只修改**：_experiments/security_comparison/adapters.py 或 fixtures.py。
- **具体改动**：按 ExperimentConfig 创建 Issuer、Holder、Verifier、Evaluator、Attacker 身份；创建独立 VC ID、VP、challenge、status list、状态和上下文；为 Lineage 保留独立子密钥挂接点。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_bundle_factory

- **预期结果**：重复创建同一 case 的两个 bundle 时所有要求独立的标识均不同，协议语义字段一致。
- **完成条件**：场景变异器只修改攻击所需字段，不重新实现正常材料生成。

---

### 步骤 029：实现 Original-AgentDID 适配器

- **学习目标**：理解 Original 是统一协议下的身份基线，不等于跳过 VC/VP。
- **本步只修改**：_experiments/security_comparison/adapters.py。
- **具体改动**：只要求 AgentIdentityCredential 与合法 VP；共享协议通过后直接接受；不检查能力、五类 VC 完整性、真实状态、Context 或 Lineage；仍保留 trace。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_original_adapter

- **预期结果**：H00 通过；协议层无效材料拒绝；单纯缺少能力或 Lineage 不构成 Original 拒绝。
- **完成条件**：适配器没有调用 BaselinePolicy 或 LineageGateway。

---

### 步骤 030：生成 Baseline 五类 VC 集

- **学习目标**：理解 AgentIdentity、AgentModel、AgentCapability、AgentToolset、AgentCompliance 五类凭证各自职责。
- **本步只修改**：_experiments/security_comparison/adapters.py 与 vc_schemas 的兼容映射。
- **具体改动**：为 Baseline 和 Lineage 生成五类 VC；每类拥有独立 VC ID 和状态索引；验证必需类型集合；保留现有 schema 字段兼容。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_baseline_credential_set

- **预期结果**：完整集合通过，缺失任一类型或重复冲突类型被稳定拒绝。
- **完成条件**：Original 仍只需最小身份 VC，不被五类集合要求误伤。

---

### 步骤 031：实现独立能力证据交叉核验

- **学习目标**：理解 A04 是“可信 Issuer 有效签名的虚假能力”，密码学检查理应通过。
- **本步只修改**：_experiments/security_comparison/adapters.py 与 infrastructure/semantic_benchmark.py 的调用封装。
- **具体改动**：定义 evaluator report；绑定 holder DID、benchmark ID、artifact digest、observed score、threshold、qualified；用独立 Evaluator authentication 或专用 relationship 签名；与 Capability VC 逐字段交叉核验。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_capability_evidence

- **预期结果**：一致且达标的能力通过；有效签名但与独立评测不一致时返回 CAPABILITY_EVIDENCE_MISMATCH。
- **完成条件**：测试确认虚假能力 VC 与 VP 的签名仍然有效。

---

### 步骤 032：实现当前状态与真实工件摘要交叉核验

- **学习目标**：理解 A05 是 holder 对虚假状态作出有效签名，而不是伪造 holder。
- **本步只修改**：_experiments/security_comparison/adapters.py 与状态工件读取封装。
- **具体改动**：状态声明绑定 holder、audience、nonce、timestamp 和 state；验证 authentication 签名；从实际工件重新计算摘要；比较 ready、state_version 和 artifact_digest。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_state_cross_check

- **预期结果**：真实声明通过；有效签名的虚假摘要返回 STATE_GROUND_TRUTH_MISMATCH。
- **完成条件**：真实工件摘要不能取自攻击者提供的状态声明。

---

### 步骤 033：实现上下文哈希与版本连续性

- **学习目标**：理解 A06 的危险是认证后合法签名一个“被清空的新上下文”。
- **本步只修改**：_experiments/security_comparison/adapters.py 与 context 状态封装。
- **具体改动**：维护 previous_hash、previous_version、context_hash、context_version；声明绑定 holder、audience、nonce、timestamp；验证签名后仍与验证端保存的前序状态比较。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_context_continuity

- **预期结果**：正常版本递增通过；清空、回退、跳号或前序哈希不一致均被拒绝。
- **完成条件**：A06 在密码学 trace 中通过，在 Baseline trace 中以 CONTEXT_CONTINUITY_MISMATCH 拒绝。

---

### 步骤 034：保持 auth、Probe 与 Context 入口兼容

- **学习目标**：理解严格策略需要复用现有演示入口，而不是另造无法比较的旁路。
- **本步只修改**：agents/holder/runtime.py、agents/verifier/runtime.py 及最小兼容封装。
- **具体改动**：保留 /auth、/probe、/context_hash 请求与响应主字段；把共享协议、能力证据、状态和上下文检查接入内部；旧调用方未传新可选字段时给出明确兼容行为。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_endpoint_compatibility

- **预期结果**：旧演示请求仍能到达相同入口；严格实验模式可拿到新增 trace 与错误码。
- **完成条件**：_demo_2v2/start_network.py 和 trigger_audit.py 不需要改命令行用法。

---

### 步骤 035：实现 Baseline-AgentDID 适配器

- **学习目标**：理解 Baseline 是共享协议加完整 AgentDID 语义策略。
- **本步只修改**：_experiments/security_comparison/adapters.py。
- **具体改动**：共享协议通过后依次检查五类 VC、能力证据、当前状态、Context 连续性与现有 /auth、Probe 结果；任何失败返回 baseline-agentdid 检测层；不调用 Lineage。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_baseline_adapter

- **预期结果**：H00 通过；A04、A05、A06 在各自语义检查被拒绝；Lineage 材料缺失不影响 Baseline。
- **完成条件**：Baseline 对 Lineage 场景使用明确的宽权限策略并保留通过证据。

---

### 步骤 036：验证 Lineage 四类撤销原语

- **学习目标**：理解 Lineage 的撤销不仅是单个 credential revoked 标志。
- **本步只修改**：infrastructure/lineage/verifier.py、registry_client.py 及对应测试。
- **具体改动**：逐一验证 root 撤销、epoch 撤销、node 或祖先撤销、credential/JTI 撤销；每类绑定链上状态与稳定错误码；补充无关分支撤销不误伤测试。
- **验证命令**：

      conda run -n agentdid python -B -m unittest discover -s _experiments/lineage -p "test_*.py" -v

- **预期结果**：四类撤销均能独立阻止对应链，未撤销链继续通过。
- **完成条件**：L12 可选择祖先撤销构造攻击，且不是由 Baseline 提前拒绝。

---

### 步骤 037：实现 Lineage-AgentDID 适配器

- **学习目标**：理解 Lineage 只能在 Baseline 成功后增加委托约束，不能替换基础身份验证。
- **本步只修改**：_experiments/security_comparison/adapters.py。
- **具体改动**：严格执行 shared protocol → BaselinePolicy → LineageGateway/LineageVerifier；校验委托链、权限收缩、预算、重放、四类撤销；收集合约交易和事件引用。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_adapter

- **预期结果**：H00 通过；若共享协议或 Baseline 失败则不进入 Lineage；合法低层材料上的 Lineage 违规在 lineage-agentdid 层拒绝。
- **完成条件**：decision trace 能证明三个验证层的调用顺序。

---

### 步骤 038：锁定三适配器分层不变量

- **学习目标**：理解同一攻击可能被多个层发现，但实验必须控制首个目标检测层。
- **本步只修改**：_experiments/security_comparison/tests/test_adapter_layering.py。
- **具体改动**：为 A01-A03 断言三方案首个失败层为共享协议；A04-A06 断言共享协议通过且 Baseline/Lineage 在 Baseline 层失败；L01-L14 断言共享协议与 Baseline 全通过。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_adapter_layering

- **预期结果**：所有非目标验证层均按设计通过，不出现“攻击被错误低层提前拒绝”。
- **完成条件**：测试失败时输出 case、scheme、预期层、实际层和首个错误码。

---

### 步骤 039：验收第一里程碑“三方案协议与适配器”

- **学习目标**：学会用测试门槛而不是文件数量判断一个架构里程碑。
- **本步只修改**：不再增加功能；只修复步骤 007 至 038 暴露的问题。
- **具体改动**：运行协议与适配器测试合集；审查三个方案是否复用同一协议入口；审查 Original、Baseline、Lineage 的能力边界；记录未完成项，禁止用 xfail 掩盖。
- **验证命令**：

      conda run -n agentdid python -B -m unittest discover -s _experiments/security_comparison -p "test_*.py" -v

- **预期结果**：相关测试全通过，且无 INFRA_ERROR 被包装成安全拒绝。
- **完成条件**：步骤 007 至 038 全部满足各自门槛后，才把第一里程碑标记为完成；否则继续停留在本步骤。

---

## 阶段 2：逐个构造 21 个安全场景

### 步骤 040：把预期向量写成独立测试数据

- **学习目标**：理解“预期安全行为”属于测试 oracle，不应与适配器实现混在一起。
- **本步只修改**：_experiments/security_comparison/cases.py 与 tests/expected_vectors.py。
- **具体改动**：为 21 个 case 和 3 个 scheme 建立 63 个预期 ACCEPT/REJECT；记录预期首个检测层；增加完整性检查，确保无缺项、无额外项。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_expected_vectors

- **预期结果**：预期向量恰好 63 项，三个 H00 接受，攻击接受数为 17、14、0。
- **完成条件**：运行时代码不导入 expected_vectors，只有测试与最终对照报告使用它。

---

### 步骤 041：实现 H00 合法请求

- **学习目标**：理解每类攻击都应从同一个可通过的合法控制样本变异而来。
- **本步只修改**：_experiments/security_comparison/case_builders.py 或现有 bundle 工厂。
- **具体改动**：生成合法 DID、五类 VC、未撤销状态、VP、能力证据、真实状态、连续 Context、合法两级 Lineage 委托、足够预算和唯一请求；Original 只消费最小子集。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_cases

- **预期结果**：H00 在三个方案均接受，所有应执行层的 trace 都为通过。
- **完成条件**：H00 失败时后续攻击步骤全部暂停，因为攻击变异没有可靠控制样本。

---

### 步骤 042：实现 A01 攻击者密钥声明受害者 DID

- **学习目标**：学习区分 DID 字符串声明与 DID authentication 授权。
- **本步只修改**：_experiments/security_comparison/case_builders.py 中 A01 变异器及对应测试。
- **具体改动**：保留 VP holder 为受害者 DID；改用攻击者操作私钥签 VP；不篡改其他 VC、challenge 或 audience；记录攻击者与受害者公开地址摘要。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_cases

- **预期结果**：三方案均在共享 DID/VP authentication 层拒绝；VC 校验不应成为首个失败点。
- **完成条件**：验证 trace 证明签名可恢复但 recovered key 不在受害者 authentication 中。

---

### 步骤 043：实现 A02 在新 challenge 下重放旧 VP

- **学习目标**：学习会话 challenge 如何阻止完整旧证明重放。
- **本步只修改**：A02 变异器及对应测试。
- **具体改动**：先生成并签署 captured challenge 的合法旧 VP；验证端改为期待 fresh challenge；保持旧 VP 原样，不能为了制造失败而篡改其 proof。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_cases

- **预期结果**：三方案均在共享 VP proof options 或 ReplayGuard 层拒绝，旧 VP 自身签名仍有效。
- **完成条件**：测试同时证明旧 expected challenge 下可通过、新 expected challenge 下被拒绝。

---

### 步骤 044：实现 A03 攻击者 VP 携带受害者 VC

- **学习目标**：学习 credential subject-holder binding 阻止凭证借用。
- **本步只修改**：A03 变异器及对应测试。
- **具体改动**：由可信 Issuer 给受害者签发合法 VC；攻击者用自己的 DID 和 authentication key 创建全新合法 VP；把受害者 VC 放入该 VP；challenge 和 audience 保持正确。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_cases

- **预期结果**：三方案均因 VC subject 与 VP holder 不一致在共享协议层拒绝。
- **完成条件**：攻击者 VP 签名有效、受害者 VC 签名有效，唯一目标失败是 holder binding。

---

### 步骤 045：实现 A04 可信 Issuer 签发虚假能力

- **学习目标**：学习密码学真实性与声明语义真实性的区别。
- **本步只修改**：A04 变异器、能力评测 fixture 与对应测试。
- **具体改动**：可信 Issuer 对 qualified=true、claimedScore=1.0 的能力 VC 有效签名；独立 integer-addition-v1 评测绑定同一 artifact digest 并给出低于 0.80 的结果；其余材料合法。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_cases

- **预期结果**：Original 接受；Baseline 与 Lineage 在 CAPABILITY_EVIDENCE_MISMATCH 或 CAPABILITY_NOT_QUALIFIED 拒绝；共享协议通过。
- **完成条件**：测试明确断言 Issuer 可信、VC 签名有效、VP 签名有效且状态未撤销。

---

### 步骤 046：实现 A05 Holder 有效签名虚假当前状态

- **学习目标**：学习 signed state 只能证明“holder 说过”，不能证明工件真的处于该状态。
- **本步只修改**：A05 变异器、真实工件 fixture 与对应测试。
- **具体改动**：实际工件使用 faulty 摘要；holder 在状态声明中报告 correct 摘要并有效签名；保持 holder、audience、nonce、timestamp 全部正确。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_cases

- **预期结果**：Original 接受；Baseline 与 Lineage 在 STATE_GROUND_TRUTH_MISMATCH 拒绝；共享协议通过。
- **完成条件**：状态签名验证测试单独为通过，失败只来自重新计算的工件摘要。

---

### 步骤 047：实现 A06 认证后重置上下文

- **学习目标**：学习有效签名的全新快照仍可能破坏会话连续性。
- **本步只修改**：A06 变异器、上下文 fixture 与对应测试。
- **具体改动**：验证端保存版本 1 的认证上下文；正常下一状态应为版本 2；攻击者清空消息并签署版本 1 的新快照；签名、holder、audience 与时间均合法。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_cases

- **预期结果**：Original 接受；Baseline 与 Lineage在 CONTEXT_CONTINUITY_MISMATCH 拒绝；共享协议通过。
- **完成条件**：测试证明新上下文签名有效，且哈希自洽但不连接验证端保存的前序状态。

---

### 步骤 048：建立 Lineage 攻击共用合法宽权限夹具

- **学习目标**：理解 14 个 Lineage 攻击必须避免被共享协议或 Baseline 策略提前拒绝。
- **本步只修改**：_experiments/security_comparison/lineage_cases.py 的共同构造器。
- **具体改动**：创建 Root → Persistent → Session 合法链；为 Baseline 提供覆盖所有测试 action、resource、task、audience、version 的宽权限控制策略；为每次实验创建独立 epoch、JTI、budget 和子密钥。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_case_base

- **预期结果**：未变异的基础链通过 shared protocol、Baseline 和 Lineage；各独立标识均非空。
- **完成条件**：后续 L01-L14 只通过小型变异函数改变一个目标约束。

---

### 步骤 049：实现 L01 action 越权

- **学习目标**：学习调用权限必须是委托 action 集合的子集。
- **本步只修改**：lineage_cases.py 中 L01 变异器与测试。
- **具体改动**：leaf 委托只允许 read；调用改为 write 并由合法 leaf operation key 重新签名；Baseline 宽策略同时允许 read 与 write。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 以 action scope 错误码拒绝。
- **完成条件**：共享协议和 Baseline trace 全通过，Lineage 是首个失败层。

---

### 步骤 050：实现 L02 resource 越权

- **学习目标**：学习 action 合法不代表目标 resource 自动合法。
- **本步只修改**：L02 变异器与测试。
- **具体改动**：leaf 只被委托 urn:tool:a；调用改为 urn:tool:b 并重签；Baseline 宽策略允许两个 resource。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 在 resource scope 拒绝。
- **完成条件**：除 resource 外的 action、task、audience、version 和签名全部保持合法。

---

### 步骤 051：实现 L03 委托范围扩大

- **学习目标**：学习子委托权限必须单调收缩。
- **本步只修改**：L03 变异器与测试。
- **具体改动**：重建并合法签署子委托，使其新增父委托未授权的 action 或 resource；调用使用被扩大的权限；保留父引用和其余链结构。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 attenuation violation 拒绝。
- **完成条件**：子委托签名本身有效，不能用无效签名替代范围检查。

---

### 步骤 052：实现 L04 有效期延长

- **学习目标**：学习子委托有效期不得超出父委托。
- **本步只修改**：L04 变异器与测试。
- **具体改动**：把子委托 expires_at 设置为父委托 expires_at 之后，并由合法委托密钥重签；当前调用时间仍在两者时间窗内，避免简单过期检查提前失败。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 validity attenuation 拒绝。
- **完成条件**：拒绝理由是“子窗超出父窗”，而不是“当前凭证已过期”。

---

### 步骤 053：实现 L05 深度重置

- **学习目标**：学习 remaining_depth 必须沿委托链递减。
- **本步只修改**：L05 变异器与测试。
- **具体改动**：把子委托 remaining_depth 提高或重置到父级数值；使用合法委托密钥重签；不改变 delegable 等其他字段。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 depth attenuation 拒绝。
- **完成条件**：测试能显示父深度、期望最大子深度与实际子深度。

---

### 步骤 054：实现 L06 禁止委托绕过

- **学习目标**：学习 delegable=false 与 remaining_depth=0 是需要共同执行的禁止条件。
- **本步只修改**：L06 变异器与测试。
- **具体改动**：从不可继续委托的 Session 凭证构造下一层或伪造可委托子凭证；用当前持有的合法密钥签署可签部分；Baseline 不解释该谱系字段。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 forbidden delegation 拒绝。
- **完成条件**：拒绝不是来自普通 VP holder 或 VC subject 不一致。

---

### 步骤 055：实现 L07 operation key 签委托

- **学习目标**：学习 operation key 与 delegation key 的权限分离。
- **本步只修改**：L07 变异器与测试。
- **具体改动**：保持委托内容合法，但用父代理的 operation private key 替代 delegation private key 签署子委托；调用仍由 leaf operation key 合法签署。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 以 delegation signer relationship 错误拒绝。
- **完成条件**：测试证明错误密钥属于同一代理但用途不被授权。

---

### 步骤 056：实现 L08 兄弟凭证冒充

- **学习目标**：学习同一父节点下的 sibling 不能互用 credential。
- **本步只修改**：L08 变异器与测试。
- **具体改动**：创建两个合法 sibling；由 sibling-B 的 operation key 签调用，但引用 sibling-A 的 credential JTI 或权限；VP holder 与调用者保持一致以通过共享协议。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 leaf/JTI/operation key 绑定不一致拒绝。
- **完成条件**：两个 sibling 自身 DID、密钥和凭证都各自合法。

---

### 步骤 057：实现 L09 分支拼接

- **学习目标**：学习每个子凭证必须链接到实际父凭证与 lineage commitment。
- **本步只修改**：L09 变异器与测试。
- **具体改动**：创建两条各自合法的委托分支；把分支 A 的上层与分支 B 的叶凭证拼接；保持各单份凭证签名有效。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 parent credential hash 或 lineage commitment 不连续拒绝。
- **完成条件**：测试分别证明两条原始完整链可通过，而拼接链被拒绝。

---

### 步骤 058：实现 L10 跨任务重放

- **学习目标**：学习 task_id 是委托权限和调用签名的一部分。
- **本步只修改**：L10 变异器与测试。
- **具体改动**：leaf 仅获 task-1；调用改为 task-2 并由合法 leaf key 重签；Baseline 宽策略允许两个 task。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 task scope 拒绝。
- **完成条件**：请求正文、action、resource 和 audience 保持不变。

---

### 步骤 059：实现 L11 跨受众重放

- **学习目标**：学习 VP audience 合法不代表 Lineage 委托也授权该受众。
- **本步只修改**：L11 变异器与测试。
- **具体改动**：为新的协议 audience 创建全新合法 VP，确保共享协议 expected_audience 同步；调用与 VP 均绑定 other gateway；委托只授权正式 Lineage gateway。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因委托 audience scope 拒绝。
- **完成条件**：共享 VP audience 检查通过，不能让 L11 退化为 A02 类低层失败。

---

### 步骤 060：实现 L12 祖先撤销绕过

- **学习目标**：学习叶凭证未撤销也不能绕过祖先节点撤销。
- **本步只修改**：L12 变异器与测试。
- **具体改动**：先注册合法链，再在链上撤销 persistent 祖先；保持 leaf credential、VP 和 Baseline 状态有效；尝试使用原链调用。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 从链上状态发现 ancestor revoked 并拒绝。
- **完成条件**：chain-activity 可引用撤销交易与事件，拒绝不依赖内存标志。

---

### 步骤 061：实现 L13 confused deputy

- **学习目标**：学习合法代理不能把调用来源或 on_behalf_of 关系偷换成更高权限主体。
- **本步只修改**：L13 变异器与测试。
- **具体改动**：由合法 leaf key 重签请求，但把 origin_did、on_behalf_of 或请求主体关系改成未被委托允许的身份；其他作用域字段合法。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因代理主体关系不一致拒绝。
- **完成条件**：签名者身份有效，但所代表的主体语义无授权。

---

### 步骤 062：实现 L14 版本替换

- **学习目标**：学习 agent/version binding 防止用同一身份替换未经授权的软件版本。
- **本步只修改**：L14 变异器与测试。
- **具体改动**：调用声明另一个 version_id 并由合法 leaf key 重签；Baseline 的 Model VC 与宽策略允许该版本用于对照；Lineage 委托只允许原版本。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_cases

- **预期结果**：Original、Baseline 接受，Lineage 因 version scope 拒绝。
- **完成条件**：共享协议和 Baseline 版本检查均有明确通过证据。

---

### 步骤 063：总体验证 21 个场景的非目标层

- **学习目标**：学习安全实验的关键不是“发生拒绝”，而是“在预定机制处发生拒绝”。
- **本步只修改**：_experiments/security_comparison/tests/test_case_layer_invariants.py。
- **具体改动**：遍历 H00、A01-A06、L01-L14；断言攻击只修改预定字段；检查所有非目标层通过；检查每个 case 的稳定错误码与检测层。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_case_layer_invariants

- **预期结果**：21 个场景全部满足分层不变量，且没有两个 case 意外生成相同攻击材料摘要。
- **完成条件**：可以用一张机器生成表解释每个场景“哪些层通过、首个失败层是什么”。

---

## 阶段 3：把共享矩阵改成 63 个独立子进程实验

### 步骤 064：集中生成独立实验标识

- **学习目标**：理解随机 ID 不只是命名问题，也是重放、串扰和证据归属的安全边界。
- **本步只修改**：_experiments/security_comparison/isolation.py。
- **具体改动**：创建 ExperimentIdentityFactory；生成 experiment_id、nonce、challenge、VC ID、JTI、budget ID、request hash salt、context namespace、ReplayGuard ID 和 Lineage 子密钥材料；支持测试注入 seed，但正式运行默认使用安全随机源。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_isolation_factory

- **预期结果**：批量生成 63 组时所有要求唯一的字段均无重复。
- **完成条件**：业务构造器不再各自随意调用 uuid 或固定字符串生成关键标识。

---

### 步骤 065：隔离 ReplayGuard、上下文和状态存储

- **学习目标**：理解进程隔离之外还要避免共享磁盘键与全局单例。
- **本步只修改**：_experiments/security_comparison/isolation.py 与 bundle 工厂接线。
- **具体改动**：为每个 experiment_id 创建独立 ReplayGuard、ContextStore、StateArtifactStore；所有文件键带 experiment_id；清除模块级可变字典；提供 close/finalize 接口。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_state_isolation

- **预期结果**：实验 A 写入的 challenge、context 或 state 在实验 B 中不可见。
- **完成条件**：并行或任意顺序执行两项实验得到相同各自结果。

---

### 步骤 066：定义父子进程输入协议

- **学习目标**：理解独立子进程应只接收可审计配置，不能继承父进程中的活对象。
- **本步只修改**：_experiments/security_comparison/subprocess_protocol.py。
- **具体改动**：父进程把 ExperimentConfig 写入 .codex/comparison_runs/run_id/inputs；子进程只从一个明确 JSON 路径读取；校验 schema_version、run_id、scheme、case_id 与输出目录边界。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_subprocess_protocol

- **预期结果**：合法输入可读取；路径越界、未知 scheme、未知 case 或 schema 不匹配被拒绝。
- **完成条件**：父进程不通过 pickle、共享内存或隐式全局变量传递实验状态。

---

### 步骤 067：写入 experiment-config.json

- **学习目标**：理解可复现实验需要记录公开配置，同时必须脱敏。
- **本步只修改**：_experiments/security_comparison/run_one.py 与证据写入辅助函数。
- **具体改动**：在实验开始即写 experiment-config.json；记录 run、experiment、scheme、case、chain、公开 actor DID、配置摘要和开始时间；RPC URL 只保留已脱敏 origin，私钥与 token 永不写入。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_experiment_config_artifact

- **预期结果**：配置文件 schema 稳定、字段齐全，敏感扫描无命中。
- **完成条件**：即使后续 INFRA_ERROR，也能从该文件确定失败属于哪项实验。

---

### 步骤 068：让 run_one 只执行一个方案和一个场景

- **学习目标**：理解真正的独立实验入口不能在内部循环整个矩阵。
- **本步只修改**：_experiments/security_comparison/run_one.py。
- **具体改动**：支持 --scheme original|baseline|lineage、--case H00..L14、--run-id、--experiment-id、--config、--output-dir；单次只构造一个 bundle、调用一个适配器、锚定一次并退出。
- **验证命令**：

      conda run -n agentdid python -B -m _experiments.security_comparison.run_one --help

- **预期结果**：帮助信息列出单实验参数，非法 scheme/case 返回非零退出码。
- **完成条件**：run_one 源码中不存在遍历 SCHEMES 或 CASES 的正式执行循环。

---

### 步骤 069：定义子进程退出码与结果哨兵

- **学习目标**：理解安全 REJECT 是成功完成的实验，不应使用失败退出码。
- **本步只修改**：run_one.py 与 subprocess_protocol.py。
- **具体改动**：ACCEPT 和策略 REJECT 均写 COMPLETED 并退出 0；基础设施异常写 INFRA_ERROR 并退出专用非零码；不可分类异常写脱敏 traceback 摘要；创建 result-ready.json 作为完成哨兵。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_run_one_exit_codes

- **预期结果**：安全拒绝返回 0，模拟 RPC 失败返回非零且 decision 不伪装为 REJECT。
- **完成条件**：run_all 只根据结构化状态和退出码判定，不搜索控制台文本。

---

### 步骤 070：实现超时、信号和不完整目录处理

- **学习目标**：理解中断的实验不能被误认为已有完整证据。
- **本步只修改**：run_one.py 与 run_all.py 的进程包装层。
- **具体改动**：设置单实验超时；捕获可处理的终止信号；先写临时 staging 子目录，完成 manifest 与 anchor 后再发布完成哨兵；保留不完整目录供诊断，不批量删除。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_subprocess_timeout

- **预期结果**：模拟超时得到 INFRA_ERROR，无 result-ready 哨兵，已有诊断文件仍保留。
- **完成条件**：汇总器不会读取或计入未发布完成哨兵的实验。

---

### 步骤 071：管理本地 Hardhat 生命周期

- **学习目标**：理解 63 个实验共享已部署合约，但不能各自悄悄启动不同本地链。
- **本步只修改**：_experiments/security_comparison/chain.py 与 run_all.py。
- **具体改动**：运行前探测 localhost:8545；若由本次 run 启动 Hardhat，则记录 PID 和日志到 .codex；等待 RPC ready；运行后只终止本次启动的进程；禁止终止用户已有服务。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_hardhat_lifecycle

- **预期结果**：已有 Hardhat 时复用；无服务时能启动并确认 chain ID 31337；错误 chain ID 立即失败。
- **完成条件**：链生命周期状态进入 run 级元数据，子进程不自行启动 Hardhat。

---

### 步骤 072：部署一次共享合约并准备控制 DID

- **学习目标**：理解共享链基础设施与独立实验状态可以同时成立。
- **本步只修改**：contracts/scripts/deploy-comparison.js、chain.py 与 run 级配置。
- **具体改动**：每个 run 部署或确认 DID Registry、Lineage Registry；注册共享 Issuer、Holder、Verifier 控制 DID 与 delegate；记录部署和注册回执；单实验只引用这些控制身份，同时生成独立业务材料。
- **验证命令**：

      npx.cmd hardhat run contracts/scripts/deploy-comparison.js --network localhost

- **预期结果**：输出合约地址、chain ID 和成功回执；地址写入 run 级非敏感配置。
- **完成条件**：63 项实验不重复部署合约，也不共享要求独立的 nonce、JTI、epoch、budget 或子密钥。

---

### 步骤 073：实现 run_all 的 63 项稳定编排

- **学习目标**：理解矩阵编排器只负责调度和收集，不能代替子进程执行验证。
- **本步只修改**：_experiments/security_comparison/run_all.py。
- **具体改动**：按 SCHEMES × CASES 生成 63 个 ExperimentConfig；每项使用 Python subprocess 调用 run_one；默认顺序固定；记录 PID、开始结束时间、退出码和输出目录；链 nonce 未实现安全协调前保持串行。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_run_all_orchestration

- **预期结果**：模拟执行器被调用 63 次，每次参数唯一且没有进程内 bundle 复用。
- **完成条件**：父进程源码不导入 evaluate_scheme 或具体适配器执行函数。

---

### 步骤 074：实现失败继续与最终失败策略

- **学习目标**：理解完整矩阵需要保留所有失败证据，但验收不能在存在 INFRA_ERROR 时成功。
- **本步只修改**：run_all.py。
- **具体改动**：单项 INFRA_ERROR 后继续调度剩余项；最终汇总列出失败；默认整体返回非零；提供 --fail-fast 仅供调试且不得用于正式验收。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_run_all_failure_policy

- **预期结果**：模拟第 5 项失败后仍执行其余 58 项，最终退出非零并记录第 5 项 INFRA_ERROR。
- **完成条件**：任何缺失实验或 INFRA_ERROR 都不能生成“验收通过”标志。

---

### 步骤 075：支持精确调试选择但保持正式入口完整

- **学习目标**：理解学习和调试需要小范围运行，但正式 run_all 不能悄悄变成抽样。
- **本步只修改**：run_one.py、run_all.py 的 CLI 参数层。
- **具体改动**：run_one 保持 --scheme 与 --case；run_all 正式默认始终 63 项；若提供开发过滤器必须在输出中标记 NON_ACCEPTANCE_RUN，且不能生成正式 PESR 验收结论。
- **验证命令**：

      conda run -n agentdid python -B -m _experiments.security_comparison.run_one --scheme baseline --case A04 --help
      conda run -n agentdid python -B -m _experiments.security_comparison.run_all --help

- **预期结果**：单项调试命令可发现；正式完整命令无需额外参数；过滤运行有明确非验收标记。
- **完成条件**：--sepolia 不能与任何抽样或过滤参数组合用于正式结果。

---

## 阶段 4：建立每实验链下证据与链上锚定

### 步骤 076：创建固定实验目录布局

- **学习目标**：理解证据路径本身应能唯一定位 run、scheme 与 case。
- **本步只修改**：_experiments/security_comparison/evidence.py。
- **具体改动**：实现 .codex/comparison_runs/run_id/experiments/scheme-directory/case_id；使用允许列表创建 12 个固定文件；拒绝 scheme、case 或 run_id 中的路径穿越字符。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_evidence_paths

- **预期结果**：三个 scheme 目录名稳定；21 个 case 目录可创建；越界路径被拒绝。
- **完成条件**：所有中间和最终运行文件均位于工作目录 .codex 内。

---

### 步骤 077：输出 DID、VC 与 VP 证据文件

- **学习目标**：理解验证输入需要可重算，但秘密材料不属于证据。
- **本步只修改**：evidence.py 与 run_one.py。
- **具体改动**：分别写 did-documents.json、credentials.json、presentation.json；包含公开 DID 文档、状态列表公开材料、VC 与 VP；写入 schema_version；做私钥和 RPC token 递归扫描。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_protocol_evidence_files

- **预期结果**：可从文件重新执行共享协议验证；敏感字段扫描为零。
- **完成条件**：文件不是 Python repr，必须为确定编码的 UTF-8 JSON。

---

### 步骤 078：输出 trace、状态、Lineage 和决策文件

- **学习目标**：理解输入证据、验证过程和最终决策应分文件保存。
- **本步只修改**：evidence.py 与 run_one.py。
- **具体改动**：写 verification-trace.json、state-and-context.json、lineage-evidence.json、decision.json；Original/Baseline 的 lineage-evidence 明确写 enforced=false，而不是缺失文件。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_decision_evidence_files

- **预期结果**：四个文件在 ACCEPT 与 REJECT 情况下都存在；检测层、错误码和非目标层结果一致。
- **完成条件**：decision.json 可以独立驱动汇总，trace 可用于复核其来源。

---

### 步骤 079：定义 audit.jsonl 稳定事件 schema

- **学习目标**：理解审计日志应记录阶段变化，而不是只写最终一行。
- **本步只修改**：evidence.py 或 audit.py。
- **具体改动**：事件包含 run_id、experiment_id、scheme、case_id、attack、stage、status、error_code、detection_layer、DID/VC/VP 哈希、context version、Lineage 哈希、tx hash、block、timestamp；定义事件类型允许列表。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_audit_schema

- **预期结果**：最小合法事件通过 schema；缺失 ID、阶段或状态失败；正文和秘密字段被拒绝。
- **完成条件**：稳定错误码和检测层是结构化字段，不藏在 message 中。

---

### 步骤 080：把 audit.jsonl 串成前序哈希链

- **学习目标**：理解 append-only 日志仍需要检测删除、插入和重排。
- **本步只修改**：audit.py 与验证测试。
- **具体改动**：首事件 previous_event_hash 使用固定 genesis；每事件 event_hash 覆盖除自身 hash 外的全部字段及 previous hash；写入前刷新并同步；实现离线 verify_audit_chain。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_audit_hash_chain

- **预期结果**：原日志通过；改一字、删中间行或交换两行均失败并定位序号。
- **完成条件**：最后事件哈希进入 evidence manifest 和 Merkle 叶子。

---

### 步骤 081：实施证据脱敏与敏感内容门禁

- **学习目标**：理解“完整证据”不等于记录私钥、RPC Token 或敏感正文。
- **本步只修改**：evidence.py 的 redaction 与扫描函数。
- **具体改动**：递归拒绝 private_key、mnemonic、authorization、rpc_token 等键；RPC URL 查询串脱敏；状态和上下文只存摘要及必要元数据；审计正文改存哈希。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_evidence_redaction

- **预期结果**：注入测试秘密时写入被阻止或替换为明确 REDACTED；公开地址与交易哈希保留。
- **完成条件**：manifest 生成前必须通过敏感扫描，否则实验为 INFRA_ERROR 且不得锚定泄密文件。

---

### 步骤 082：生成 evidence-manifest.json

- **学习目标**：理解清单要固定文件集合、大小与内容摘要。
- **本步只修改**：evidence.py。
- **具体改动**：对除 evidence-manifest.json 和 chain-anchor.json 外的固定证据文件按相对路径排序；记录 SHA-256、字节数、schema；拒绝缺文件、额外未声明文件或重复路径。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_evidence_manifest

- **预期结果**：完整目录生成确定清单；改动任一文件后完整性验证失败。
- **完成条件**：清单生成前所有 JSON 与 JSONL 都通过各自 schema 和哈希链校验。

---

### 步骤 083：为每项实验计算独立 Merkle 根

- **学习目标**：理解 Merkle 根承诺的是整套证据，而不是只承诺 decision.json。
- **本步只修改**：evidence.py。
- **具体改动**：用 relative_path 与 file_hash 共同构造叶子；按路径稳定排序；明确奇数叶复制规则或域分离规则；记录算法版本、叶数量、叶哈希和 root。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_merkle_root

- **预期结果**：同一证据集根稳定；文件内容或路径变化使根变化；不同实验即使决策相同也有不同根。
- **完成条件**：manifest 中唯一的 evidence_root 可被离线重算。

---

### 步骤 084：每项实验提交一次审计锚定交易

- **学习目标**：理解 63 次锚定指每项实验一次，不等于整个 run 只锚定一个总根。
- **本步只修改**：infrastructure/evidence_anchor.py、chain.py 与 run_one.py。
- **具体改动**：把 32 字节 evidence_root 编码到零值交易 data 或专用锚定合约；等待回执；记录 tx hash、block、from、to、Gas、latency 和 anchored hash；单实验只调用一次。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_chain_anchor

- **预期结果**：回执 status 为 1，链上数据解码后与该实验 Merkle 根完全一致。
- **完成条件**：run_one 的成功路径若没有且仅有一个有效 anchor，则不得标记 COMPLETED。

---

### 步骤 085：让策略拒绝也生成并锚定证据

- **学习目标**：理解安全拒绝是实验结果，不是提前中止证据流程的异常。
- **本步只修改**：run_one.py。
- **具体改动**：将 SchemeDecision.REJECT 继续送入 audit、manifest、Merkle 和 anchor 流程；只有基础设施错误进入 INFRA_ERROR；记录 rejected=true 与稳定检测层。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_rejection_anchor

- **预期结果**：A01 等被拒绝实验仍有完整 12 个文件和成功锚定回执。
- **完成条件**：REJECT 不抛出导致子进程非零退出，且其证据可反向验证。

---

### 步骤 086：记录 Original 与 Baseline 链活动

- **学习目标**：理解方案没有 Lineage 交易不代表没有链活动。
- **本步只修改**：chain.py 与 chain-activity.json 写入逻辑。
- **具体改动**：记录共享 DID 注册、delegate 设置的引用及本实验审计锚定；区分 run 级共享交易和 experiment 级锚定；验证相关回执与控制 DID 解析结果。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_control_chain_activity

- **预期结果**：Original/Baseline chain-activity.json 至少能追溯 DID 控制状态和本实验 anchor。
- **完成条件**：不会伪造每实验重复注册交易，也不会遗漏共享交易的来源引用。

---

### 步骤 087：解析 Lineage 合约事件

- **学习目标**：理解交易成功之外还需验证预期业务事件与参数。
- **本步只修改**：chain.py 与 Lineage 事件解析器。
- **具体改动**：解析 RootRegistered、DelegationRegistered、InvocationStarted、InvocationFinished、预算创建/保留/结算和撤销事件；记录 logIndex、block、tx 与关键参数摘要；按场景声明预期事件。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_lineage_chain_events

- **预期结果**：H00 有完整调用和预算事件；安全拒绝只要求到拒绝前已发生的合法设置事件；L12 包含撤销事件。
- **完成条件**：chain-activity.json 不以函数调用记录冒充链上事件，必须来自交易 receipt logs。

---

### 步骤 088：实现链上锚定反向验证

- **学习目标**：理解“已发送交易”不等于“该交易承诺了当前证据”。
- **本步只修改**：evidence_anchor.py、evidence.py 与离线校验入口。
- **具体改动**：从 chain-anchor.json 读取 tx hash；从 RPC 获取交易和回执；解码 anchored hash；重新计算本地 manifest 与 Merkle root；逐项比较 chain ID、sender、回执状态和 hash。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_anchor_reverse_verification

- **预期结果**：原证据通过；替换 tx hash、篡改文件或连接错误 chain 均失败。
- **完成条件**：每项 COMPLETED 的实验都能从链上交易反向验证到本地 11 个前置证据文件。

---

## 阶段 5：Sepolia 严格预检与完整运行

### 步骤 089：预检 RPC 可用性和 chain ID

- **学习目标**：理解远程实验必须在产生任何交易费用前发现错误网络。
- **本步只修改**：_experiments/security_comparison/preflight.py。
- **具体改动**：探测 RPC 连通性、最新区块、chain ID 11155111、节点同步状态与调用超时；输出结构化 PreflightReport；URL 与错误日志脱敏。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_sepolia_preflight

- **预期结果**：正确模拟节点通过；错误 chain ID、无响应和落后节点稳定失败。
- **完成条件**：预检失败时不调用任何发送交易函数。

---

### 步骤 090：预检 relayer 地址与余额

- **学习目标**：理解完整 63 项需要按最坏 Gas 预算评估，而不是只检查余额大于零。
- **本步只修改**：preflight.py。
- **具体改动**：从私钥推导 relayer 公共地址；查询余额、base fee 与预估 Gas；估计 DID 设置、Lineage 活动和 63 次 anchor 的安全上界；私钥只在内存使用。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_sepolia_preflight

- **预期结果**：余额充足通过；低于估算加安全余量时给出余额缺口并停止。
- **完成条件**：报告只出现 relayer 地址和余额，不出现私钥或助记词。

---

### 步骤 091：预检 DID Registry 与 Lineage Registry

- **学习目标**：理解“地址格式正确”不能证明目标地址部署了正确合约。
- **本步只修改**：preflight.py 与 chain.py。
- **具体改动**：检查两个地址非零、有字节码；验证 chain ID；调用只读接口或比对允许的 runtime bytecode hash/接口选择器；确认 relayer 可执行必要操作。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_sepolia_preflight

- **预期结果**：正确 Registry 通过；EOA、空地址、错误 ABI 或错误网络合约失败。
- **完成条件**：预检报告明确列出 DID Registry 和 Lineage Registry 的地址、代码摘要和检查结果。

---

### 步骤 092：禁止 Sepolia 自动回退

- **学习目标**：理解回退会把标为 Sepolia 的结果污染成本地结果。
- **本步只修改**：run_all.py、run_one.py、chain.py 与 resolver 接线。
- **具体改动**：--sepolia 一旦选中，所有 DID 解析、注册、Lineage 交易和锚定均只能使用 Sepolia ChainConfig；删除或拒绝 localhost fallback；在每个证据文件记录 chain ID。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_no_chain_fallback

- **预期结果**：模拟 Sepolia RPC 中断得到 INFRA_ERROR；Hardhat 模拟器的调用计数保持为零。
- **完成条件**：代码审查找不到 except 后改用 HARDHAT_RPC_URL 的路径。

---

### 步骤 093：复用 Sepolia 部署与控制 DID

- **学习目标**：理解控制成本的正确方式是共享部署与控制身份，而不是减少实验数量。
- **本步只修改**：preflight.py、chain.py 与 run 级元数据。
- **具体改动**：确认已部署 Registry；确认或一次性设置 Issuer、Holder、Verifier 控制 DID/delegate；记录可复用交易引用；为每实验仍创建独立 VC、VP、nonce、Lineage 子密钥、JTI、epoch 和 budget。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_shared_chain_setup

- **预期结果**：共享控制设置只执行必要次数，63 个实验隔离字段仍全部唯一。
- **完成条件**：共享项和独立项在代码模型及证据中有明确列表，不能混淆。

---

### 步骤 094：锁定 Sepolia 完整 63 项执行门槛

- **学习目标**：理解远程链模式与本地模式拥有相同安全覆盖率。
- **本步只修改**：run_all.py 的参数校验与 acceptance 元数据。
- **具体改动**：--sepolia 强制预检通过后生成完整 63 配置；拒绝与 --scheme、--case、--sample 或过滤参数组合；记录 planned=63；预检失败时 planned 状态可见但 started=0。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_sepolia_full_matrix_gate

- **预期结果**：Sepolia 正式模式只能计划 63 项；任何抽样组合在发交易前失败。
- **完成条件**：不存在名为 smoke 的结果被汇总成正式 Sepolia 安全结论。

---

## 阶段 6：汇总、指标与完整性报告

### 步骤 095：生成 decisions.csv

- **学习目标**：理解汇总只消费独立实验产物，不重新执行安全逻辑。
- **本步只修改**：_experiments/security_comparison/summary.py。
- **具体改动**：遍历有 result-ready 哨兵的目录；从 decision.json、chain-anchor.json 和计时字段提取 run、scheme、case、family、状态、accepted、code、layer、latency、tx、block、gas；固定列顺序。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_decisions_csv

- **预期结果**：完整 run 恰好 63 行；每个 scheme 21 行；每个 scheme/case 组合唯一。
- **完成条件**：缺失、重复、INFRA_ERROR 或未完成目录都会在 CSV 和完整性报告中显式出现。

---

### 步骤 096：生成三方案并列表与向量对照

- **学习目标**：理解同一 case 横向比较比 63 行明细更容易发现方案差异。
- **本步只修改**：summary.py。
- **具体改动**：生成每行一个 case、三列方案决策的 Markdown/CSV 表；附实际检测层和错误码；与测试 oracle 对照但不改写实际值；列出 mismatch。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_comparison_table

- **预期结果**：21 行完整对齐；缺一方案时该行标记 incomplete 而不是默认拒绝。
- **完成条件**：用户能从并列表直接核对 H00、A 类与 L 类的预期模式。

---

### 步骤 097：从实际结果计算 PESR 与 HAR

- **学习目标**：理解指标分母必须排除 H00 与 INFRA_ERROR，并公开计算式。
- **本步只修改**：summary.py。
- **具体改动**：PESR 定义为已完成攻击中被方案接受的数量除以已完成攻击数量；正式验收要求分母为 20；HAR 定义为已完成 H00 中接受数量除以已完成 H00 数量；分别按 scheme 计算。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_metrics

- **预期结果**：固定合法 fixture 得到 17/20、14/20、0/20 和三个 HAR=1/1；插入 INFRA_ERROR 时指标标记 incomplete。
- **完成条件**：代码中没有直接返回 17、14、0 的分支，数字只能来自行级 decision 计数。

---

### 步骤 098：计算分攻击族检测率

- **学习目标**：理解总 PESR 会隐藏身份、语义和谱系三类机制的差异。
- **本步只修改**：summary.py。
- **具体改动**：按 identity_replay=A01-A03、semantic=A04-A06、lineage=L01-L14 分组；输出每方案 detected/completed、accepted/completed 和首个检测层分布。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_family_metrics

- **预期结果**：固定向量中三方案对 A01-A03 检测率均 3/3；Baseline/Lineage 对 A04-A06 为 3/3；只有 Lineage 对 L01-L14 为 14/14。
- **完成条件**：INFRA_ERROR 不计作 detected，并使对应族标记覆盖不完整。

---

### 步骤 099：汇总验证延迟、交易延迟与 Gas

- **学习目标**：理解安全判定延迟与链上确认延迟是不同指标。
- **本步只修改**：summary.py 与计时字段采集。
- **具体改动**：分别统计 protocol、baseline、lineage、evidence build、anchor submit、anchor confirmation；输出 count、median、p95、min、max；Gas 按操作和方案汇总；不把预检时间混入单实验验证。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_latency_gas_summary

- **预期结果**：缺失计时或回执时报告 incomplete，不以 0 填补；分位数从原始行计算。
- **完成条件**：benchmark 重复测量使用独立入口，不增加 Sepolia 安全矩阵交易数量。

---

### 步骤 100：生成隔离与完整性检查报告

- **学习目标**：理解“63 个目录”不等于“63 项真正独立且可验证的实验”。
- **本步只修改**：_experiments/security_comparison/integrity.py、summary.py 与 verify_run.py。
- **具体改动**：检查 63 个唯一 experiment_id、nonce、VC ID、VP hash、ReplayGuard ID、context namespace、request hash、Lineage child key、JTI、epoch、budget ID；检查每项 12 个文件、audit hash chain、manifest、Merkle root、anchor 回执和反向验证；提供只读 verify_run CLI。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_run_integrity

- **预期结果**：完整 fixture 通过；任一重复 ID、缺文件、坏哈希或错误 anchor 均定位到具体 scheme/case。
- **完成条件**：integrity-report.json 的 overall_pass 只在所有检查通过时为 true。

---

## 阶段 7：兼容迁移、完整测试与最终验收

### 步骤 101：让旧基线退出正式结果

- **学习目标**：理解删除旧代码不是必要条件，关键是正式结果不可混入旧方案。
- **本步只修改**：_experiments/lineage/baselines.py、旧矩阵入口和新 summary 的边界接线。
- **具体改动**：Shared-Root、ACL、OpenFGA、Plain-Delegation 标记 legacy 或 historical；新 run_all 不导入、不调度、不汇总它们；旧研究脚本若保留，输出目录和结果 schema 与正式矩阵隔离。
- **验证命令**：

      rg -n "Shared.Root|OpenFGA|Plain.Delegation|ACL" _experiments/security_comparison

- **预期结果**：正式 security_comparison 中只允许迁移说明或禁止列表出现旧名称，不存在适配器或调度项。
- **完成条件**：decisions.csv 的 scheme 唯一值恰好是三个新方案。

---

### 步骤 102：完善三个主 CLI

- **学习目标**：理解稳定入口是可复现实验的一部分。
- **本步只修改**：run_all.py、run_one.py 与 _experiments/security_comparison/README.md。
- **具体改动**：确保以下三条命令可发现、参数说明一致；run_all 默认 Hardhat 全量；--sepolia 全量且预检；run_one 支持精确调试；README 解释输出和退出码。
- **验证命令**：

      conda run -n agentdid python -B -m _experiments.security_comparison.run_all --help
      conda run -n agentdid python -B -m _experiments.security_comparison.run_one --help

- **预期结果**：帮助文本包含模式、输出目录、预检、非回退和正式验收含义。
- **完成条件**：文档中的三条主命令与 argparse 实际行为完全一致。

---

### 步骤 103：完成共享协议单元测试矩阵

- **学习目标**：理解协议边界应在不启动链的快速测试中被穷举。
- **本步只修改**：_experiments/security_comparison/tests/test_protocol_matrix.py。
- **具体改动**：覆盖 DID relationship、VC proof options、VP challenge/audience/created、subject-holder、可信 Issuer、有效期、重复 VC、status list 和 replay；每个失败路径断言稳定错误码。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_protocol_matrix

- **预期结果**：所有协议正反例通过，运行快速且不访问网络。
- **完成条件**：A01-A03 的根因都有至少一个更小的协议单元测试。

---

### 步骤 104：完成 Baseline 语义单元测试矩阵

- **学习目标**：理解能力、状态和上下文是三条独立的语义证据链。
- **本步只修改**：_experiments/security_comparison/tests/test_baseline_policy_matrix.py。
- **具体改动**：分别覆盖能力评测签名/绑定/分数、真实状态摘要、状态签名与新鲜度、Context 哈希/版本/前序状态；增加多个错误同时存在时首错顺序测试。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_baseline_policy_matrix

- **预期结果**：A04-A06 的合法控制与目标变异均可独立复现。
- **完成条件**：每个语义攻击都证明共享协议有效，而非只断言最终拒绝。

---

### 步骤 105：固定 63 项适配器预期向量测试

- **学习目标**：理解适配器层测试可以快速验证方案语义，而不用为每次改动支付链上成本。
- **本步只修改**：_experiments/security_comparison/tests/test_63_adapter_vectors.py。
- **具体改动**：参数化遍历 63 组合；比较实际 ACCEPT/REJECT 与 expected_vectors；同时断言首个检测层和所有非目标层；测试 fixture 使用确定链状态替身。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_63_adapter_vectors

- **预期结果**：63 项全部通过；统计攻击接受数为 17、14、0，但数字由测试结果计数得到。
- **完成条件**：任何单 case 失败都显示完整 case/scheme 与 trace 摘要。

---

### 步骤 106：完成 63 项隔离测试

- **学习目标**：理解独立性需要全矩阵集合级断言。
- **本步只修改**：_experiments/security_comparison/tests/test_63_isolation.py。
- **具体改动**：生成或轻量运行 63 个子进程配置；收集 nonce、VC ID、JTI、budget、request hash、context、ReplayGuard、child key 和 epoch；对每类字段做全局唯一检查；随机打乱执行顺序复测结果。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_63_isolation

- **预期结果**：全部要求唯一字段无碰撞，执行顺序变化不改变安全向量。
- **完成条件**：测试能够报告首个冲突值和涉及的两个 experiment_id。

---

### 步骤 107：执行本地 Hardhat 63 项集成测试

- **学习目标**：理解模拟适配器通过后仍需验证真实交易、事件、回执与锚定。
- **本步只修改**：_experiments/security_comparison/tests/test_hardhat_full_matrix.py 与必要修复。
- **具体改动**：启动或复用隔离 Hardhat；部署共享合约；实际运行 63 个子进程；检查 63 个 COMPLETED、0 INFRA_ERROR、63 个独立 anchor、全部回执与事件、全部 Merkle 反向验证。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_hardhat_full_matrix

- **预期结果**：本地完整矩阵一次通过；三个 H00 接受；Lineage 的 20 个攻击接受数为零。
- **完成条件**：测试必须读取真实产物和 RPC 回执，不能 mock anchor 或 Lineage Registry。

---

### 步骤 108：验证旧 HTTP 入口兼容

- **学习目标**：理解新安全层不能破坏现有 AgentDID 演示契约。
- **本步只修改**：兼容性测试和必要的最小 runtime 适配。
- **具体改动**：对 /auth、/probe、/context_hash 发送旧格式请求；验证状态码、关键响应字段与调用顺序；再发送严格模式新字段并验证 trace；不改变旧命令入口。
- **验证命令**：

      conda run -n agentdid python -B -m unittest -v _experiments.security_comparison.tests.test_endpoint_compatibility

- **预期结果**：旧客户端继续工作，严格模式可附加新验证证据。
- **完成条件**：兼容不是“捕获所有异常后默认成功”，失败仍需稳定错误响应。

---

### 步骤 109：运行全部既有回归测试

- **学习目标**：理解最终验收必须同时证明新增功能和旧功能。
- **本步只修改**：仅修复新改造造成的回归；不得降低断言或删除旧测试。
- **具体改动**：运行当前 23 个 Lineage Python 测试、14 个 AgentDID 安全测试和 9 个合约测试；若数量变化，解释新增或删除来源并保持原有用例全通过。
- **验证命令**：

      conda run -n agentdid python -B -m unittest discover -s _experiments/lineage -p "test_*.py" -v
      conda run -n agentdid python -B -m unittest discover -s _experiments/security_reproduction -p "test_*.py" -v
      npx.cmd hardhat test

- **预期结果**：三套既有测试全通过，无无理由 skip 或 xfail。
- **完成条件**：旧入口、旧安全用例和合约行为均无回归。

---

### 步骤 110：运行本地正式主入口

- **学习目标**：理解测试夹具成功之后还要验证用户实际运行的命令。
- **本步只修改**：只修复主入口运行发现的问题，不改变预期向量。
- **具体改动**：执行默认 Hardhat 完整 run_all；保存 run_id；运行完整性校验和汇总；对 decisions.csv、PESR、HAR、anchor 数和 reverse verification 做最终核对。
- **验证命令**：

      conda run -n agentdid python -B -m _experiments.security_comparison.run_all

- **预期结果**：63 项均 COMPLETED、0 INFRA_ERROR、3 个合法请求接受、Lineage 对 20 个攻击零接受、63 个 anchor 全部可反向验证。
- **完成条件**：run 目录内有 decisions.csv、三方案并列表、指标、延迟/Gas、integrity-report.json，且 overall_pass=true。

---

### 步骤 111：执行 Sepolia 正式主入口

- **学习目标**：理解远程验收是同一完整矩阵的链环境替换，不是抽样 smoke test。
- **本步只修改**：只修复 Sepolia 环境特有问题；禁止增加回退或减少 case。
- **具体改动**：准备显式环境变量；先检查预检报告；确认余额预算；执行完整命令；保留全部 63 项链上回执；出现 INFRA_ERROR 时结果不通过，修复后另开新 run_id 重跑。
- **验证命令**：

      conda run -n agentdid python -B -m _experiments.security_comparison.run_all --sepolia

- **预期结果**：预检通过后完整执行 63 项，产生 63 个 Sepolia 审计 anchor；安全向量与本地一致。
- **完成条件**：63 项 COMPLETED、0 INFRA_ERROR、63 个 anchor 均在 chain ID 11155111 上反向验证；否则不得声称 Sepolia 验收完成。

---

### 步骤 112：形成最终修改与执行结果报告

- **学习目标**：理解“代码已修改”“测试已通过”“正式实验已执行”是三个不同结论。
- **本步只修改**：docs 或 run 目录中的最终报告，不再改业务代码。
- **具体改动**：按“修改文件、关键行为、兼容影响、执行命令、测试计数、run_id、63 项状态、实际向量、PESR/HAR、交易和 Gas、完整性、未完成项”顺序写报告；所有结论链接到具体产物。
- **验证命令**：

      conda run -n agentdid python -B -m _experiments.security_comparison.verify_run --run-id <实际 run_id>

- **预期结果**：报告中的每个数字都能从 run 目录或链上交易重新计算；没有把计划目标写成实际结果。
- **完成条件**：只有 verify_run 成功且所有验收门槛满足时，才使用“完成”；否则明确写“已实现但未完整执行”或“因 INFRA_ERROR 未验收”。

---

## 5. 每次学习提交的建议格式

每完成一个步骤，建议只提交该步骤涉及的文件，并使用如下提交信息结构：

    security-comparison(step-NNN): <本步的单一目标>

提交前至少回答四个问题：

1. 本步新增了哪条安全不变量？
2. 哪个最小正例证明正常行为未被破坏？
3. 哪个最小反例证明目标攻击会被预定层检测？
4. 本步是否意外修改了其他方案或旧演示入口？

## 6. 最终验收清单

- [ ] 第一里程碑“三方案协议与适配器”已通过步骤 039 的全部验证，而不是仅有文件。
- [ ] 21 个场景均有独立构造器、合法控制样本、目标变异和非目标层断言。
- [ ] run_all 实际创建 63 个独立子进程实验。
- [ ] 63 项均为 COMPLETED，且没有 INFRA_ERROR。
- [ ] 每项都有固定的 12 个证据文件。
- [ ] 每项 audit.jsonl 的前序哈希链有效。
- [ ] 每项有独立 evidence manifest、Merkle 根和一次成功 anchor。
- [ ] 完整 run 恰好有 63 个可反向验证的审计锚定交易。
- [ ] 三个 H00 全部接受。
- [ ] A01-A03 在三个方案的共享协议层全部拒绝。
- [ ] A04-A06 被 Original 接受、被 Baseline 与 Lineage 在 Baseline 语义层拒绝。
- [ ] L01-L14 被 Original 与 Baseline 接受、被 Lineage 层拒绝。
- [ ] 实际攻击接受数为 17、14、0，且由 decision.json 计算。
- [ ] PESR、HAR、攻击族检测率、验证延迟、交易延迟和 Gas 均来自实际数据。
- [ ] nonce、VC ID、JTI、budget ID、request hash、context、ReplayGuard、Lineage 子密钥与 epoch 的隔离检查通过。
- [ ] /auth、/probe、/context_hash 和旧 demo 命令保持兼容。
- [ ] 既有 Lineage、AgentDID 安全与合约测试全部继续通过。
- [ ] Sepolia 模式通过余额、RPC、chain ID、两个 Registry 与 relayer 预检。
- [ ] Sepolia 模式没有本地回退，也没有抽样执行。
- [ ] 最终报告明确区分“计划”“实现”“测试”和“实际链上执行”。
