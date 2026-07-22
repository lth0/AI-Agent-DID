# develop AgentDID Demo

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18.20-green)](https://nodejs.org/)
[![npm](https://img.shields.io/badge/npm-10.8-red)](https://www.npmjs.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

## 📖 Project Overview

This is a Proof of Concept (PoC) for an Agent decentralized identity authentication system.

The project explores the autonomous interaction capabilities of AI Agents within a Decentralized Identity (DID) network, focusing on the end-to-end authentication flow between Holder Agents and Verifier Agents.

## Local Hardhat Quick Start

本地正式实验不需要 Sepolia RPC、测试币或私钥。安装依赖后，所有实验实例都从根目录 `main.py` 启动：

```powershell
conda create -n agentdid python=3.11 -y
conda run -n agentdid python -m pip install -r requirements.txt
npm.cmd install
conda run -n agentdid python -B main.py list
conda run -n agentdid python -B main.py single --scheme baseline --case A04
conda run -n agentdid python -B main.py all
```

默认最终结果写入 `exp_result/<run_id>/`。下文“统一实验入口”章节给出完整参数和证据说明。

## Optional AgentLineage-DID MVP

The `develop` branch includes an optional privilege-conserving delegation layer. The long-running AgentLineage gateway is disabled by default and does not change the original `/auth`, `/probe`, or `/context_hash` flows. The unified local comparison runner deploys and configures its own isolated Lineage contracts when `main.py single/all` requires them; it does not require enabling the gateway service.

Key properties:

* Tree-only delegation with independent operation and delegation keys.
* `secp256k1`, HKDF-SHA256 domain separation, and EIP-712 signatures.
* Exact-match permission attenuation with a maximum depth of 8.
* On-chain calls, cost, concurrency, replay, lease, and revocation enforcement.
* Keyless ReplicaGroup budgets shared by independently keyed Instance agents.
* Fail-closed latest-state verification at the resource gateway.

The final Sepolia registry is [`0xD08c036042dC2B71dCD59be3E8A58689fb346198`](https://sepolia.etherscan.io/address/0xD08c036042dC2B71dCD59be3E8A58689fb346198). Runtime configuration and all experiment outputs remain ignored by Git.

### AgentLineage Setup

```powershell
conda create -n agentdid python=3.11 -y
conda run -n agentdid python -m pip install -r requirements.txt
npm.cmd install
conda run -n agentdid python _ops_services\configure_lineage.py `
  --registry-address 0xD08c036042dC2B71dCD59be3E8A58689fb346198
```

Set secrets in the current process, a secret manager, or a local configuration file that is confirmed to be ignored by Git. Never commit them:

```powershell
$env:AGENTLINEAGE_ROOT_IDENTITY_KEY = "0x..."
$env:AGENTLINEAGE_ROOT_SEED = "<at-least-64-hex-characters>"
$env:AGENTLINEAGE_RELAYER_KEY = "0x..."
$env:AGENTLINEAGE_KEYSTORE_PASSWORD = "..."
$env:AGENTLINEAGE_CONTROL_TOKEN = "..."
```

For a new registry, initialize epoch 1 and its root budget. For an already registered root, rotate to a fresh epoch instead:

```powershell
conda run -n agentdid python _ops_services\setup_lineage_root.py
conda run -n agentdid python _ops_services\setup_lineage_root.py --rotate
```

Enable and run the policy enforcement gateway:

```powershell
$env:AGENTLINEAGE_ENABLED = "true"
conda run -n agentdid python _ops_services\lineage_server.py --port 8100
```

Create a child identity as an encrypted keystore under `.codex/lineage/keys/`:

```powershell
conda run -n agentdid python _ops_services\create_lineage_identity.py `
  --type session --challenge-url http://127.0.0.1:8100
```

The API exposes `POST /v1/lineage/challenge`, `/spawn`, `/invoke`, `/revoke`, and `GET /v1/lineage/status/<id>`. Spawn and revoke require `X-AgentLineage-Control-Token`. See [`docs/AGENTLINEAGE.md`](docs/AGENTLINEAGE.md) for request flow and invariants.

### AgentLineage Verification

正式的 AgentDID 对比实验实例统一由仓库根目录的 `main.py` 启动。运行一个 Lineage 鲁棒性检查或完整矩阵：

```powershell
conda run -n agentdid python -B main.py single --scheme lineage --case L01
conda run -n agentdid python -B main.py all
```

以下命令仅用于开发回归和性能基准，不会生成正式的 63 项对比实验结果：

```powershell
conda run -n agentdid python -B -m unittest discover -s _experiments\lineage -p "test_*.py" -v
npm.cmd run test:lineage
conda run -n agentdid python -B -m _experiments.lineage.run_benchmark --iterations 10
npm.cmd run benchmark:lineage
```

Evidence produced by the developer regression and benchmark commands above is written only to `.codex/lineage_runs/` and `.codex/lineage/audit/`. Formal `main.py` comparison evidence uses `exp_result/<run_id>/`.

### Core Workflow
1.  **Step 1 (Registration)**: Register a DID and authorize a Delegate (operated by the Agent's actual controller).
2.  **Step 2 (Self-Application)**: Upon startup, the Agent autonomously applies for a VC (Verifiable Credential) from the Issuer.
3.  **Step 3 (Authentication)**: DID-based identity verification between Agents.
4.  **Step 4 (Probe & Audit)**: The Verifier initiates a "Probe Task" to the Holder to perform status detection and Context Consistency Checks.

---

## 🎥 Demonstration Video

Here is a complete demonstration video of the AgentDID workflow.

<video src="media/AgentDID_Demo.mp4" controls="controls" style="max-width: 800px; display: block; margin: auto;">
  Your browser does not support the video tag.
</video>

---

## 🛠️ Prerequisites

This project requires both Python and Node.js environments. To ensure system stability, **the following versions (or higher) are strongly recommended**:

*   **Python**: `3.11.14` (Requires Python 3.10+ syntax support)
*   **Node.js**: `18.20.8` (Used for the DID resolution service)
*   **npm**: `10.8.2`

### Installation Steps

1.  **Install Python Dependencies**:
    ```powershell
    conda create -n agentdid python=3.11 -y
    conda run -n agentdid python -m pip install -r requirements.txt
    ```
2.  **Install Node.js Dependencies**:
    The project root contains `package.json` and `package-lock.json`. Ensure Node.js is installed, then run:
    ```powershell
    npm.cmd install
    ```
3.  **Configure Keys Only for Sepolia**:
    *   Local Hardhat runs do not read private-key configuration.
    *   For any Sepolia run, copy `config/agents_4_key_example.json` to the Git-ignored `config/agents_4_key.json` and fill the required Issuer and Agent controller/operation roles; full mode checks every payer role before sending transactions.
    *   Set the RPC and transaction key through process environment variables as shown below.
    *   ⚠️ **Security Warning**: Never commit `config/agents_4_key.json`, RPC Tokens, private keys, or accounts containing real assets.

---

## 🚀 统一实验入口：`main.py`

仓库根目录的 `main.py` 是三种 DID 方案、21 个鲁棒性检查场景和 63 项完整矩阵的唯一正式运行入口。不要直接调用 `run_one.py`、`run_robustness.py`、`run_lineage_phase1.py`、`run_lineage_robustness.py` 或旧的 attack-matrix runner 来生成正式结果。

所有命令都应在仓库根目录执行。本文使用 Conda 环境 `agentdid`；如果已经激活该环境，可以把 `conda run -n agentdid` 简写为直接调用 `python`。

### 1. 查看入口帮助

```powershell
conda run -n agentdid python -B main.py --help
conda run -n agentdid python -B main.py list --help
conda run -n agentdid python -B main.py single --help
conda run -n agentdid python -B main.py all --help
```

`main.py` 提供三个子命令：

| 子命令 | 用途 | 是否启动区块链 |
|---|---|---:|
| `list` | 查看可用方案、案例和矩阵规模 | 否 |
| `single` | 运行一个“方案 × 案例”独立实例 | 是 |
| `all` | 固定运行 `21 × 3 = 63` 个独立实例 | 是；`--dry-run` 除外 |

### 2. 查看方案和案例

以便于阅读的文本形式列出三种方案和 21 个案例：

```powershell
conda run -n agentdid python -B main.py list
```

输出机器可读取的 JSON：

```powershell
conda run -n agentdid python -B main.py list --json
```

支持的 DID 方案：

| `--scheme` 短名 | 完整名称 | 验证能力 |
|---|---|---|
| `original` | `Original-AgentDID` | DID 身份和统一 DID/VC/VP 协议验证 |
| `baseline` | `Baseline-AgentDID` | Original + 能力、状态、上下文等严格策略 |
| `lineage` | `Lineage-AgentDID` | Baseline + 委托谱系、权限、预算、重放和撤销验证 |

`--scheme` 同时接受短名和完整名称，例如 `baseline` 与 `Baseline-AgentDID` 等价。

支持的 21 个案例均按鲁棒性检查解释：

| 案例 | 检查内容 | 案例 | 检查内容 |
|---|---|---|---|
| `H00` | 合法 DID/VC/VP 和授权请求 | `A01` | DID 与签名密钥绑定 |
| `A02` | VP challenge 新鲜度和防重放 | `A03` | VC subject 与 VP holder 绑定 |
| `A04` | 能力声明与独立评测证据一致性 | `A05` | 当前状态与真实工件摘要一致性 |
| `A06` | 上下文哈希和版本连续性 | `L01` | action 范围约束 |
| `L02` | resource 范围约束 | `L03` | 子委托权限不得扩大 |
| `L04` | 子委托有效期不得延长 | `L05` | 委托深度必须收缩 |
| `L06` | session 身份不可重新获得委托权 | `L07` | operation key 不可签发委托 |
| `L08` | 调用必须绑定正确叶凭证 | `L09` | 委托分支必须连续 |
| `L10` | task 范围约束 | `L11` | audience 绑定 |
| `L12` | 祖先撤销向后代传播 | `L13` | request origin 与叶身份绑定 |
| `L14` | 调用版本与叶凭证绑定 |  |  |

`A01-A06` 和 `L01-L14` 是确定性的 Agent 鲁棒性检查标签，不表示 README 在指导真实攻击行为。

### 3. 运行单个实例

基本语法是 `main.py single --scheme SCHEME --case CASE_ID`；其中 `SCHEME` 和 `CASE_ID` 必须替换为下方示例中的实际值。

典型示例：

```powershell
# 合法请求：Original-AgentDID
conda run -n agentdid python -B main.py single --scheme original --case H00

# 能力证据一致性：Baseline-AgentDID
conda run -n agentdid python -B main.py single --scheme baseline --case A04

# 祖先撤销传播：Lineage-AgentDID；完整方案名和小写案例也可识别
conda run -n agentdid python -B main.py single --scheme Lineage-AgentDID --case l12
```

为学习过程指定可读的运行标识和输出路径：

```powershell
conda run -n agentdid python -B main.py single `
  --scheme baseline `
  --case A04 `
  --run-id study-baseline-a04-001 `
  --output-root .\exp_result
```

注意：

- `--case` 与 `--case-id` 等价，案例值不区分大小写。
- 本地 Hardhat 单例会自动启动临时链、部署合约、执行一次实验并完成一次证据锚定。
- 显式提供 `--run-id` 时，它必须是安全的单一路径名，不能包含 `..`、斜杠或绝对路径。
- 本地单例必须使用新的 `run-id`，避免把旧链的 DID 初始化状态误用于新链。不提供 `--run-id` 时会自动生成。
- 某个检查“拒绝请求”不等于实验失败。例如 Baseline 的 `A04` 预期拒绝；只要实际结果与预期一致，`decision.json` 中仍会记录 `passed: true`，进程退出码为 `0`。

### 4. 运行完整 63 项矩阵

先查看计划，不启动 Hardhat，也不生成正式验收结果：

```powershell
conda run -n agentdid python -B main.py all --dry-run
```

在一次共享的本地 Hardhat 生命周期内执行全部 63 项：

```powershell
conda run -n agentdid python -B main.py all
```

指定运行标识、单个子进程超时和错误处理方式：

```powershell
conda run -n agentdid python -B main.py all `
  --run-id full-local-001 `
  --timeout-seconds 900 `
  --fail-fast
```

正式 `all` 模式固定运行全部 63 项，因此不接受 `--scheme` 或 `--case` 过滤。学习和调试单项时使用 `single`。

### 5. 参数参考

`single` 和 `all` 的公共参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--chain` | `hardhat` | 链后端：`hardhat` 或 `sepolia`；Sepolia 全量会先执行严格只读预检 |
| `--run-id` | 自动生成 | 本次运行的安全单路径标识 |
| `--output-root` | `<仓库根目录>/exp_result` | 最终证据和汇总输出目录 |
| `--temp-root` | `<仓库根目录>/.codex/comparison_tmp` | 子进程、Hardhat 日志等临时文件目录 |

`single` 专用参数：

| 参数 | 是否必需 | 说明 |
|---|---:|---|
| `--scheme` | 是 | DID 方案短名或完整名称 |
| `--case` / `--case-id` | 是 | `H00`、`A01-A06` 或 `L01-L14` |
| `--experiment-id` | 否 | 覆盖自动生成的独立实验 ID |
| `--lineage-epoch` | 否 | Lineage epoch，必须为正整数，默认 `1` |
| `--chain-id` | 否 | 高级链配置；与两个 Registry 参数同时提供 |
| `--did-registry` | 否 | 高级链配置：DID Registry 地址 |
| `--lineage-registry` | 否 | 高级链配置：Lineage Registry 地址 |

`all` 专用参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--timeout-seconds` / `--timeout` | `900` | 每个独立子进程的最大执行秒数；Sepolia 不接受低于 `900` 秒 |
| `--fail-fast` | 关闭 | 首个失败后停止；仅建议调试使用 |
| `--dry-run` | 关闭 | 只打印固定的 63 项计划 |

### 6. 输出目录和证据

默认最终输出位于 Git 已忽略的 `exp_result/`：

```text
exp_result/<run_id>/
├── summary.json                 # 仅 all
├── decisions.csv               # 仅 all
├── comparison-table.csv        # 仅 all
├── integrity-report.json       # 仅 all
└── experiments/
    └── <scheme-directory>/<case-id>/
        ├── experiment-config.json
        ├── did-documents.json
        ├── credentials.json
        ├── presentation.json
        ├── verification-trace.json
        ├── state-and-context.json
        ├── lineage-evidence.json
        ├── robustness-evidence.json
        ├── decision.json
        ├── audit.jsonl
        ├── evidence-manifest.json
        ├── chain-activity.json
        └── chain-anchor.json
```

其中：

- `decision.json` 是单项判定入口，区分 `accepted`、`passed` 和 `INFRA_ERROR`。
- `single` 直接生成一个实验目录；`summary.json`、两个 CSV 和 `integrity-report.json` 由 `all` 汇总生成。
- `audit.jsonl` 是带前序事件哈希的链下审计日志链。
- `evidence-manifest.json` 和 `chain-anchor.json` 用于验证 Merkle 根及链上锚定。
- `decisions.csv` 和 `comparison-table.csv` 用于比较三种方案。
- `integrity-report.json` 汇总 63 项隔离性、证据完整性和链上反向验证结果。

### 7. 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 实验完成，实际响应符合预期且完整性检查通过 |
| `1` | 基础设施、链连接、预检、证据或子进程失败 |
| `2` | 实验已完成，但至少一项响应不符合预期向量 |

自动化脚本应以退出码和结构化 JSON/CSV 为准，不要通过搜索控制台文本判断实验成败。

### 8. Hardhat 与 Sepolia

- `--chain hardhat` 是默认模式。`single` 使用独立临时链；`all` 在一次共享部署中串行运行 63 个隔离子进程，以避免签名账户 nonce 冲突。这里的“独立”指子进程、随机标识、实验状态和证据目录独立，不表示 63 次重复部署链与合约。
- `single --chain sepolia` 会执行远程 RPC、chain ID 和 DID Registry 预检；预检通过后执行指定的一个实验并锚定证据，任何失败都会关闭式返回 `INFRA_ERROR`，不会回退到 Hardhat。
- `all --chain sepolia` 会由父进程执行且只执行一次完整只读预检，检查 RPC、chain ID、节点同步状态、DID/Lineage Registry 字节码与只读接口、Root governance、15 个实际上链的 Lineage 实验所需 epoch 容量与预算命名空间、Actor/Relayer 的 `latest == pending` nonce、余额和 Gas 预算。只有全部通过后，父进程才进行一次共享 DID 初始化并串行启动 63 个子进程。
- Lineage 适配器先在链下 `prepare`，并且只有共享协议与 Baseline 都通过后才 `materialize` 到 Registry。因而 A01–A03 在共享协议层停止，A04–A06 在 Baseline 层停止；这 6 个 Lineage 方案实例仍生成完整决策、证据与审计锚定，但不会发送 Lineage Registry 交易。真正占用 Lineage epoch 和预算命名空间的是 H00 与 L01–L14，共 15 个实例。
- 父进程把预检报告及其 SHA-256 完整性摘要传给子进程；每个子进程在发送交易前校验固定 63 项计划、run、experiment、chain、Actor、Registry 实时代码、报告路径和摘要。该摘要用于父子进程间的防篡改绑定，不是对不可信本地调用者的数字签名；`--full-preflight*` 属于内部参数，正式全量运行必须从 `main.py all` 进入。
- Sepolia full 在首个基础设施错误、链配置不一致或响应不一致后强制停止，且任何阶段都不会回退 Hardhat。共享交易账户需要串行使用，每个子进程必须使用至少 `900` 秒超时。
- Sepolia 环境变量名和占位值见 [`.env.example`](.env.example)；不要把占位文件直接改成真实密钥文件提交。
- RPC Token、私钥和其他敏感信息只能放入进程环境变量或忽略的本地配置，不能写入 README、实验证据或 Git。

Sepolia 会合并两个被 Git 忽略的本地配置：`config/agents_4_key.json` 提供完整的 Agent admin/op 角色，`config/key.json` 覆盖 RPC 配置与 `issuer` 私钥；未设置环境变量时，该 `issuer` 即为默认交易付款账户。`AGENTDID_EXPERIMENT_CHAIN_KEY` 仅用于显式覆盖付款私钥，优先级最高。Sepolia 单例示例：

```powershell
$env:AGENTDID_EXPERIMENT_RPC_URL = "https://eth-sepolia.example/v2/replace-me"
# 可选：$env:AGENTDID_EXPERIMENT_CHAIN_KEY = "0xREPLACE_WITH_SEPOLIA_TRANSACTION_KEY"
$env:AGENTDID_DID_REGISTRY_ADDRESS = "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818"
$env:AGENTDID_LINEAGE_REGISTRY_ADDRESS = "0xD08c036042dC2B71dCD59be3E8A58689fb346198"
$env:AGENTDID_EXPERIMENT_CONFIRMATIONS = "2"
$env:AGENTDID_FULL_FEE_SAFETY_BPS = "20000"
conda run -n agentdid python -B main.py single --scheme original --case H00 --chain sepolia
```

若 `config/key.json` 和 `config/agents_4_key.json` 已准备好，CMD 全量命令无需在命令行中展开私钥：

```cmd
conda run -n agentdid python main.py all --chain sepolia --run-id sepolia-full-002 --timeout-seconds 900
```

完整 Sepolia 矩阵会产生约 `160–164` 笔测试网交易：15 个 materialized Lineage 实例共 97 笔业务交易、63 笔独立审计锚定，以及按控制 DID 当前状态决定的 0–4 笔共享初始化交易。请为 Relayer 和需要初始化的 DID controller 备足 Sepolia 测试币，建议先设置可接受的总成本上限并使用新的 `run-id`：

```powershell
$env:AGENTDID_FULL_MAX_COST_ETH = "0.25"
conda run -n agentdid python -B main.py all `
  --chain sepolia `
  --run-id full-sepolia-001 `
  --timeout-seconds 900
```

预检报告写入 `exp_result/<run_id>/preflight.json`。`AGENTDID_FULL_FEE_SAFETY_BPS` 为 RPC 费用报价增加安全余量，形成整次运行强制使用的 `fee_upper_bound_wei`；可选的 `AGENTDID_FULL_MAX_COST_ETH` 是全量运行成本上限。预检按 Relayer `50,000,000` Gas 总预算和每个待初始化 DID controller `100,000` Gas 计算逐付款账户余额。运行时还会在签名和广播前强制检查：每笔 Lineage 交易不超过 `450,000` Gas、每笔 anchor 固定为 `70,000` Gas、每笔 DID controller 初始化不超过 `100,000` Gas，并且所有发送路径的 gas price 或 EIP-1559 max fee 不超过预检 fee cap。任一费用或 Gas 上限超出都会在广播前失败；余额、pending nonce、Registry 接口、治理、epoch 容量或预算命名空间不满足要求同样以退出码 `1` 结束。

延迟 materialize 修复后的完整本地复跑 `run_id=sepolia-impl-local-final-a31f6d` 已验证通过：63/63 `COMPLETED`、0 `INFRA_ERROR`、63 个 anchor、97 笔 Lineage 交易/事件、4 笔 DID setup，合计 164 笔交易；101 笔 DID+Lineage canonical 交易和 63 个 anchor 均完成反查。A01–A06 的 Lineage 实例均为 `prepared=true`、`materialized=false`、`enforcement=false`、0 Registry 交易。实测 Gas 为 Lineage 19,049,662、anchor 1,448,790、DID setup 204,888，总计 20,703,340，运行约 203.5 秒。

上述结果验证的是本地 Hardhat 全量路径，不代表仓库维护者已经付费完成一次真实的 63 项 Sepolia 验收。只有用户显式执行远程命令、备足测试币，并得到 63/63 `COMPLETED`、0 `INFRA_ERROR` 和 63 个 chain ID `11155111` 上可反向验证的锚定后，才能声称 Sepolia 全量验收完成。

### 9. 推荐学习顺序

```powershell
# 1. 了解全部方案和场景
conda run -n agentdid python -B main.py list

# 2. 运行三种方案的合法请求
conda run -n agentdid python -B main.py single --scheme original --case H00
conda run -n agentdid python -B main.py single --scheme baseline --case H00
conda run -n agentdid python -B main.py single --scheme lineage --case H00

# 3. 分别观察协议层、Baseline 层和 Lineage 层的鲁棒性检查
conda run -n agentdid python -B main.py single --scheme original --case A02
conda run -n agentdid python -B main.py single --scheme baseline --case A04
conda run -n agentdid python -B main.py single --scheme lineage --case L01

# 4. 查看计划后执行完整矩阵
conda run -n agentdid python -B main.py all --dry-run
conda run -n agentdid python -B main.py all
```

### 10. 旧工作流说明

`_demo_2v2/`、早期 massive experiment 脚本和分阶段 runner 仍保留用于历史复现或开发维护，但它们不属于当前三方案、63 项正式对比结果。需要运行正式实验实例时，一律使用根目录 `main.py`。

---

## 📊 Benchmarks

以下性能工具是独立的开发基准，不是三方案、63 项正式实验实例，也不能替代 `main.py all` 的验收结果。

*   **VC Size Measurement**: Run `_experiments/measure_vc_size.py` to analyze the storage overhead for different VC schemas.
*   **Context Hash Performance**: Run `_experiments/context_test.py` to test the time cost curve of hash calculations as conversation rounds increase.

---

## ⚠️ Troubleshooting

*   **FileNotFoundError**: Usually a path issue. Please ensure you are running scripts from the project root directory.
*   **DID Resolution Failed**: Check if Node.js is installed and the `node` command is in your system PATH.
*   **Insufficient Gas**: For Sepolia runs, ensure the Relayer and every DID controller that still needs shared initialization have enough Sepolia ETH. Full mode also reports its per-payer balance requirement and estimated maximum cost in `preflight.json`.

## License

[MIT License](LICENSE)
