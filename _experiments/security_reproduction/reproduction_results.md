# AgentDID 安全复现实验结果

实验分支：`security`  
真实 LLM：`gpt-5.4-mini`  
真实网络实验：`vp_replay-f7c2b9f3-7ab8-4d42-8e4c-d40fa982fad9`

## 结果总表

| 场景 | 复现情况 | 严格验证结果 | 日志/测试依据 |
|---|---|---|---|
| 智能体冒充 | 已完成离线复现 | 声明 DID 与实际签名 DID 不一致，应拒绝 | `test_impersonation_claim_is_signed_by_attacker` |
| VP 重放 | 已完成真实网络复现 | 第一轮通过；第二轮旧 nonce 被拒绝 | `holder_49872.jsonl`、`demo_Server-agent_c_op.jsonl` |
| 凭证重放 | 已完成离线复现 | 同一 VC 出现两次，严格验证器应拒绝 | `test_duplicate_vc_and_false_capability_profiles` |
| 虚假能力声明 | 已完成离线复现 | 评分改为 `1.000` 后原签名失效，应拒绝 | `test_duplicate_vc_and_false_capability_profiles` |
| 虚假当前状态 | 已完成离线复现 | 第二次仍返回旧上下文哈希 | `test_false_state_replays_initial_hash` |
| 上下文丢失或重置 | 脚本已实现，尚未独立运行网络实验 | 预期本地/远端上下文哈希不一致 | `reset_context.py` |

## 1. 智能体冒充

实验效果：攻击者使用自己的签名密钥，但把 VP 的 `holder` 字段改成受害者 DID。该场景目前由离线测试验证，尚未产生独立 JSONL 网络日志。

离线测试输出：

```text
test_impersonation_claim_is_signed_by_attacker ... ok
```

测试断言：

```text
vp["holder"] == "did:example:victim"
vp["holder"] != "did:example:attacker"
```

## 2. VP 重放

实验效果：第一轮捕获合法 VP；第二轮返回完全相同的 VP，响应哈希相同，但挑战 nonce 已改变。严格验证器拒绝第二轮。

Holder 日志：

```json
{"accepted":true,"event_id":"f64d04e1-0fc7-44b7-b130-c3c48d40a0d8","event_type":"holder_auth_response","evidence_hash":"cd9a2dcf9b252f98db5dbd6b7027f31b8966de960391f51f60a0b49a61d3","metadata":{"attack_mode":"vp_replay","creation_ms":0.0,"experiment_id":"vp_replay-f7c2b9f3-7ab8-4d42-8e4c-d40fa982fad9","injected_behavior":"captured_vp_for_replay"},"reason":"VP returned","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121"}
{"accepted":true,"event_id":"b095475d-4ab6-43cf-b9b2-9aaf1779b5b5","event_type":"holder_auth_response","evidence_hash":"9080d27ec75ad4fed70a5cbdf815c52dfef2c15b0110ad5d994049f1d1f3e08c","metadata":{"attack_mode":"vp_replay","creation_ms":0.0,"experiment_id":"vp_replay-f7c2b9f3-7ab8-4d42-8e4c-d40fa982fad9","injected_behavior":"replayed_previous_vp"},"reason":"VP returned","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121"}
```

Verifier 日志：

```json
{"accepted":true,"event_type":"vp_verification","evidence_hash":"036c3e6b6311f3963bf12e84b4186d28791c723a0ae02d2732eb83ce775854d8","metadata":{"strict_security":true},"reason":"VP Valid","request_hash":"e0b39d44cfc9c64011d13ecf7d4597242c2f44b4acbdad7f2576a3d8898f7228","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121"}
{"accepted":false,"event_type":"vp_verification","evidence_hash":"4c167bb80c2f29741ece78d61784312cfc497882d2ec89018e84e95a8e0c19d1","metadata":{"strict_security":true},"reason":"Nonce mismatch: expected f39ce0a7-2f6d-406a-898f-24d8c7cbc3e4, got 80ca27e6-036c-402f-b09e-408738757d1c","request_hash":"6a49babd3c3cd83e13970e0c942f54779bad6339a9a6042349839858455884d5","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121"}
```

对应文件中的完整原始记录分别为：

`holder_49872.jsonl`

```json
{"accepted":true,"event_id":"f64d04e1-0fc7-44b7-b2b3-72821d7d3cdb","event_type":"holder_auth_response","evidence_hash":"cd9a2dcf9b252f98db5db9e32d6b7027f31b8966de960391f51f60a0b49a61d3","metadata":{"attack_mode":"vp_replay","creation_ms":0.0,"experiment_id":"vp_replay-f7c2b9f3-7ab8-4d42-8e4c-d40fa982fad9","injected_behavior":"captured_vp_for_replay"},"observed_at":"2026-07-16T09:26:38.329886+00:00","reason":"VP returned","request_hash":"e0b39d44cfc9c64011d13ecf7d4597242c2f44b4acbdad7f2576a3d8898f7228","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121","schema_version":"agentdid-security-v1","subject_did":"did:ethr:sepolia:0x645BE26B5674C7A483c34118D23DC5429D0Fde36"}
{"accepted":true,"event_id":"b095475d-4ab6-43cf-b9b2-9aaf1779b5b5","event_type":"holder_auth_response","evidence_hash":"9080d27ec75ad4fed70a5cbdf815c52dfef2c15b0110ad5d994049f1d1f3e08c","metadata":{"attack_mode":"vp_replay","creation_ms":0.0,"experiment_id":"vp_replay-f7c2b9f3-7ab8-4d42-8e4c-d40fa982fad9","injected_behavior":"replayed_previous_vp"},"observed_at":"2026-07-16T09:27:37.566925+00:00","reason":"VP returned","request_hash":"6a49babd3c3cd83e13970e0c942f54779bad6339a9a6042349839858455884d5","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121","schema_version":"agentdid-security-v1","subject_did":"did:ethr:sepolia:0x645BE26B5674C7A483c34118D23DC5429D0Fde36"}
```

`demo_Server-agent_c_op.jsonl`

```json
{"accepted":true,"event_id":"f0876893-69c5-41b0-91a1-37ef37b495a0","event_type":"vp_verification","evidence_hash":"036c3e6b6311f3963bf12e84b4186d28791c723a0ae02d2732eb83ce775854d8","metadata":{"strict_security":true},"observed_at":"2026-07-16T09:26:40.923020+00:00","reason":"VP Valid","request_hash":"e0b39d44cfc9c64011d13ecf7d4597242c2f44b4acbdad7f2576a3d8898f7228","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121","schema_version":"agentdid-security-v1","subject_did":"did:ethr:sepolia:0x645BE26B5674C7A483c34118D23DC5429D0Fde36"}
{"accepted":false,"event_id":"90e88d06-4aeb-4d4d-96c6-aba71405a35b","event_type":"vp_verification","evidence_hash":"4c167bb80c2f29741ece78d61784312cfc497882d2ec89018e84e95a8e0c19d1","metadata":{"strict_security":true},"observed_at":"2026-07-16T09:27:37.568886+00:00","reason":"Nonce mismatch: expected f39ce0a7-2f6d-406a-898f-24d8c7cbc3e4, got 80ca27e6-036c-402f-b09e-408738757d1c","request_hash":"6a49babd3c3cd83e13970e0c942f54779bad6339a9a6042349839858455884d5","response_hash":"7e00a4e1b5b133bc361d68d58efa2675c0b9c2f6a43402b668bb233750d02121","schema_version":"agentdid-security-v1","subject_did":"did:ethr:sepolia:0x645BE26B5674C7A483c34118D23DC5429D0Fde36"}
```

## 3. 凭证重放

实验效果：攻击注入器将同一个 VC 放入 VP 两次。当前为离线复现，未产生独立网络日志。

```text
test_duplicate_vc_and_false_capability_profiles ... ok
duplicate_vp["verifiableCredential"] length == 2
```

## 4. 虚假能力声明

实验效果：将能力评分篡改为 `1.000`，但保留原 Issuer 签名。篡改后的签名验证应失败。当前为离线复现。

```text
test_duplicate_vc_and_false_capability_profiles ... ok
evaluation["ratingValue"] == "1.000"
```

## 5. 虚假当前状态

实验效果：第一次上下文哈希为 `hash-1`，第二次真实状态已变为 `hash-2`，攻击者仍返回 `hash-1`。

```text
test_false_state_replays_initial_hash ... ok
context_hash("hash-1") -> "hash-1"
context_hash("hash-2") -> "hash-1"
```

## 6. 上下文丢失或重置

安全重置接口要求签名请求；旧式无签名重置仅在显式开启 `allow_unsafe_reset` 时允许。当前已完成驱动脚本，但没有独立网络运行日志。

```text
python _experiments/security_reproduction/reset_context.py \
  --holder-url http://localhost:5000 \
  --verifier-role agent_c_op
```

预期严格结果：Verifier 保留旧 transcript，而 Holder 清空记忆，随后 `local_context_hash != remote_context_hash`，审计事件应记录 `reason: "Mismatch"`。

## 离线测试汇总

```text
Ran 9 tests
OK
```

所有 JSONL 事件都包含 `evidence_hash`，用于后续链上锚定；本次未执行 Sepolia 锚定交易。
