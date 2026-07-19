# AgentDID security reproduction

This directory reproduces five adversarial behaviours using only test DIDs and
the local/Sepolia demo network.  Every attack is disabled by default.

## Safety switches

- Holder attack: `AGENTDID_ATTACK_MODE`, injected per Holder by the generated config.
- Original 2v2 verifier behaviour: `strict_security: false`.
- Original unsigned reset endpoint: `allow_unsafe_reset: true`.
- Strict issuer allow-list: `AGENTDID_STRICT_ISSUER=true` by default.

Evidence is appended under `.codex/security_results/`.  Each record contains
request/response hashes and an `evidence_hash`; raw private keys are never written.

## Common workflow

Generate one runtime config:

```powershell
python _experiments/security_reproduction/prepare_experiment.py vp_replay
```

Start the Issuer, network, and audit using the printed config path:

```powershell
python _ops_services/issuer_server.py
python _demo_2v2/start_network.py .codex/security_experiments/vp_replay_network.json
python _demo_2v2/trigger_audit.py .codex/security_experiments/vp_replay_network.json
```

For a single tracked local run (including automatic cleanup), use:

```powershell
python _experiments/security_reproduction/run_local_network.py `
  .codex/security_experiments/vp_replay_network.json --issuer
```

Run each attack against both verifier modes:

```powershell
# Strict verifier: expected to reject
python _experiments/security_reproduction/prepare_experiment.py vp_replay

# Legacy 2v2 verifier: reproduces the original missing VP verification
python _experiments/security_reproduction/prepare_experiment.py vp_replay --legacy-verifier
```

## Scenarios

### Agent impersonation

The attacker signs a VP with its own operation key but claims a victim DID.

```powershell
python _experiments/security_reproduction/prepare_experiment.py impersonation `
  --impersonated-did "did:ethr:sepolia:0xVICTIM"
```

Strict expected result: `Holder mismatch` or unauthorized signer.

### VP replay

The Holder captures the first legal VP and returns it for the next challenge.
The strict verifier rejects the old `proof.challenge`.

### Credential replay

`vc_replay_duplicate` inserts the same VC twice into a newly signed VP.  The
strict verifier rejects the duplicate credential fingerprint.

### False capability

`false_capability` changes the capability rating to `1.000`, then signs the VP.
The unchanged Issuer proof no longer validates, so the strict verifier rejects it.
This tests tampering; a separate semantic test is still required to prove that
an Issuer actually ran the benchmark before issuing an otherwise valid claim.

The current Issuer also supports that semantic comparison. In legacy mode it
signs the static template and marks the VC with
`issuanceBasis.evidenceVerified=false`. In strict mode it omits the capability
VC unless independently signed benchmark evidence is supplied:

```powershell
# Legacy semantic failure: static capability is signed without a benchmark.
$env:AGENTDID_ISSUER_REQUIRE_CAPABILITY_EVIDENCE="false"
python _ops_services/issuer_server.py

# Strict positive control: create evaluator-signed evidence for Holder-A.
python _experiments/security_reproduction/create_capability_evidence.py `
  --agent-role agent_a_op --evaluator-role agent_c_op --rating 0.75
$env:AGENTDID_ISSUER_REQUIRE_CAPABILITY_EVIDENCE="true"
$env:AGENTDID_CAPABILITY_EVIDENCE_FILE=".codex/security_experiments/capability_evidence_agent_a_op.json"
python _ops_services/issuer_server.py
```

The evaluator DID must be registered/delegated in the same test network. The
evidence binds the score, dataset, report, evaluator, and evaluated Agent DID.

### False current state

`false_state` captures the first context hash and reports it after local state
changes.  The response is still Holder-signed; the verifier detects the mismatch
against its independently retained transcript.

### Context loss/reset

Secure, signed reset request:

```powershell
python _experiments/security_reproduction/prepare_experiment.py context_reset_secure
python _experiments/security_reproduction/reset_context.py `
  --holder-url http://localhost:5000 --verifier-role agent_c_op
```

Legacy unsigned attack reproduction:

```powershell
python _experiments/security_reproduction/prepare_experiment.py context_reset_legacy
python _experiments/security_reproduction/reset_context.py `
  --holder-url http://localhost:5000 --verifier-role agent_c_op --unsigned
```

After either reset, trigger another audit.  The context phase should report a
hash mismatch because the Verifier retained its transcript while the Holder did
not.

## Offline checks

```powershell
python -m unittest _experiments.security_reproduction.test_security -v
```

## Sepolia evidence anchoring

Verifier and Holder events are written as hash-protected JSONL records under
`.codex/security_results`. Anchor the last event with a zero-value transaction:

```powershell
python _experiments/security_reproduction/anchor_evidence.py anchor `
  .codex/security_results/verifier_Runtime-agent_c_op.jsonl --role agent_c_op
```

Verify the transaction input later:

```powershell
python _experiments/security_reproduction/anchor_evidence.py verify `
  0xTRANSACTION_HASH --evidence-hash 64_HEX_DIGEST --role agent_c_op
```

Only the SHA-256 evidence hash is placed on-chain; prompts, responses, and keys
remain off-chain.

## LLM preflight

Keep the API key out of Git and pass it through the environment:

```powershell
$env:AGENTDID_ANTHROPIC_API_KEY = "<your-api-key>"
$env:AGENTDID_ANTHROPIC_BASE_URL = "https://bjtuppml.art/v1"
$env:AGENTDID_LLM_MODEL = "deepseek-v4-pro"
python _experiments/security_reproduction/llm_preflight.py
```

The adapter converts the OpenCode-style `/v1` URL to the root URL expected by
the Python Anthropic client, which appends `/v1/messages` itself.
