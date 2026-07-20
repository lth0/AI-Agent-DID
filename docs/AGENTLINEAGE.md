# AgentLineage-DID MVP

## Runtime Flow

1. A child generates an independent operation key and, only when delegation is allowed, a separate delegation key.
2. `POST /v1/lineage/challenge` returns a one-time enrollment nonce.
3. The child signs the enrollment payload with every declared key.
4. `POST /v1/lineage/spawn` intersects the requested permission with the parent permission and the identity-type policy.
5. The registry reserves a child budget or creates/reuses a keyless ReplicaGroup budget.
6. The parent signs and registers one delegation credential.
7. `POST /v1/lineage/invoke` verifies one complete root-to-leaf chain at the latest block.
8. The registry atomically debits calls and cost, rejects replay, and acquires a concurrency lease.
9. The gateway executes the tool and releases the lease. Failed calls are not refunded.

## Stable Permission DSL

```json
{
  "actions": ["echo"],
  "resources": ["urn:agentlineage:tool:echo"],
  "tasks": ["task-id"],
  "audiences": ["urn:agentlineage:gateway:local"],
  "versions": ["urn:agentlineage:version:sha256:<64-hex-digest>"],
  "not_before": 0,
  "expires_at": 0,
  "remaining_depth": 0,
  "delegable": false
}
```

Collections are sorted, deduplicated exact strings. `"*"` is valid only as the sole element. A child wildcard is legal only when its parent also has a wildcard. Missing fields inherit before attenuation; an empty intersection is rejected.

## Identity Policy

| Type | Maximum TTL | Delegation | Additional rule |
|---|---:|---|---|
| Persistent | 30 days | Explicit | Independent delegation key required |
| Session | 1 hour | Never | Operation key only |
| Instance | 24 hours | Never | ReplicaGroupID required |
| Child | 7 days | Explicit | Defaults to non-delegable |

The maximum chain depth is 8. A content-addressed VersionDID is mandatory for credentials and invocations. ReplicaGroupID is a content-addressed identifier, never a signing identity.

## On-Chain Invariants

* `spent + reserved <= limit` for calls and cost.
* Active and reserved concurrency never exceed the limit.
* A request hash can begin only once.
* A child budget cannot close while it has active calls or child reservations.
* A ReplicaGroup is keyless; all member Instance credentials consume its single shared budget.
* Credential, edge, node/subtree, and epoch revocations are root-scoped.
* Ancestor state is checked by the gateway at `latest`; RPC failure and stale state fail closed.

## Secret Handling

`config/lineage.json`, `.env*`, `.codex/`, keystores, logs, Hardhat artifacts, and cache directories are ignored. Root identity keys, root seeds, relayer keys, keystore passwords, and control tokens must come from environment variables or an external secret manager. The root seed is never written to the public root state.

## Main Components

```text
infrastructure/lineage/
|-- models.py             protocol models and content identifiers
|-- crypto.py             HKDF, EIP-712, wallets, encrypted keystores
|-- policy.py             attenuation and type policy
|-- credentials.py        epoch and delegation credentials
|-- verifier.py           root-to-leaf offline verifier
|-- registry_client.py    Sepolia/Hardhat contract client
|-- service.py            authority, gateway, tool router, audit
`-- runtime.py            environment-only secret loading

contracts/
|-- AgentLineageRegistry.sol
|-- abi/AgentLineageRegistry.json
|-- test/AgentLineageRegistry.test.js
`-- scripts/
```
