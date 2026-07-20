const { expect } = require("chai");
const { ethers } = require("hardhat");
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

const TYPES = {
  AgentLineageEnvelope: [
    { name: "purpose", type: "string" },
    { name: "payloadHash", type: "bytes32" },
  ],
};

function id(value) {
  return ethers.sha256(ethers.toUtf8Bytes(value));
}

async function signEnvelope(wallet, registry, purpose, payloadHash) {
  const network = await ethers.provider.getNetwork();
  return wallet.signTypedData(
    {
      name: "AgentLineage-DID",
      version: "1",
      chainId: network.chainId,
      verifyingContract: await registry.getAddress(),
    },
    TYPES,
    { purpose, payloadHash },
  );
}

async function expectFailure(promise, reason) {
  try {
    await promise;
    expect.fail(`expected transaction to fail with ${reason}`);
  } catch (error) {
    expect(String(error.message)).to.include(reason);
  }
}

describe("AgentLineageRegistry", function () {
  let registry;
  let governance;
  let epochKey;
  let parentOp;
  let parentDel;
  let leafOp;
  let relayer;
  let rootId;
  let epochHash;

  beforeEach(async function () {
    [governance, epochKey, parentOp, parentDel, leafOp, relayer] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("AgentLineageRegistry");
    registry = await Factory.deploy();
    await registry.waitForDeployment();
    rootId = id("did:ethr:sepolia:root");
    epochHash = id("epoch-1-certificate");
    await registry.connect(governance).registerRoot(rootId, 1, epochKey.address, epochHash);
  });

  async function registerDelegation({
    credentialId,
    parentCredentialId = ethers.ZeroHash,
    credentialHash,
    parentCredentialHash = epochHash,
    parentId = rootId,
    childId,
    edgeId,
    lineageCommitment,
    policyHash,
    budgetId,
    replicaGroupId = ethers.ZeroHash,
    operationKey,
    delegationKey = ethers.ZeroAddress,
    signer = epochKey,
    expiresAt,
  }) {
    const encoded = abiCoder.encode(
      [
        "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
        "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "address", "address", "uint64",
      ],
      [
        credentialId, parentCredentialId, credentialHash, parentCredentialHash, rootId,
        parentId, childId, edgeId, lineageCommitment, policyHash, budgetId, replicaGroupId,
        operationKey, delegationKey, expiresAt,
      ],
    );
    const signature = await signEnvelope(
      signer,
      registry,
      "AgentLineage/REGISTER_DELEGATION/v1",
      ethers.keccak256(encoded),
    );
    return registry.connect(relayer).registerDelegation(
      credentialId, parentCredentialId, credentialHash, parentCredentialHash, rootId,
      parentId, childId, edgeId, lineageCommitment, policyHash, budgetId, replicaGroupId,
      operationKey, delegationKey, expiresAt, signature,
    );
  }

  async function reserve({ parentBudgetId, childBudgetId, ownerCredentialId, calls, cost, concurrency, signer }) {
    const encoded = abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint32"],
      [parentBudgetId, childBudgetId, ownerCredentialId, calls, cost, concurrency],
    );
    const signature = await signEnvelope(
      signer,
      registry,
      "AgentLineage/RESERVE_BUDGET/v1",
      ethers.keccak256(encoded),
    );
    return registry.connect(relayer).reserveChildBudget(
      parentBudgetId, childBudgetId, ownerCredentialId, calls, cost, concurrency, signature,
    );
  }

  async function createReplicaGroup({ parentBudgetId, groupId, groupBudgetId, calls, cost, concurrency, signer }) {
    const encoded = abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint32"],
      [parentBudgetId, groupId, groupBudgetId, calls, cost, concurrency],
    );
    const signature = await signEnvelope(
      signer,
      registry,
      "AgentLineage/CREATE_REPLICA_GROUP/v1",
      ethers.keccak256(encoded),
    );
    return registry.connect(relayer).createReplicaGroupBudget(
      parentBudgetId, groupId, groupBudgetId, calls, cost, concurrency, signature,
    );
  }

  async function createFirstLeaf({
    calls = 10,
    cost = 100,
    concurrency = 2,
    rootCalls = 100,
    rootCost = 1000,
    rootConcurrency = 10,
  } = {}) {
    const latest = await ethers.provider.getBlock("latest");
    const values = {
      credentialId: id("credential-1"),
      credentialHash: id("credential-hash-1"),
      childId: id("child-1"),
      edgeId: id("edge-root-child-1"),
      lineageCommitment: id("lineage-1"),
      policyHash: id("policy-1"),
      budgetId: id("budget-child-1"),
      operationKey: parentOp.address,
      delegationKey: parentDel.address,
      expiresAt: latest.timestamp + 3600,
    };
    await registerDelegation(values);
    const rootBudgetId = id("budget-root");
    await registry.connect(governance).createRootBudget(
      rootBudgetId, rootId, rootCalls, rootCost, rootConcurrency,
    );
    await reserve({
      parentBudgetId: rootBudgetId, childBudgetId: values.budgetId,
      ownerCredentialId: values.credentialId, calls, cost, concurrency, signer: epochKey,
    });
    return { ...values, rootBudgetId };
  }

  it("enforces atomic invocation budgets and request replay protection", async function () {
    const leaf = await createFirstLeaf({ calls: 2, cost: 10, concurrency: 1 });
    const requestHash = id("request-1");
    const signature = await signEnvelope(
      parentOp, registry, "AgentLineage/REQUEST/v1", requestHash,
    );
    await registry.connect(relayer).beginInvocation(
      leaf.credentialId, leaf.budgetId, requestHash, 4, 30, signature,
    );
    await expectFailure(
      registry.connect(relayer).beginInvocation(
        leaf.credentialId, leaf.budgetId, requestHash, 4, 30, signature,
      ),
      "REQUEST_REPLAY",
    );
    await registry.connect(relayer).finishInvocation(requestHash);
    const budget = await registry.budgets(leaf.budgetId);
    expect(Number(budget.spentCalls)).to.equal(1);
    expect(Number(budget.spentCost)).to.equal(4);
    expect(budget.activeConcurrency).to.equal(0n);
  });

  it("prevents sibling quota laundering", async function () {
    const first = await createFirstLeaf({ calls: 60, cost: 200, concurrency: 2 });
    const latest = await ethers.provider.getBlock("latest");
    const second = {
      credentialId: id("credential-2"), credentialHash: id("credential-hash-2"),
      childId: id("child-2"), edgeId: id("edge-root-child-2"),
      lineageCommitment: id("lineage-2"), policyHash: id("policy-2"),
      budgetId: id("budget-child-2"), operationKey: leafOp.address,
      expiresAt: latest.timestamp + 3600,
    };
    await registerDelegation(second);
    await expectFailure(
      reserve({
        parentBudgetId: first.rootBudgetId, childBudgetId: second.budgetId,
        ownerCredentialId: second.credentialId, calls: 60, cost: 200,
        concurrency: 2, signer: epochKey,
      }),
      "CALL_BUDGET_EXCEEDED",
    );
  });

  it("closes a nested budget and propagates spent units to its parent", async function () {
    const first = await createFirstLeaf({ calls: 50, cost: 500, concurrency: 5 });
    const latest = await ethers.provider.getBlock("latest");
    const child = {
      credentialId: id("credential-nested"), parentCredentialId: first.credentialId,
      credentialHash: id("credential-hash-nested"), parentCredentialHash: first.credentialHash,
      parentId: first.childId, childId: id("nested-child"), edgeId: id("nested-edge"),
      lineageCommitment: id("nested-lineage"), policyHash: id("nested-policy"),
      budgetId: id("nested-budget"), operationKey: leafOp.address,
      delegationKey: ethers.ZeroAddress, signer: parentDel,
      expiresAt: latest.timestamp + 1800,
    };
    await registerDelegation(child);
    await reserve({
      parentBudgetId: first.budgetId, childBudgetId: child.budgetId,
      ownerCredentialId: child.credentialId, calls: 10, cost: 100,
      concurrency: 1, signer: parentDel,
    });

    const closeEncoded = abiCoder.encode(
      ["bytes32", "uint64", "uint64"], [child.budgetId, 0, 0],
    );
    const closeSig = await signEnvelope(
      leafOp, registry, "AgentLineage/CLOSE_BUDGET/v1", ethers.keccak256(closeEncoded),
    );
    await registry.connect(relayer).closeBudget(child.budgetId, closeSig);
    const parent = await registry.budgets(first.budgetId);
    expect(Number(parent.reservedCalls)).to.equal(0);
  });

  it("invalidates descendants through ancestor node and epoch revocation", async function () {
    const first = await createFirstLeaf();
    let state = await registry.getValidationState(
      rootId, 1, [first.credentialId], [first.edgeId], [first.childId],
    );
    expect(state.active).to.equal(true);
    await registry.connect(governance).revokeNode(rootId, first.childId);
    state = await registry.getValidationState(
      rootId, 1, [first.credentialId], [first.edgeId], [first.childId],
    );
    expect(state.active).to.equal(false);
    await registry.connect(governance).revokeEpoch(rootId, 1);
    state = await registry.getValidationState(rootId, 1, [], [], []);
    expect(state.active).to.equal(false);
  });

  it("supports credential and edge revocation independently", async function () {
    const first = await createFirstLeaf();
    await registry.connect(governance).revokeEdge(rootId, first.edgeId);
    let state = await registry.getValidationState(
      rootId, 1, [first.credentialId], [first.edgeId], [first.childId],
    );
    expect(state.active).to.equal(false);
    expect(ethers.decodeBytes32String(state.reason)).to.equal("EDGE_REVOKED");
    expect(await registry.revokedEdges(rootId, first.edgeId)).to.equal(true);
    await registry.connect(governance).revokeCredential(rootId, first.credentialId);
    state = await registry.getValidationState(rootId, 1, [first.credentialId], [], []);
    expect(state.active).to.equal(false);
    expect(ethers.decodeBytes32String(state.reason)).to.equal("CREDENTIAL_INACTIVE");
  });

  it("rejects descendant registration after the parent node is revoked", async function () {
    const first = await createFirstLeaf();
    await registry.connect(governance).revokeNode(rootId, first.childId);
    const latest = await ethers.provider.getBlock("latest");
    await expectFailure(
      registerDelegation({
        credentialId: id("credential-after-revoke"),
        parentCredentialId: first.credentialId,
        credentialHash: id("credential-hash-after-revoke"),
        parentCredentialHash: first.credentialHash,
        parentId: first.childId,
        childId: id("child-after-revoke"),
        edgeId: id("edge-after-revoke"),
        lineageCommitment: id("lineage-after-revoke"),
        policyHash: id("policy-after-revoke"),
        budgetId: id("budget-after-revoke"),
        operationKey: leafOp.address,
        signer: parentDel,
        expiresAt: latest.timestamp + 300,
      }),
      "PARENT_NODE_REVOKED",
    );
  });

  it("rejects credentials from another root in a batch state query", async function () {
    const first = await createFirstLeaf();
    const otherRoot = id("did:ethr:sepolia:other-root");
    await registry.connect(governance).registerRoot(otherRoot, 1, epochKey.address, id("other-epoch"));
    const state = await registry.getValidationState(
      otherRoot, 1, [first.credentialId], [], [],
    );
    expect(state.active).to.equal(false);
    expect(ethers.decodeBytes32String(state.reason)).to.equal("CREDENTIAL_ROOT_MISMATCH");
  });

  it("enforces 100 concurrent leases and reaps an expired lease", async function () {
    this.timeout(60000);
    const leaf = await createFirstLeaf({
      calls: 101,
      cost: 200,
      concurrency: 100,
      rootCalls: 200,
      rootCost: 1000,
      rootConcurrency: 100,
    });
    const requestHashes = [];
    for (let index = 0; index < 100; index += 1) {
      const requestHash = id(`concurrent-request-${index}`);
      const signature = await signEnvelope(
        parentOp, registry, "AgentLineage/REQUEST/v1", requestHash,
      );
      await registry.connect(relayer).beginInvocation(
        leaf.credentialId, leaf.budgetId, requestHash, 1, 1, signature,
      );
      requestHashes.push(requestHash);
    }
    const overflowHash = id("concurrent-overflow");
    const overflowSignature = await signEnvelope(
      parentOp, registry, "AgentLineage/REQUEST/v1", overflowHash,
    );
    await expectFailure(
      registry.connect(relayer).beginInvocation(
        leaf.credentialId, leaf.budgetId, overflowHash, 1, 1, overflowSignature,
      ),
      "CONCURRENCY_BUDGET_EXCEEDED",
    );
    await ethers.provider.send("evm_increaseTime", [2]);
    await ethers.provider.send("evm_mine", []);
    await registry.connect(governance).reapExpiredInvocation(requestHashes[0]);
    const budget = await registry.budgets(leaf.budgetId);
    expect(budget.activeConcurrency).to.equal(99n);
  });

  it("forces replicas to consume one shared group budget", async function () {
    const rootBudgetId = id("replica-root-budget");
    const groupId = id("replica-group");
    const groupBudgetId = id("replica-group-budget");
    await registry.connect(governance).createRootBudget(rootBudgetId, rootId, 3, 30, 2);
    await createReplicaGroup({
      parentBudgetId: rootBudgetId,
      groupId,
      groupBudgetId,
      calls: 3,
      cost: 30,
      concurrency: 2,
      signer: epochKey,
    });
    const latest = await ethers.provider.getBlock("latest");
    const first = {
      credentialId: id("replica-credential-1"), credentialHash: id("replica-hash-1"),
      childId: id("replica-child-1"), edgeId: id("replica-edge-1"),
      lineageCommitment: id("replica-lineage-1"), policyHash: id("replica-policy-1"),
      budgetId: groupBudgetId, replicaGroupId: groupId, operationKey: parentOp.address,
      expiresAt: latest.timestamp + 3600,
    };
    const second = {
      credentialId: id("replica-credential-2"), credentialHash: id("replica-hash-2"),
      childId: id("replica-child-2"), edgeId: id("replica-edge-2"),
      lineageCommitment: id("replica-lineage-2"), policyHash: id("replica-policy-2"),
      budgetId: groupBudgetId, replicaGroupId: groupId, operationKey: leafOp.address,
      expiresAt: latest.timestamp + 3600,
    };
    await registerDelegation(first);
    await registerDelegation(second);
    const requests = [
      [first, parentOp, id("replica-request-1")],
      [first, parentOp, id("replica-request-2")],
      [second, leafOp, id("replica-request-3")],
    ];
    for (const [credential, signer, requestHash] of requests) {
      const signature = await signEnvelope(
        signer, registry, "AgentLineage/REQUEST/v1", requestHash,
      );
      await registry.connect(relayer).beginInvocation(
        credential.credentialId, groupBudgetId, requestHash, 1, 30, signature,
      );
      await registry.connect(relayer).finishInvocation(requestHash);
    }
    const overflowHash = id("replica-request-overflow");
    const overflowSignature = await signEnvelope(
      leafOp, registry, "AgentLineage/REQUEST/v1", overflowHash,
    );
    await expectFailure(
      registry.connect(relayer).beginInvocation(
        second.credentialId, groupBudgetId, overflowHash, 1, 30, overflowSignature,
      ),
      "CALL_BUDGET_EXCEEDED",
    );
    const groupBudget = await registry.budgets(groupBudgetId);
    expect(Number(groupBudget.spentCalls)).to.equal(3);
  });
});
