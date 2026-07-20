const fs = require("fs");
const path = require("path");
const { performance } = require("perf_hooks");
const hre = require("hardhat");

const { ethers } = hre;
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

async function main() {
  const [governance, epochKey, leafOp, relayer] = await ethers.getSigners();
  const Factory = await ethers.getContractFactory("AgentLineageRegistry");
  const registry = await Factory.deploy();
  await registry.waitForDeployment();
  const deploymentReceipt = await registry.deploymentTransaction().wait();
  const rootId = id("benchmark-root");
  const epochHash = id("benchmark-epoch");
  await (await registry.connect(governance).registerRoot(
    rootId, 1, epochKey.address, epochHash,
  )).wait();

  const rootBudgetId = id("benchmark-root-budget");
  await (await registry.connect(governance).createRootBudget(
    rootBudgetId, rootId, 2000, 5000, 1000,
  )).wait();
  const latest = await ethers.provider.getBlock("latest");
  const credentialId = id("benchmark-credential");
  const childId = id("benchmark-child");
  const edgeId = id("benchmark-edge");
  const childBudgetId = id("benchmark-child-budget");
  const registrationValues = [
    credentialId,
    ethers.ZeroHash,
    id("benchmark-credential-hash"),
    epochHash,
    rootId,
    rootId,
    childId,
    edgeId,
    id("benchmark-lineage"),
    id("benchmark-policy"),
    childBudgetId,
    ethers.ZeroHash,
    leafOp.address,
    ethers.ZeroAddress,
    latest.timestamp + 86400,
  ];
  const registrationTypes = [
    "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
    "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "address", "address", "uint64",
  ];
  const registrationHash = ethers.keccak256(
    abiCoder.encode(registrationTypes, registrationValues),
  );
  const registrationSignature = await signEnvelope(
    epochKey, registry, "AgentLineage/REGISTER_DELEGATION/v1", registrationHash,
  );
  const registrationReceipt = await (await registry.connect(relayer).registerDelegation(
    ...registrationValues, registrationSignature,
  )).wait();

  const reserveValues = [rootBudgetId, childBudgetId, credentialId, 2000, 5000, 1000];
  const reserveHash = ethers.keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint32"],
    reserveValues,
  ));
  const reserveSignature = await signEnvelope(
    epochKey, registry, "AgentLineage/RESERVE_BUDGET/v1", reserveHash,
  );
  const reserveReceipt = await (await registry.connect(relayer).reserveChildBudget(
    ...reserveValues, reserveSignature,
  )).wait();

  const levels = [1, 10, 100, 1000];
  const concurrency = [];
  let sequence = 0;
  for (const level of levels) {
    const requests = [];
    for (let index = 0; index < level; index += 1) {
      const requestHash = id(`benchmark-request-${sequence}`);
      sequence += 1;
      requests.push({
        requestHash,
        signature: await signEnvelope(
          leafOp, registry, "AgentLineage/REQUEST/v1", requestHash,
        ),
      });
    }
    let beginGas = 0;
    const started = performance.now();
    for (const item of requests) {
      const receipt = await (await registry.connect(relayer).beginInvocation(
        credentialId, childBudgetId, item.requestHash, 1, 3600, item.signature,
      )).wait();
      beginGas += Number(receipt.gasUsed);
    }
    const beginElapsed = performance.now() - started;
    let finishGas = 0;
    for (const item of requests) {
      const receipt = await (await registry.connect(relayer).finishInvocation(
        item.requestHash,
      )).wait();
      finishGas += Number(receipt.gasUsed);
    }
    concurrency.push({
      level,
      begin_tps: level / (beginElapsed / 1000),
      begin_elapsed_ms: beginElapsed,
      begin_gas_average: beginGas / level,
      finish_gas_average: finishGas / level,
    });
  }

  const budget = await registry.budgets(childBudgetId);
  const report = {
    schema: "agentlineage-hardhat-benchmark-v1",
    chain_id: Number((await ethers.provider.getNetwork()).chainId),
    deployment_gas: Number(deploymentReceipt.gasUsed),
    registration_gas: Number(registrationReceipt.gasUsed),
    reservation_gas: Number(reserveReceipt.gasUsed),
    concurrency,
    budget: {
      limit_calls: Number(budget.limitCalls),
      spent_calls: Number(budget.spentCalls),
      active_concurrency: Number(budget.activeConcurrency),
      qor: budget.spentCalls > budget.limitCalls ? 1 : 0,
    },
  };
  const timestamp = new Date().toISOString().replace(/[-:.]/g, "").replace("Z", "Z");
  const outputDir = path.join(process.cwd(), ".codex", "lineage_runs");
  fs.mkdirSync(outputDir, { recursive: true });
  const outputFile = path.join(outputDir, `hardhat_budget_${timestamp}.json`);
  fs.writeFileSync(outputFile, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(JSON.stringify({ outputFile, report }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
