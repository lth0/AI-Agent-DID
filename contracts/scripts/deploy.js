const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const Factory = await hre.ethers.getContractFactory("AgentLineageRegistry");
  const registry = await Factory.deploy();
  await registry.waitForDeployment();
  const deploymentTransaction = registry.deploymentTransaction();
  const receipt = await deploymentTransaction.wait();
  const address = await registry.getAddress();
  const deployment = {
    network: hre.network.name,
    chainId: Number((await hre.ethers.provider.getNetwork()).chainId),
    address,
    transactionHash: deploymentTransaction.hash,
    blockNumber: receipt.blockNumber,
  };
  const outputDir = path.join(process.cwd(), ".codex", "lineage", "deployments");
  fs.mkdirSync(outputDir, { recursive: true });
  const outputFile = path.join(outputDir, `${hre.network.name}.json`);
  fs.writeFileSync(outputFile, `${JSON.stringify(deployment, null, 2)}\n`, "utf8");
  console.log(JSON.stringify({ ...deployment, outputFile }));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
