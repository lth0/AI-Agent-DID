const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const LineageFactory = await hre.ethers.getContractFactory("AgentLineageRegistry");
  const lineage = await LineageFactory.deploy();
  await lineage.waitForDeployment();
  const lineageReceipt = await lineage.deploymentTransaction().wait();

  const didArtifact = require(
    "../../node_modules/ethr-did-resolver/src/__tests__/EthereumDIDRegistry-Legacy/LegacyEthereumDIDRegistry.json"
  );
  const DidFactory = new hre.ethers.ContractFactory(
    didArtifact.abi,
    didArtifact.bytecode,
    deployer
  );
  const didRegistry = await DidFactory.deploy();
  await didRegistry.waitForDeployment();
  const didReceipt = await didRegistry.deploymentTransaction().wait();

  const network = await hre.ethers.provider.getNetwork();
  const deployment = {
    network: hre.network.name,
    chainId: Number(network.chainId),
    lineageRegistry: {
      address: await lineage.getAddress(),
      transactionHash: lineage.deploymentTransaction().hash,
      blockNumber: lineageReceipt.blockNumber,
      gasUsed: lineageReceipt.gasUsed.toString(),
    },
    didRegistry: {
      address: await didRegistry.getAddress(),
      transactionHash: didRegistry.deploymentTransaction().hash,
      blockNumber: didReceipt.blockNumber,
      gasUsed: didReceipt.gasUsed.toString(),
    },
  };
  const outputDir = path.join(process.cwd(), ".codex", "comparison", "deployments");
  fs.mkdirSync(outputDir, { recursive: true });
  const outputFile = path.join(outputDir, `${hre.network.name}.json`);
  fs.writeFileSync(outputFile, `${JSON.stringify(deployment, null, 2)}\n`, "utf8");
  console.log(JSON.stringify({ ...deployment, outputFile }));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
