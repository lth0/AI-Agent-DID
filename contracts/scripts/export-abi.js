const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const artifact = await hre.artifacts.readArtifact("AgentLineageRegistry");
  const targetDir = path.join(process.cwd(), "contracts", "abi");
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(
    path.join(targetDir, "AgentLineageRegistry.json"),
    JSON.stringify({ contractName: artifact.contractName, abi: artifact.abi }, null, 2) + "\n",
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
