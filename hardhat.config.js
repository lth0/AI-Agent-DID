require("@nomicfoundation/hardhat-ethers");

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./contracts/test",
    cache: "./.codex/hardhat-cache",
    artifacts: "./.codex/hardhat-artifacts",
  },
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
    sepolia: {
      url: process.env.AGENTLINEAGE_RPC_URL || "",
      accounts: process.env.AGENTLINEAGE_DEPLOYER_KEY
        ? [process.env.AGENTLINEAGE_DEPLOYER_KEY]
        : [],
      chainId: 11155111,
    },
  },
};
