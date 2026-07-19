# develop AgentDID Demo

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18.20-green)](https://nodejs.org/)
[![npm](https://img.shields.io/badge/npm-10.8-red)](https://www.npmjs.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

## 📖 Project Overview

This is a Proof of Concept (PoC) for an Agent decentralized identity authentication system.

The project explores the autonomous interaction capabilities of AI Agents within a Decentralized Identity (DID) network, focusing on the end-to-end authentication flow between Holder Agents and Verifier Agents.

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
    ```bash
    pip install -r requirements.txt
    ```
2.  **Install Node.js Dependencies**:
    The project root contains `package.json` and `package-lock.json`. Ensure Node.js is installed, then run:
    ```bash
    npm install
    ```
3.  **Configure Keys**:
    *   Copy `config/key_example.json` to `config/key.json`.
    *   **Important**: Fill in your Sepolia Testnet API URL, LLM API Key, and the private key of an account holding Sepolia ETH.
    *   ⚠️ **Security Warning**: Do NOT commit private keys containing real assets to version control! Ensure `config/key.json` is added to `.gitignore`.

---

## 🚀 Usage

This project supports two running modes: **2v2 Full Demo** and **Massive Experiments**.

### Mode 1: 2v2 Full Demo
> **Scenario**: Demonstrates the complete interaction cycle between 2 Holders and 2 Verifiers.
>
> **⚠️ Configuration**: Ensure `infrastructure/load_config.py` (Line 18) targets `"agents_4_key.json"`.

**Execution Steps**:

1.  **Initialize Accounts**: Generate 4 key pairs, register DIDs, and authorize Delegates.
    ```bash
    python _demo_2v2/setup_4_agents.py
    ```
2.  **Start Issuer Service**:
    ```bash
    python _ops_services/issuer_server.py
    ```
3.  **Start Agent Network**:
    Open a new terminal and run the network orchestration script (starts Holders and Verifiers):
    ```bash
    python _demo_2v2/start_network.py
    ```
4.  **Trigger Audit Process**:
    Open a new terminal to send instructions to the Verifier and begin probing the Holder:
    ```bash
    python _demo_2v2/trigger_audit.py
    ```

### Mode 2: Massive Experiments
> **Scenario**: Performance stress testing, latency measurement, and VC storage cost analysis.
>
> **⚠️ Configuration**: Modify `infrastructure/load_config.py` (Line 18) to target `"key.json"`.

**Execution Steps**:

1.  **Batch Identity Generation (N Agents)**:
    Modify the `N` value in the script to generate a large number of test accounts:
    ```bash
    python _experiments/setup_agents_N.py
    ```
2.  **Prepare Keys**:
    Ensure the generated `holders_key.json` and `verifiers_key.json` are placed in the `data/` directory.
3.  **Start Issuer**:
    Start the Issuer (if not already running) :
    ```bash
    python _ops_services/issuer_server.py
    ```
4.  **Start Holders**:
    Start the Verifier cluster:
    ```bash
    python _experiments/start_p2p_holders.py
    ```
4.  **Start Verifiers & Stress Test**:
    Start the Verifier cluster to initiate attacks/probes. The results will be output as a CSV file:
    ```bash
    python _experiments/stress_test_p2p.py
    ```

---

## 📊 Benchmarks

*   **VC Size Measurement**: Run `_experiments/measure_vc_size.py` to analyze the storage overhead for different VC schemas.
*   **Context Hash Performance**: Run `_experiments/context_test.py` to test the time cost curve of hash calculations as conversation rounds increase.

---

## ⚠️ Troubleshooting

*   **FileNotFoundError**: Usually a path issue. Please ensure you are running scripts from the project root directory.
*   **DID Resolution Failed**: Check if Node.js is installed and the `node` command is in your system PATH.
*   **Insufficient Gas**: Ensure the Master account in `key.json` has enough Sepolia ETH for distribution and registration.

## License

[MIT License](LICENSE)
