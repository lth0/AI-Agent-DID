import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = current_dir
while not os.path.exists(os.path.join(project_root, "infrastructure")):
    parent = os.path.dirname(project_root)
    if parent == project_root: break 
    project_root = parent
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import json
import subprocess
import time

def start_network(config_path=None, keep_alive=True):
    # 1. Read configuration
    json_path = os.path.abspath(config_path or (
        sys.argv[1] if len(sys.argv) > 1
        else os.path.join(project_root, 'config', 'network_config.json')
    ))

    try:
        with open(json_path, "r", encoding='utf-8') as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Error: Config file not found at {json_path}")
        return []

    processes = []

    print("="*60)
    print("Initializing Decentralized Network Simulation")
    print("="*60)

    # 2. Start all Holders
    for h in config["holders"]:
        print(f"Starting [Holder] {h['name']} ({h['role']}) on port {h['port']}...")
        
        # Construct command: python agents/holder/runtime.py <port> <role>
        cmd = [
            sys.executable, 
            "agents/holder/runtime.py", 
            str(h["port"]), 
            h["role"]
        ]
        
        security = h.get("security", {})
        child_env = os.environ.copy()
        child_env["AGENTDID_ATTACK_MODE"] = security.get("attack_mode", "none")
        child_env["AGENTDID_EXPERIMENT_ID"] = config.get("experiment_id", "")
        child_env["AGENTDID_IMPERSONATED_DID"] = security.get("impersonated_did", "")
        child_env["AGENTDID_ALLOW_UNSAFE_RESET"] = str(
            security.get("allow_unsafe_reset", False)
        ).lower()
        child_env["AGENTDID_DETERMINISTIC_MODE"] = str(
            security.get("deterministic_mode", False)
        ).lower()
        if config.get("experiment_id"):
            child_env["AGENTDID_DATA_DIR"] = os.path.join(
                project_root, ".codex", "security_runs", config["experiment_id"],
                "holder_" + h["role"],
            )

        p = subprocess.Popen(cmd, env=child_env)
        processes.append(p)

    # Wait a few seconds to ensure Holders are fully started
    time.sleep(2) 

    # 3. Start all Verifiers
    for v in config["verifiers"]:
        print(f"Starting [Verifier] {v['name']} ({v['role']}) on port {v['port']} -> target {v['target_url']}...")
        
        # Construct command: python _demo_2v2/demo_verifier_server.py <port> <role> <target>
        cmd = [
            sys.executable, 
            "_demo_2v2/demo_verifier_server.py", 
            str(v["port"]), 
            v["role"],
            v["target_url"]
        ]
        
        child_env = os.environ.copy()
        child_env["AGENTDID_DEMO_STRICT_SECURITY"] = str(
            v.get("strict_security", True)
        ).lower()
        if config.get("experiment_id"):
            child_env["AGENTDID_DATA_DIR"] = os.path.join(
                project_root, ".codex", "security_runs", config["experiment_id"],
                "verifier_" + v["role"],
            )
        p = subprocess.Popen(cmd, env=child_env)
        processes.append(p)

    print("\n✅ Network is running! (Press Ctrl+C in this terminal to stop all nodes)")
    
    if not keep_alive:
        return processes

    try:
        # Keep main script running until user presses Ctrl+C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down network...")
        for p in processes:
            p.terminate()
    return processes

if __name__ == "__main__":
    start_network()
