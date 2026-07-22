import os
import json
import sys
from copy import deepcopy

# Calculate project root directory
current_dir = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(current_dir)

# Add root directory to sys.path for easy module imports
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

def _read_json_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"[Config] Error: Expected a JSON object in {path}")
    return value


def _merge_key_config(base, overlay):
    merged = deepcopy(base)
    overlay_accounts = overlay.get("accounts")
    for key, value in overlay.items():
        if key != "accounts":
            merged[key] = deepcopy(value)
    if isinstance(overlay_accounts, dict):
        accounts = merged.setdefault("accounts", {})
        if not isinstance(accounts, dict):
            accounts = {}
            merged["accounts"] = accounts
        for role, value in overlay_accounts.items():
            accounts[role] = deepcopy(value)
    return merged


def load_key_config():
    """
    Load config/key.json
    Uses ROOT_DIR to ensure the file can be found regardless of script location.
    """
    config_dir = os.path.join(ROOT_DIR, "config")
    role_path = os.path.join(config_dir, "agents_4_key.json")
    local_path = os.path.join(config_dir, "key.json")
    explicit_path = os.environ.get("AGENTDID_KEY_CONFIG_PATH", "").strip()

    paths = []
    if os.path.exists(role_path):
        paths.append(role_path)
    if explicit_path:
        resolved_explicit = (
            explicit_path
            if os.path.isabs(explicit_path)
            else os.path.join(ROOT_DIR, explicit_path)
        )
        if not os.path.exists(resolved_explicit):
            raise FileNotFoundError(
                "[Config] Error: AGENTDID_KEY_CONFIG_PATH does not exist: "
                f"{resolved_explicit}"
            )
        paths.append(resolved_explicit)
    elif os.path.exists(local_path):
        paths.append(local_path)

    if not paths:
        raise FileNotFoundError(
            "[Config] Error: No key configuration found; expected "
            f"{role_path} and/or {local_path}"
        )

    config = {}
    for path in paths:
        config = _merge_key_config(config, _read_json_config(path))
    return config

def get_resolve_script_path():
    """
    Get absolute path of real_resolve.js
    Location: infrastructure/real_resolve.js
    """
    path = os.path.join(current_dir, "real_resolve.js")
    
    if not os.path.exists(path):
        path_root = os.path.join(ROOT_DIR, "real_resolve.js")
        if os.path.exists(path_root):
            return path_root
            
        raise FileNotFoundError(
            f"[Config] Error: real_resolve.js not found.\n"
            f"Please ensure the file is located at {path} or the project root."
        )
    return path
