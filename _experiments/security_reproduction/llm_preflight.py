"""Minimal, secret-safe LLM connectivity check for AgentDID."""

import argparse
import json
import os
import sys
from pathlib import Path

from langchain_core.messages import HumanMessage

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from infrastructure.llm_factory import create_chat_model  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "config" / "agents_4_key.json"))
    parser.add_argument("--model", default=None)
    parser.add_argument("--prompt", default="Reply with exactly: AGENTDID_LLM_OK")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.model:
        os.environ["AGENTDID_LLM_MODEL"] = args.model
    try:
        model = create_chat_model(config, "holder", "deepseek-v4-pro", 0)
        response = model.invoke([HumanMessage(content=args.prompt)])
        content = response.content if isinstance(response.content, str) else str(response.content)
        print(json.dumps({"ok": True, "model": os.environ.get("AGENTDID_LLM_MODEL", config.get("llm", {}).get("model")), "response": content}, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
