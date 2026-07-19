import os


PLACEHOLDER_VALUES = {
    "",
    "0x...",
    "YOUR_API_KEY_HERE",
    "YOUR_DASHSCOPE_API_KEY_HERE",
    "YOUR_MASTER_PRIVATE_KEY_HERE",
    "YOUR_ISSUER_PRIVATE_KEY_HERE",
}


def _has_value(value):
    return isinstance(value, str) and value.strip() not in PLACEHOLDER_VALUES


def _first_value(*values):
    for value in values:
        if _has_value(value):
            return value.strip()
    return None


def configure_llm_environment(config):
    llm_config = config.get("llm", {}) if isinstance(config, dict) else {}
    env_config = llm_config.get("env", {}) if isinstance(llm_config, dict) else {}

    for key, value in env_config.items():
        if _has_value(value):
            os.environ[key] = value.strip()


def _get_provider(config):
    llm_config = config.get("llm", {}) if isinstance(config, dict) else {}
    provider = _first_value(
        llm_config.get("provider") if isinstance(llm_config, dict) else None,
        config.get("llm_provider") if isinstance(config, dict) else None,
    )
    if provider:
        return provider.lower()

    if _first_value(
        os.environ.get("ANTHROPIC_AUTH_TOKEN"),
        os.environ.get("ANTHROPIC_API_KEY"),
    ):
        return "anthropic"

    return "qwq"


def _get_role_model(llm_config, role_name, default_model):
    return _first_value(
        os.environ.get("AGENTDID_LLM_MODEL"),
        llm_config.get(f"{role_name}_model"),
        llm_config.get("model"),
        os.environ.get("ANTHROPIC_MODEL"),
        default_model,
    )


def _create_anthropic_model(config, role_name, temperature):
    from langchain_anthropic import ChatAnthropic

    llm_config = config.get("llm", {}) if isinstance(config, dict) else {}
    env_config = llm_config.get("env", {}) if isinstance(llm_config, dict) else {}

    api_key = _first_value(
        os.environ.get("AGENTDID_ANTHROPIC_API_KEY"),
        os.environ.get("AGENTDID_ANTHROPIC_AUTH_TOKEN"),
        env_config.get("ANTHROPIC_AUTH_TOKEN"),
        env_config.get("ANTHROPIC_API_KEY"),
        llm_config.get("anthropic_auth_token"),
        llm_config.get("anthropic_api_key"),
        os.environ.get("ANTHROPIC_AUTH_TOKEN"),
        os.environ.get("ANTHROPIC_API_KEY"),
    )
    if not api_key:
        raise ValueError("Anthropic auth token missing. Configure llm.env.ANTHROPIC_AUTH_TOKEN in config/key.json.")

    base_url = _first_value(
        os.environ.get("AGENTDID_ANTHROPIC_BASE_URL"),
        env_config.get("ANTHROPIC_BASE_URL"),
        llm_config.get("anthropic_base_url"),
        os.environ.get("ANTHROPIC_BASE_URL"),
    )
    model = _get_role_model(llm_config, role_name, "claude-3-5-sonnet-20241022")
    max_tokens = llm_config.get("max_tokens", 2048)

    os.environ["ANTHROPIC_AUTH_TOKEN"] = api_key
    os.environ["ANTHROPIC_API_KEY"] = api_key
    if base_url:
        base_url = base_url.rstrip("/")
        # ChatAnthropic builds /v1/messages itself.  OpenCode's provider
        # configuration names the equivalent endpoint as <host>/v1, so strip
        # that suffix when adapting the configuration to the Python SDK.
        if base_url.endswith("/v1"):
            base_url = base_url[:-3].rstrip("/")
        os.environ["ANTHROPIC_BASE_URL"] = base_url

    kwargs = {
        "model": model,
        "temperature": temperature,
        "anthropic_api_key": api_key,
        "max_tokens": max_tokens,
    }
    if base_url:
        kwargs["anthropic_api_url"] = base_url

    return ChatAnthropic(**kwargs)


def _create_qwq_model(config, default_model, temperature):
    from langchain_qwq import ChatQwQ

    api_key = _first_value(
        config.get("qwq_api_key") if isinstance(config, dict) else None,
        os.environ.get("DASHSCOPE_API_KEY"),
    )
    if not api_key:
        raise ValueError("qwq_api_key missing. Configure it in config/key.json or set DASHSCOPE_API_KEY.")

    os.environ["DASHSCOPE_API_KEY"] = api_key
    return ChatQwQ(
        model=default_model,
        temperature=temperature,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )


def create_chat_model(config, role_name, default_qwq_model, temperature):
    configure_llm_environment(config)
    provider = _get_provider(config)

    if provider in {"anthropic", "claude"}:
        return _create_anthropic_model(config, role_name, temperature)
    if provider in {"qwq", "dashscope"}:
        return _create_qwq_model(config, default_qwq_model, temperature)

    raise ValueError(f"Unsupported LLM provider: {provider}")
