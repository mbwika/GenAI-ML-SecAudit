"""Free/paid boundary regression tests."""

import importlib.util


def test_inline_pep_gateway_is_not_distributed_in_community():
    assert importlib.util.find_spec("aiaf.api.pep_middleware") is None


def test_deterministic_ask_aiaf_remains_in_community():
    assert importlib.util.find_spec("aiaf.api.assistant") is not None
    assert importlib.util.find_spec("aiaf.core.assistant_engine") is not None


def test_llm_inference_copilot_is_not_distributed_in_community():
    assert importlib.util.find_spec("aiaf.core.assistant_llm") is None


def test_advisory_pep_api_remains_in_community():
    assert importlib.util.find_spec("aiaf.api.policy_enforcement") is not None
