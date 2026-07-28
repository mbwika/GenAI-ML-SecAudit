"""Free/paid boundary regression tests."""

import importlib.util


def test_inline_pep_gateway_is_not_distributed_in_community():
    assert importlib.util.find_spec("aiaf.api.pep_middleware") is None


def test_advisory_pep_api_remains_in_community():
    assert importlib.util.find_spec("aiaf.api.policy_enforcement") is not None
