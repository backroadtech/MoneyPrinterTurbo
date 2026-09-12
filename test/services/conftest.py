"""
Shared fixtures for test/services.

Centralized pilot-policy state hygiene (L4C-I3): every services test runs
with a fresh pilot-policy cache and a restored MPT_PILOT_PROFILE so no
test can inherit a cached policy or profile activation from an earlier
test. Setup/teardown only — no test assertion is weakened.
"""

import os

import pytest

from app.services.pilot_policy import reset_pilot_policy_cache


@pytest.fixture(autouse=True)
def _reset_pilot_policy_state():
    """Reset the pilot-policy cache and restore the profile env per test."""
    previous_profile = os.environ.get("MPT_PILOT_PROFILE")
    reset_pilot_policy_cache()
    try:
        yield
    finally:
        reset_pilot_policy_cache()
        if previous_profile is None:
            os.environ.pop("MPT_PILOT_PROFILE", None)
        else:
            os.environ["MPT_PILOT_PROFILE"] = previous_profile
