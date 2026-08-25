import pytest

from correlate import validate_config

def test_trigger_sid_must_be_integer():
    config = {
        "trigger_sid": "1000001",
        "backdoor_sid": 1000002,
        "correlation_window_seconds": 300,
    }

    with pytest.raises(ValueError):
        validate_config(config)

def test_valid_config_is_accepted():
    config = {
        "trigger_sid": 1000001,
        "backdoor_sid": 1000002,
        "correlation_window_seconds": 300,
    }

    validate_config(config)
