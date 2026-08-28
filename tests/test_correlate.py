import pytest

from correlate import validate_config, process_event

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

def test_trigger_is_stored_without_creating_incident():
    pending_triggers = {}
    incidents = []

    event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:00:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000001,
        },
    }

    result = process_event(
        event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    key = ("192.168.139.128", "192.168.139.129")

    assert result is None
    assert incidents == []
    assert key in pending_triggers
def test_backdoor_without_trigger_creates_no_incident():
    pending_triggers = {}
    incidents = []

    event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:01:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000002,
        },
    }

    result = process_event(
        event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    assert result is None
    assert incidents == []
    assert pending_triggers == {}

def test_matching_trigger_and_backdoor_creates_incident():
    pending_triggers = {}
    incidents = []

    trigger_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:00:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000001,
        },
    }

    trigger_result = process_event(
        trigger_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    key = ("192.168.139.128", "192.168.139.129")

    assert trigger_result is None
    assert incidents == []
    assert key in pending_triggers

    backdoor_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:01:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000002,
        },
    }

    backdoor_result = process_event(
        backdoor_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    assert backdoor_result is not None
    assert backdoor_result["severity"] == "HIGH"
    assert backdoor_result["source_ip"] == "192.168.139.128"
    assert backdoor_result["target_ip"] == "192.168.139.129"
    assert backdoor_result["elapsed_seconds"] == 60.0
    assert len(incidents) == 1
    assert key not in pending_triggers

def test_different_host_pair_does_not_create_incident():
    pending_triggers = {}
    incidents = []

    trigger_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:00:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000001,
        },
    }

    backdoor_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:01:00",
        "src_ip": "192.168.139.50",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000002,
        },
    }

    process_event(
        trigger_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    result = process_event(
        backdoor_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    original_key = ("192.168.139.128", "192.168.139.129")

    assert result is None
    assert incidents == []
    assert original_key in pending_triggers

def test_backdoor_outside_window_does_not_create_incident():
    pending_triggers = {}
    incidents = []

    trigger_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:00:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000001,
        },
    }

    backdoor_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:06:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000002,
        },
    }

    process_event(
        trigger_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    result = process_event(
        backdoor_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    key = ("192.168.139.128", "192.168.139.129")

    assert result is None
    assert incidents == []
    assert key not in pending_triggers

def test_backdoor_at_exact_window_boundary_creates_incident():
    pending_triggers = {}
    incidents = []

    trigger_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:00:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000001,
        },
    }

    backdoor_event = {
        "event_type": "alert",
        "timestamp": "2026-08-27T10:05:00",
        "src_ip": "192.168.139.128",
        "dest_ip": "192.168.139.129",
        "alert": {
            "signature_id": 1000002,
        },
    }

    process_event(
        trigger_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    result = process_event(
        backdoor_event,
        pending_triggers,
        incidents,
        1000001,
        1000002,
        300,
    )

    key = ("192.168.139.128", "192.168.139.129")

    assert result is not None
    assert result["severity"] == "HIGH"
    assert result["elapsed_seconds"] == 300.0
    assert len(incidents) == 1
    assert key not in pending_triggers
