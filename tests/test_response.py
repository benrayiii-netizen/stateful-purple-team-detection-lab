
from copy import deepcopy

from response import generate_incident_id


def sample_incident():
    return {
        "source_ip": "192.168.139.128",
        "target_ip": "192.168.139.129",
        "trigger_sid": 1000001,
        "backdoor_sid": 1000002,
        "trigger_time": "2026-10-09T12:49:21-05:00",
        "backdoor_time": "2026-10-09T12:49:23-05:00",
    }


def test_incident_id_is_repeatable():
    incident = sample_incident()

    first_id = generate_incident_id(incident)
    second_id = generate_incident_id(incident)

    assert first_id == second_id
    assert len(first_id) == 64


def test_different_incidents_have_different_ids():
    first = sample_incident()
    second = deepcopy(first)
    second["backdoor_time"] = "2026-10-09T12:50:23-05:00"

    assert generate_incident_id(first) != generate_incident_id(second)


def test_identifying_evidence_changes_id():
    original = sample_incident()
    modified = deepcopy(original)
    modified["target_ip"] = "192.168.139.130"

    assert generate_incident_id(original) != generate_incident_id(modified)


def test_dictionary_order_does_not_change_id():
    incident = sample_incident()
    reversed_incident = dict(reversed(list(incident.items())))

    assert generate_incident_id(incident) == generate_incident_id(
        reversed_incident
    )



import pytest

from response import validate_response_status


@pytest.mark.parametrize(
    "status",
    ["NEW", "TRIAGED", "CONTAINED", "CLOSED"],
)
def test_valid_response_statuses(status):
    assert validate_response_status(status) == status


@pytest.mark.parametrize(
    "status",
    ["DONE", "CONTAIN", "", None, 123, "triaged"],
)
def test_invalid_response_statuses(status):
    with pytest.raises(ValueError):
        validate_response_status(status)




from response import create_triage_record


def test_triage_record_requires_no_approval():
    incident = sample_incident()

    record = create_triage_record(
        incident,
        "Blue Team Analyst",
        "Recommend containment",
        "Correlated FTP trigger and backdoor alert",
    )

    assert record["incident_id"] == generate_incident_id(incident)
    assert record["status"] == "TRIAGED"
    assert record["analyst"] == "Blue Team Analyst"
    assert record["decision"] == "Recommend containment"
    assert record["approved"] is False


@pytest.mark.parametrize(
    "analyst,decision,reason",
    [
        ("", "Recommend containment", "Evidence reviewed"),
        ("Analyst", "", "Evidence reviewed"),
        ("Analyst", "Recommend containment", ""),
        ("   ", "Recommend containment", "Evidence reviewed"),
        (None, "Recommend containment", "Evidence reviewed"),
    ],
)
def test_triage_record_rejects_missing_required_fields(
    analyst, decision, reason
):
    with pytest.raises(ValueError):
        create_triage_record(
            sample_incident(),
            analyst,
            decision,
            reason,
        )



import json

from response import load_response_records


def test_load_response_records_missing_file(tmp_path):
    path = tmp_path / "missing.json"

    assert load_response_records(path) == []
    assert not path.exists()


def test_load_response_records_valid_list(tmp_path):
    path = tmp_path / "valid.json"
    expected = [
        {"incident_id": "test-001", "status": "TRIAGED"}
    ]

    path.write_text(json.dumps(expected), encoding="utf-8")

    assert load_response_records(path) == expected


def test_load_response_records_rejects_non_list(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(
        json.dumps({"status": "TRIAGED"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must be a JSON list"):
        load_response_records(path)


def test_load_response_records_rejects_malformed_json(tmp_path):
    path = tmp_path / "malformed.json"
    path.write_text("[{", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        load_response_records(path)



from response import validate_response_record


def test_valid_triage_record_is_accepted():
    record = create_triage_record(
        sample_incident(),
        "Blue Team Analyst",
        "Recommend containment",
        "Evidence reviewed",
    )

    assert validate_response_record(record) == record
    assert record["approved"] is False


def test_triage_record_rejects_unauthorized_approval():
    record = create_triage_record(
        sample_incident(),
        "Blue Team Analyst",
        "Recommend containment",
        "Evidence reviewed",
    )
    record["approved"] = True

    with pytest.raises(ValueError, match="must be unapproved"):
        validate_response_record(record)


def test_triage_record_rejects_contained_status():
    record = create_triage_record(
        sample_incident(),
        "Blue Team Analyst",
        "Recommend containment",
        "Evidence reviewed",
    )
    record["status"] = "CONTAINED"

    with pytest.raises(ValueError, match="Only TRIAGED"):
        validate_response_record(record)



from response import check_duplicate_incident


def test_duplicate_incident_is_rejected():
    incident = sample_incident()
    record = create_triage_record(
        incident,
        "Blue Team Analyst",
        "Review",
        "Evidence reviewed",
    )

    with pytest.raises(ValueError, match="already exists"):
        check_duplicate_incident([record], record)


def test_different_incident_is_accepted():
    first_incident = sample_incident()
    second_incident = sample_incident()
    second_incident["backdoor_time"] = "2026-10-13T12:00:00"

    first_record = create_triage_record(
        first_incident,
        "Blue Team Analyst",
        "Review",
        "First incident",
    )
    second_record = create_triage_record(
        second_incident,
        "Blue Team Analyst",
        "Review",
        "Second incident",
    )

    assert first_record["incident_id"] != second_record["incident_id"]
    assert check_duplicate_incident([first_record], second_record) is True



from response import save_response_record


def test_first_response_record_is_saved(tmp_path):
    path = tmp_path / "response_records.json"
    record = create_triage_record(
        sample_incident(), "Blue Team Analyst",
        "Review", "Evidence reviewed"
    )

    result = save_response_record(path, record)

    assert path.exists()
    assert result == [record]
    assert load_response_records(path) == [record]


def test_saving_second_record_preserves_history(tmp_path):
    path = tmp_path / "response_records.json"
    first_incident = sample_incident()
    second_incident = sample_incident()
    second_incident["backdoor_time"] = "2026-10-13T12:00:00"

    first = create_triage_record(
        first_incident, "Blue Team Analyst",
        "Review", "First incident"
    )
    second = create_triage_record(
        second_incident, "Blue Team Analyst",
        "Review", "Second incident"
    )

    save_response_record(path, first)
    save_response_record(path, second)

    assert load_response_records(path) == [first, second]


def test_duplicate_save_does_not_modify_history(tmp_path):
    path = tmp_path / "response_records.json"
    record = create_triage_record(
        sample_incident(), "Blue Team Analyst",
        "Review", "Evidence reviewed"
    )

    save_response_record(path, record)
    original_bytes = path.read_bytes()

    with pytest.raises(ValueError, match="already exists"):
        save_response_record(path, record)

    assert path.read_bytes() == original_bytes


def test_corrupted_history_is_not_overwritten(tmp_path):
    path = tmp_path / "response_records.json"
    path.write_text("[{", encoding="utf-8")
    original_bytes = path.read_bytes()

    record = create_triage_record(
        sample_incident(), "Blue Team Analyst",
        "Review", "Evidence reviewed"
    )

    with pytest.raises(json.JSONDecodeError):
        save_response_record(path, record)

    assert path.read_bytes() == original_bytes



def test_duplicate_existing_history_is_not_overwritten(tmp_path):
    path = tmp_path / "response_records.json"

    first_incident = sample_incident()
    second_incident = sample_incident()
    second_incident["backdoor_time"] = "2026-10-13T12:00:00"

    first = create_triage_record(
        first_incident, "Blue Team Analyst",
        "Review", "First incident"
    )
    second = create_triage_record(
        second_incident, "Blue Team Analyst",
        "Review", "Second incident"
    )

    path.write_text(
        json.dumps([first, first.copy()]),
        encoding="utf-8"
    )
    original_bytes = path.read_bytes()

    with pytest.raises(ValueError, match="Duplicate incident ID"):
        save_response_record(path, second)

    assert path.read_bytes() == original_bytes



def test_concurrent_writers_preserve_both_records(tmp_path):
    """Two processes must not lose updates to shared response history."""
    import multiprocessing
    import queue

    path = tmp_path / "response_records.json"

    first_incident = sample_incident()
    second_incident = sample_incident()
    second_incident["backdoor_time"] = "2026-10-13T12:00:00"

    first = create_triage_record(
        first_incident, "Blue Team Analyst",
        "Review", "First concurrent incident"
    )
    second = create_triage_record(
        second_incident, "Blue Team Analyst",
        "Review", "Second concurrent incident"
    )

    # Linux fork context: separate processes share the start signal.
    ctx = multiprocessing.get_context("fork")
    start = ctx.Event()
    results = ctx.Queue()

    def worker(record):
        try:
            if not start.wait(timeout=10):
                raise TimeoutError("Start signal timed out")
            save_response_record(path, record)
            results.put(("PASS", record["incident_id"]))
        except Exception as exc:
            results.put(("FAIL", repr(exc)))

    processes = [
        ctx.Process(target=worker, args=(first,)),
        ctx.Process(target=worker, args=(second,)),
    ]

    for process in processes:
        process.start()

    try:
        start.set()

        for process in processes:
            process.join(timeout=15)

        assert all(
            not process.is_alive() for process in processes
        ), "Concurrent writer did not finish"

        assert all(
            process.exitcode == 0 for process in processes
        ), "Concurrent writer exited abnormally"

        outcomes = [results.get(timeout=5) for _ in processes]

        assert all(
            outcome[0] == "PASS" for outcome in outcomes
        ), outcomes

        saved = load_response_records(path)
        saved_ids = [record["incident_id"] for record in saved]

        assert len(saved) == 2
        assert len(set(saved_ids)) == 2
        assert set(saved_ids) == {
            first["incident_id"],
            second["incident_id"],
        }

    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)
        results.close()
        results.join_thread()



def test_writer_waits_for_exclusive_lock(tmp_path):
    """A writer waits until another process releases its lock."""
    import multiprocessing
    import time
    from response import acquire_response_lock

    path = tmp_path / "response_records.json"
    lock_path = path.with_name(path.name + ".lock")

    record = create_triage_record(
        sample_incident(),
        "Blue Team Analyst",
        "Review",
        "Controlled lock contention",
    )

    ctx = multiprocessing.get_context("spawn")
    started = ctx.Event()
    finished = ctx.Event()
    results = ctx.Queue()

    process = ctx.Process(
        target=contention_save_worker,
        args=(path, record, started, finished, results),
    )
    process.daemon = True

    try:
        with lock_path.open("a+b") as lock_file:
            acquire_response_lock(lock_file)
            process.start()

            assert started.wait(timeout=5), "Worker did not start"

            # Allow the worker time to attempt the locked save.
            time.sleep(0.3)

            assert not finished.is_set(), (
                "Writer completed while exclusive lock was held"
            )
            assert not path.exists(), (
                "Response history was written before lock release"
            )

        # The exclusive lock is released here.
        process.join(timeout=10)

        assert not process.is_alive(), (
            "Writer remained blocked after lock release"
        )
        assert process.exitcode == 0

        outcome = results.get(timeout=5)
        assert outcome == ("PASS", record["incident_id"])

        assert finished.is_set()
        assert load_response_records(path) == [record]

    finally:
        if process.is_alive():
            process.terminate()
        if process.pid is not None:
            process.join(timeout=5)
        results.close()
        results.join_thread()


def contention_save_worker(path, record, started, finished, results):
    """Save a record from an independent process."""
    from response import save_response_record

    started.set()

    try:
        save_response_record(path, record)
        results.put(("PASS", record["incident_id"]))
    except Exception as exc:
        results.put(("FAIL", repr(exc)))
    finally:
        finished.set()

