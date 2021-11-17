"""Test nagios allocations check script."""

import json
import unittest.mock as mock

import pytest

import run_allocation_checks


@pytest.fixture
def servers():
    return [
        mock.MagicMock(id="vm-0", compute_host="host-0"),
        mock.MagicMock(id="vm-1", compute_host="host-0"),
        mock.MagicMock(id="vm-2", compute_host="host-0"),
    ]


@pytest.fixture
def rp():
    rp = [mock.MagicMock(), mock.MagicMock()]
    rp[0].name = "host-0"
    rp[0].uuid = "rp-0"
    rp[1].name = "host-1"
    rp[1].uuid = "rp-1"
    return rp


def test_correct_state(servers, rp):
    args = mock.MagicMock()

    conn = mock.MagicMock()
    conn.compute.servers.return_value = servers

    rps = {"resource_providers": [{"name": rp[0].name, "uuid": rp[0].uuid}]}
    allocs = {"allocations": {servers[0].id: "", servers[1].id: "", servers[2].id: ""}}

    placement_client = mock.MagicMock()
    allocations_resp = mock.MagicMock()
    allocations_resp.content = json.dumps(allocs)
    rps_resp = mock.MagicMock()
    rps_resp.content = json.dumps(rps)
    placement_client.get.side_effect = [rps_resp, allocations_resp]

    alerts = run_allocation_checks.check_allocations(conn, placement_client)
    status_message = run_allocation_checks.nagios_exit(args, alerts)

    assert len(alerts) == 0
    assert status_message == (
        0,
        "OK: total_alarms[0], total_crit[0], total_ignored[0], ignoring r''\n",
    )


def test_nova_instance_missing(servers, rp):
    args = mock.MagicMock()

    conn = mock.MagicMock()
    conn.compute.servers.return_value = [servers[0], servers[2]]

    rps = {"resource_providers": [{"name": rp[0].name, "uuid": rp[0].uuid}]}
    allocs = {
        "allocations": {
            servers[0].id: "",
            servers[1].id: "",  # missing in nova
            servers[2].id: "",
        }
    }

    placement_client = mock.MagicMock()
    allocations_resp = mock.MagicMock()
    allocations_resp.content = json.dumps(allocs)
    rps_resp = mock.MagicMock()
    rps_resp.content = json.dumps(rps)
    placement_client.get.side_effect = [rps_resp, allocations_resp]

    alerts = run_allocation_checks.check_allocations(conn, placement_client)
    status_message = run_allocation_checks.nagios_exit(args, alerts)

    assert len(alerts) == 1
    assert status_message == (
        1,
        "WARNING: total_alarms[1], total_crit[0], total_ignored[0], ignoring r''\n"
        "instance vm-1 is missing in nova: placement host: ['host-0'], "
        "clean up in placement",
    )


def test_placement_allocation_missing(servers, rp):
    args = mock.MagicMock()

    conn = mock.MagicMock()
    conn.compute.servers.return_value = [
        servers[0],
        servers[1],  # missing in placement
        servers[2],
    ]

    rps = {"resource_providers": [{"name": rp[0].name, "uuid": rp[0].uuid}]}
    allocs = {"allocations": {servers[0].id: "", servers[2].id: ""}}

    placement_client = mock.MagicMock()
    allocations_resp = mock.MagicMock()
    allocations_resp.content = json.dumps(allocs)
    rps_resp = mock.MagicMock()
    rps_resp.content = json.dumps(rps)
    placement_client.get.side_effect = [rps_resp, allocations_resp]

    alerts = run_allocation_checks.check_allocations(conn, placement_client)
    status_message = run_allocation_checks.nagios_exit(args, alerts)

    assert len(alerts) == 1
    assert status_message == (
        1,
        "WARNING: total_alarms[1], total_crit[0], total_ignored[0], ignoring r''\n"
        "instance vm-1 is incorrect in placement: "
        "placement host: [], nova host: ['host-0']",
    )


def test_multiple_placement_allocations_mismatch(servers, rp):
    args = mock.MagicMock()

    conn = mock.MagicMock()

    hosts = [mock.MagicMock(), mock.MagicMock()]
    hosts[0].name = "host-0"
    hosts[1].name = "host-1"

    nova_servers = mock.MagicMock()
    nova_servers.side_effect = [
        [servers[0], servers[1], mock.MagicMock(id="vm-2", compute_host="host-1")],
    ]

    conn.compute.servers = nova_servers

    rps = {
        "resource_providers": [
            {"name": rp[0].name, "uuid": rp[0].uuid},
            {"name": rp[1].name, "uuid": rp[1].uuid},
        ]
    }
    allocs = [
        # host-0: vms 0 and 1
        {"allocations": {servers[0].id: "", servers[1].id: ""}},
        # host-1: vm 0 (duplicated) and 2
        {"allocations": {servers[0].id: "", servers[2].id: ""}},
    ]

    placement_client = mock.MagicMock()

    rps_resp = mock.MagicMock()
    rps_resp.content = json.dumps(rps)

    placement_client.get.side_effect = [
        rps_resp,
        mock.MagicMock(content=json.dumps(allocs[0])),
        mock.MagicMock(content=json.dumps(allocs[1])),
    ]

    alerts = run_allocation_checks.check_allocations(conn, placement_client)
    status_message = run_allocation_checks.nagios_exit(args, alerts)

    assert len(alerts) == 1
    assert status_message == (
        1,
        "WARNING: total_alarms[1], total_crit[0], total_ignored[0], ignoring r''\n"
        "instance vm-0 is incorrect in placement: "
        "placement host: ['host-0', 'host-1'], nova host: ['host-0']",
    )
    assert True


def test_ignored(servers, rp):
    args = mock.MagicMock()

    conn = mock.MagicMock()
    conn.compute.servers.return_value = [servers[0], servers[2]]  # server[1] missing

    rps = {"resource_providers": [{"name": rp[0].name, "uuid": rp[0].uuid}]}
    # servers[2] missing
    allocs = {
        "allocations": {
            servers[0].id: "",
            servers[1].id: "",
        }
    }

    placement_client = mock.MagicMock()
    allocations_resp = mock.MagicMock()
    allocations_resp.content = json.dumps(allocs)
    rps_resp = mock.MagicMock()
    rps_resp.content = json.dumps(rps)
    placement_client.get.side_effect = [rps_resp, allocations_resp]

    args.ignored = f"{servers[1].id},{servers[2].id}"

    alerts = run_allocation_checks.check_allocations(conn, placement_client)
    status_message = run_allocation_checks.nagios_exit(args, alerts)

    assert len(alerts) == 2
    assert status_message == (
        0,
        "OK: total_alarms[2], total_crit[0], total_ignored[2], "
        "ignoring r'(?:vm-1)|(?:vm-2)'\n",
    )


def test_no_instances(rp):
    args = mock.MagicMock()

    conn = mock.MagicMock()
    conn.compute.servers.return_value = []  # no instances

    placement_client = mock.MagicMock()
    rps = {"resource_providers": [{"name": rp[0].name, "uuid": rp[0].uuid}]}
    rps_resp = mock.MagicMock()
    rps_resp.content = json.dumps(rps)
    allocations_resp = mock.MagicMock()
    allocations_resp.content = b'{"allocations": {}}'
    placement_client.get.side_effect = [rps_resp, allocations_resp]

    alerts = run_allocation_checks.check_allocations(conn, placement_client)
    status_message = run_allocation_checks.nagios_exit(args, alerts)

    assert len(alerts) == 0
    assert status_message == (
        0,
        "OK: total_alarms[0], total_crit[0], total_ignored[0], ignoring r''\n",
    )
