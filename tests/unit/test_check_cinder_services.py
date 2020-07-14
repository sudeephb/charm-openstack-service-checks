import pytest
import nagios_plugin3

import sys

sys.path.append("files/plugins")

import check_cinder_services  # noqa: E402


@pytest.mark.parametrize(
    "state,status,result",
    [
        ["down", "disabled", "DISABLED"],
        ["down", "enabled", "DOWN"],
        ["up", "enabled", "OK"],
        ["up", "disabled", "DISABLED"],
    ],
)
def test_check_status(state, status, result):
    cinder_service = {
        "binary": "cinder-scheduler",
        "disabled_reason": None,
        "host": "juju-ba88f7-8",
        "state": state,
        "status": status,
        "updated_at": "2020-04-29T14:36:57.000000",
        "zone": "nova",
    }

    expected = (
        result,
        "{}[{}]".format(cinder_service["host"], cinder_service["binary"]),
    )
    actual = check_cinder_services.check_status(cinder_service)
    assert actual == expected


@pytest.mark.parametrize(
    "state1,is_skip_disabled,status2,status3,result",
    [
        ["down", True, "disabled", True, "CRITICAL: juju-ba88f7-8@LVM[cinder-volume]"],
        [
            "down",
            False,
            "disabled",
            True,
            (
                "CRITICAL: juju-ba88f7-8@LVM[cinder-volume];"
                " Disabled: juju-ba88f7-8[cinder-scheduler]"
            ),
        ],
        ["up", True, "disabled", True, "OK: All cinder services happy"],
        [
            "up",
            False,
            "disabled",
            True,
            "WARNING: Disabled: juju-ba88f7-8[cinder-scheduler]",
        ],
        ["down", True, "disabled", False, "CRITICAL: No cinder services found healthy"],
    ],
)
def test_check_cinder_services(state1, is_skip_disabled, status2, status3, result):
    class _TestArgs(object):
        skip_disabled = is_skip_disabled

    class _TestCinder(object):
        def get(cls, name):
            return _TestCinderJson()

    class _TestCinderJson(object):
        def json(cls):
            return {
                "services": [
                    {
                        "active_backend_id": None,
                        "binary": "cinder-volume",
                        "disabled_reason": None,
                        "frozen": False,
                        "host": "juju-ba88f7-8@LVM",
                        "replication_status": "not-capable",
                        "state": state1,
                        "status": "enabled" if status3 else "disabled",
                        "updated_at": "2020-04-29T14:36:56.000000",
                        "zone": "nova",
                    },
                    {
                        "binary": "cinder-scheduler",
                        "disabled_reason": None,
                        "host": "juju-ba88f7-8",
                        "state": "down",
                        "status": status2,
                        "updated_at": "2020-04-29T14:36:57.000000",
                        "zone": "nova",
                    },
                    {
                        "active_backend_id": None,
                        "binary": "cinder-volume",
                        "disabled_reason": None,
                        "frozen": False,
                        "host": "cinder@cinder-ceph",
                        "replication_status": "disabled",
                        "state": "up",
                        "status": "enabled" if status3 else "disabled",
                        "updated_at": "2020-04-29T15:15:42.000000",
                        "zone": "nova",
                    },
                    {
                        "binary": "cinder-scheduler",
                        "disabled_reason": None,
                        "host": "cinder",
                        "state": "up",
                        "status": "enabled" if status3 else "disabled",
                        "updated_at": "2020-04-29T15:15:39.000000",
                        "zone": "nova",
                    },
                ]
            }

    args = _TestArgs()
    cinder = _TestCinder()
    excclass = {
        "CRITICAL: ": nagios_plugin3.CriticalError,
        "WARNING: ": nagios_plugin3.WarnError,
    }

    if result.startswith("OK: "):
        assert check_cinder_services.check_cinder_services(args, cinder) is None
    else:
        prefix = result[: (result.find(": ") + 2)]
        with pytest.raises(excclass[prefix]) as excinfo:
            check_cinder_services.check_cinder_services(args, cinder)
        assert str(excinfo.value) == result


def test_check_cinder_services_unknown():
    class _TestCinder(object):
        def get(cls, name):
            return _TestCinderJson()

    class _TestCinderJson(object):
        def json(cls):
            return {"services": []}

    args, cinder = None, _TestCinder()
    result = "UNKNOWN: No cinder services found"
    with pytest.raises(nagios_plugin3.UnknownError) as excinfo:
        check_cinder_services.check_cinder_services(args, cinder)
    assert str(excinfo.value) == result
