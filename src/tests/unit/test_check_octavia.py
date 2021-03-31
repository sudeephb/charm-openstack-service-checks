"""Test octavia nagios check script."""

import json
import unittest.mock as mock
from datetime import datetime, timedelta
from uuid import uuid4

import check_octavia

import pytest


LB_CRITICAL_MESSAGE = """
CRITICAL: total_alarms[1], total_crit[1], total_ignored[0], ignoring r''
loadbalancer {} operating_status is {}
"""


LB_OK_MESSAGE = """
OK: total_alarms[0], total_crit[0], total_ignored[0], ignoring r''
"""


@mock.patch("check_octavia.openstack.connect")
@pytest.mark.parametrize("check", ["loadbalancers", "pools", "amphorae", "image"])
def test_stable_alarms(connect, check):
    """Test for expected green status."""
    args = mock.MagicMock()
    args.ignored = r""
    args.check = check
    if check == "amphorae":
        # Present 0 Amphora instances
        resp = connect().load_balancer.get()
        resp.status_code = 200
        resp.content = json.dumps({"amphora": []})
    elif check == "image":
        # Present 1 Active Fresh Amphora image
        args.amp_image_tag = "octavia"
        args.amp_image_days = 1
        amp_image = mock.MagicMock()
        amp_image.status = "active"
        amp_image.updated_at = datetime.now().isoformat()
        connect().image.images.return_value = [amp_image]

    status, message = check_octavia.process_checks(args)
    assert (
        message
        in """
OK: total_alarms[0], total_crit[0], total_ignored[0], ignoring r''
"""
    )
    assert status == check_octavia.NAGIOS_STATUS_OK


@mock.patch("check_octavia.openstack.connect")
def test_no_images_is_ignorable(connect):
    """Test that we can ignore when no images exist."""
    args = mock.MagicMock()
    args.ignored = "none exist"
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = "octavia"
    args.amp_image_days = 1
    connect().image.images.return_value = []

    status, message = check_octavia.process_checks(args)
    assert (
        message
        in """
OK: total_alarms[1], total_crit[1], total_ignored[1], ignoring r'(?:none exist)'
"""
    )
    assert status == check_octavia.NAGIOS_STATUS_OK


@mock.patch("check_octavia.openstack.connect")
def test_no_images(connect):
    """Test alerting status when no images exist."""
    args = mock.MagicMock()
    args.ignored = r""
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = "octavia"
    args.amp_image_days = 1
    connect().image.images.return_value = []

    status, message = check_octavia.process_checks(args)
    assert (
        message
        in """
CRITICAL: total_alarms[1], total_crit[1], total_ignored[0], ignoring r''
Octavia requires image with tag octavia to create amphora, but none exist
"""
    )
    assert status == check_octavia.NAGIOS_STATUS_CRITICAL


@mock.patch("check_octavia.openstack.connect")
def test_no_active_images(connect):
    """Test alerting status when the octavia amphora image is not active."""
    args = mock.MagicMock()
    args.ignored = r""
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = "octavia"
    args.amp_image_days = 1
    amp_image = mock.MagicMock()
    amp_image.name = "bob-the-image"
    amp_image.id = str(uuid4())
    amp_image.status = "inactive"
    amp_image.updated_at = datetime.now().isoformat()
    connect().image.images.return_value = [amp_image]

    status, message = check_octavia.process_checks(args)
    assert (
        message
        in """
CRITICAL: total_alarms[1], total_crit[1], total_ignored[0], ignoring r''
Octavia requires image with tag octavia to create amphora, but none are active: bob-the-image({})
""".format(  # noqa:E501
            amp_image.id
        )
    )
    assert status == check_octavia.NAGIOS_STATUS_CRITICAL


@mock.patch("check_octavia.openstack.connect")
def test_no_fresh_images(connect):
    """Test alerting for stale octavia amphora images."""
    args = mock.MagicMock()
    args.ignored = r""
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = "octavia"
    args.amp_image_days = 1
    amp_image = mock.MagicMock()
    amp_image.name = "bob-the-image"
    amp_image.id = str(uuid4())
    amp_image.status = "active"
    amp_image.updated_at = (datetime.now() - timedelta(days=2)).isoformat()
    connect().image.images.return_value = [amp_image]

    status, message = check_octavia.process_checks(args)
    assert (
        message
        in """
WARNING: total_alarms[1], total_crit[0], total_ignored[0], ignoring r''
Octavia requires image with tag octavia to create amphora, but all images are older than 1 day(s): bob-the-image({})
""".format(  # noqa:E501
            amp_image.id
        )
    )
    assert status == check_octavia.NAGIOS_STATUS_WARNING


@mock.patch("check_octavia.openstack.connect")
@pytest.mark.parametrize(
    "operating_status, monitor_id, nagios_message, nagios_status",
    [
        ("ONLINE", None, LB_OK_MESSAGE, check_octavia.NAGIOS_STATUS_OK),
        ("DRAINING", None, LB_OK_MESSAGE, check_octavia.NAGIOS_STATUS_OK),
        ("NO_MONITOR", None, LB_OK_MESSAGE, check_octavia.NAGIOS_STATUS_OK),
        ("OFFLINE", None, LB_OK_MESSAGE, check_octavia.NAGIOS_STATUS_OK),
        (
            "OFFLINE",
            str(uuid4()),
            LB_CRITICAL_MESSAGE,
            check_octavia.NAGIOS_STATUS_CRITICAL,
        ),
        (
            "DEGRADED",
            str(uuid4()),
            LB_CRITICAL_MESSAGE,
            check_octavia.NAGIOS_STATUS_CRITICAL,
        ),
        (
            "ERROR",
            str(uuid4()),
            LB_CRITICAL_MESSAGE,
            check_octavia.NAGIOS_STATUS_CRITICAL,
        ),
    ],
)
def test_lb_operating_status(
    connect, operating_status, monitor_id, nagios_message, nagios_status
):
    """Test alerting for LB operating status."""
    args = mock.MagicMock()
    args.ignored = r""
    args.check = "loadbalancers"

    # Loadbalancer with health_monitor not available
    lb = mock.MagicMock()
    lb_uuid = str(uuid4())
    lb.id = lb_uuid
    lb.is_admin_state_up = True
    lb.provisioning_status = "ACTIVE"
    lb.operating_status = operating_status
    lb_vip_port_id = str(uuid4())
    lb.vip_port_id = lb_vip_port_id
    connect().load_balancer.load_balancers.return_value = [lb]

    port = mock.MagicMock()
    port.id = lb_vip_port_id
    connect().network.get_port.return_value = port

    pool = mock.MagicMock()
    pool.id = str(uuid4())
    pool.loadbalancer_id = lb_uuid
    pool.health_monitor_id = monitor_id

    connect().load_balancer.pools.return_value = [pool]

    status, message = check_octavia.process_checks(args)

    if nagios_status == check_octavia.NAGIOS_STATUS_OK:
        assert message in nagios_message
    else:
        assert message in nagios_message.format(lb_uuid, operating_status)

    assert status == nagios_status
