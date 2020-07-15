from datetime import datetime, timedelta
import json
import unittest.mock as mock
from uuid import uuid4

import check_octavia
import pytest


@mock.patch('check_octavia.openstack.connect')
@pytest.mark.parametrize('check', [
    'loadbalancers', 'pools', "amphorae", "image"
])
def test_stable_alarms(connect, check):
    args = mock.MagicMock()
    args.ignored = r''
    args.check = check
    if check == "amphorae":
        # Present 0 Amphora instances
        resp = connect().load_balancer.get()
        resp.status_code = 200
        resp.content = json.dumps({'amphora': []})
    elif check == "image":
        # Present 1 Active Fresh Amphora image
        args.amp_image_tag = 'octavia'
        args.amp_image_days = 1
        amp_image = mock.MagicMock()
        amp_image.status = 'active'
        amp_image.updated_at = datetime.now().isoformat()
        connect().image.images.return_value = [amp_image]

    status, message = check_octavia.process_checks(args)
    assert message in """
OK: total_alarms[0], total_crit[0], total_ignored[0], ignoring r''
"""
    assert status == check_octavia.NAGIOS_STATUS_OK


@mock.patch('check_octavia.openstack.connect')
def test_no_images_is_ignorable(connect):
    args = mock.MagicMock()
    args.ignored = 'none exist'
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = 'octavia'
    args.amp_image_days = 1
    connect().image.images.return_value = []

    status, message = check_octavia.process_checks(args)
    assert message in """
OK: total_alarms[1], total_crit[1], total_ignored[1], ignoring r'(?:none exist)'
"""
    assert status == check_octavia.NAGIOS_STATUS_OK


@mock.patch('check_octavia.openstack.connect')
def test_no_images(connect):
    args = mock.MagicMock()
    args.ignored = r''
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = 'octavia'
    args.amp_image_days = 1
    connect().image.images.return_value = []

    status, message = check_octavia.process_checks(args)
    assert message in """
CRITICAL: total_alarms[1], total_crit[1], total_ignored[0], ignoring r''
Octavia requires image with tag octavia to create amphora, but none exist
"""
    assert status == check_octavia.NAGIOS_STATUS_CRITICAL


@mock.patch('check_octavia.openstack.connect')
def test_no_active_images(connect):
    args = mock.MagicMock()
    args.ignored = r''
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = 'octavia'
    args.amp_image_days = 1
    amp_image = mock.MagicMock()
    amp_image.name = "bob-the-image"
    amp_image.id = str(uuid4())
    amp_image.status = 'inactive'
    amp_image.updated_at = datetime.now().isoformat()
    connect().image.images.return_value = [amp_image]

    status, message = check_octavia.process_checks(args)
    assert message in """
CRITICAL: total_alarms[1], total_crit[1], total_ignored[0], ignoring r''
Octavia requires image with tag octavia to create amphora, but none are active: bob-the-image({})
""".format(amp_image.id)
    assert status == check_octavia.NAGIOS_STATUS_CRITICAL


@mock.patch('check_octavia.openstack.connect')
def test_no_fresh_images(connect):
    args = mock.MagicMock()
    args.ignored = r''
    args.check = "image"
    # Present 1 Active Fresh Amphora image
    args.amp_image_tag = 'octavia'
    args.amp_image_days = 1
    amp_image = mock.MagicMock()
    amp_image.name = "bob-the-image"
    amp_image.id = str(uuid4())
    amp_image.status = 'active'
    amp_image.updated_at = (datetime.now() - timedelta(days=2)).isoformat()
    connect().image.images.return_value = [amp_image]

    status, message = check_octavia.process_checks(args)
    assert message in """
WARNING: total_alarms[1], total_crit[0], total_ignored[0], ignoring r''
Octavia requires image with tag octavia to create amphora, but all images are older than 1 day(s): bob-the-image({})
""".format(amp_image.id)
    assert status == check_octavia.NAGIOS_STATUS_WARNING
