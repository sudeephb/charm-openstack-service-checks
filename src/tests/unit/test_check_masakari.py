"""Test masakari nagios check script."""
import unittest.mock as mock
from uuid import uuid4

import check_masakari


@mock.patch("check_masakari.openstack.connect")
def test_check_masakari(connect):
    """Test for expected segment host on maintenance."""
    segment = mock.MagicMock()
    segment.uuid = str(uuid4())
    connect().instance_ha.segments = mock.MagicMock(return_value=[segment])
    host = mock.MagicMock()
    host.uuid = str(uuid4())
    host.on_maintenance = True
    connect().instance_ha.hosts = mock.MagicMock(return_value=[host])
    status, message = check_masakari.process_checks()
    assert status == check_masakari.NAGIOS_STATUS_CRITICAL


@mock.patch("check_masakari.openstack.connect")
def test_check_masakari_no_host(connect):
    """Test for no segment host on maintenance."""
    segment = mock.MagicMock()
    segment.uuid = str(uuid4())
    connect().instance_ha.segments = mock.MagicMock(return_value=[segment])
    host = mock.MagicMock()
    host.uuid = str(uuid4())
    host.on_maintenance = False
    connect().instance_ha.hosts = mock.MagicMock(return_value=[host])
    status, message = check_masakari.process_checks()
    assert status == check_masakari.NAGIOS_STATUS_OK
