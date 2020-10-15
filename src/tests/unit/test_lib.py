"""Test helper library functions."""

from unittest.mock import MagicMock

import keystoneauth1

from lib_openstack_service_checks import (
    OSCKeystoneClientError,
    OSCKeystoneServerError,
    OSCSslError,
)

import pytest


def test_openstackservicechecks_common_properties(openstackservicechecks):
    """Verify the most common properties from the class or default config.yaml."""
    assert isinstance(openstackservicechecks.charm_config, dict)
    assert openstackservicechecks.check_dns == ""
    assert openstackservicechecks.contrail_analytics_vip == ""
    assert openstackservicechecks.is_neutron_agents_check_enabled
    assert not openstackservicechecks.is_rally_enabled
    assert openstackservicechecks.novarc == "/var/lib/nagios/nagios.novarc"
    assert openstackservicechecks.nova_crit == 1
    assert openstackservicechecks.nova_warn == 2
    assert openstackservicechecks.plugins_dir == "/usr/local/lib/nagios/plugins/"
    assert openstackservicechecks.rally_cron_schedule == "*/15 * * * *"
    assert openstackservicechecks.skip_disabled == ""
    assert not openstackservicechecks.skipped_rally_checks


def test_openstackservicechecks_get_keystone_credentials_unitdata(
    openstackservicechecks, mock_unitdata_keystonecreds
):
    """Check expected behavior when 'os-credentials' not shared, but related to ks."""
    assert openstackservicechecks.get_keystone_credentials() == {
        "username": "nagios",
        "password": "password",
        "project_name": "services",
        "tenant_name": "services",
        "user_domain_name": "service_domain",
        "project_domain_name": "service_domain",
    }


@pytest.mark.parametrize(
    "os_credentials,expected",
    [
        (
            (
                'username=nagios, password=password, region_name=RegionOne, auth_url="http://XX.XX.XX.XX:5000/v3",'  # noqa:E501
                "credentials_project=services, domain=service_domain"
            ),
            {
                "username": "nagios",
                "password": "password",
                "project_name": "services",
                "auth_version": 3,
                "user_domain_name": "service_domain",
                "project_domain_name": "service_domain",
                "region_name": "RegionOne",
                "auth_url": "http://XX.XX.XX.XX:5000/v3",
            },
        ),
        (
            (
                'username=nagios, password=password, region_name=RegionOne, auth_url="http://XX.XX.XX.XX:5000/v2.0",'  # noqa:E501
                "credentials_project=services"
            ),
            {
                "username": "nagios",
                "password": "password",
                "tenant_name": "services",
                "region_name": "RegionOne",
                "auth_url": "http://XX.XX.XX.XX:5000/v2.0",
            },
        ),
    ],
)
def test_openstackservicechecks_get_keystone_credentials_oscredentials(
    os_credentials, expected, openstackservicechecks, mock_unitdata_keystonecreds
):
    """Check the expected behavior when keystone v2 and v3 data is set via config."""
    openstackservicechecks.charm_config["os-credentials"] = os_credentials
    assert openstackservicechecks.get_os_credentials() == expected


@pytest.mark.parametrize(
    "skip_rally,result",
    [
        ("nova,neutron", [True, True, False, False]),
        ("cinder,neutron", [False, True, True, False]),
        ("glance", [True, False, True, True]),
        ("nova neutron", [True, True, True, True]),  # needs to be comma-separated
        ("", [True, True, True, True]),
    ],
)
def test_get_rally_checks_context(skip_rally, result, openstackservicechecks):
    """Check that rally config context configuration works as expected."""
    openstackservicechecks.charm_config["skip-rally"] = skip_rally
    expected = {
        comp: result[num]
        for num, comp in enumerate("cinder glance nova neutron".split())
    }
    assert openstackservicechecks._get_rally_checks_context() == expected


@pytest.mark.parametrize(
    "keystone_auth_exception,expected_raised_exception",
    [
        (keystoneauth1.exceptions.http.InternalServerError, OSCKeystoneServerError),
        (keystoneauth1.exceptions.connection.ConnectFailure, OSCKeystoneServerError),
        (keystoneauth1.exceptions.http.BadRequest, OSCKeystoneClientError),
        (keystoneauth1.exceptions.connection.SSLError, OSCSslError),
    ],
)
@pytest.mark.parametrize("source", ["endpoints", "services"])
def test_keystone_client_exceptions(
    keystone_auth_exception, expected_raised_exception, openstackservicechecks, source
):
    """Test OSC exceptions."""
    mock_keystone_client = MagicMock()
    getattr(mock_keystone_client, source).list.side_effect = keystone_auth_exception
    openstackservicechecks._keystone_client = mock_keystone_client
    with pytest.raises(expected_raised_exception):
        if source == "endpoints":
            openstackservicechecks.keystone_endpoints
        else:
            openstackservicechecks.keystone_services
