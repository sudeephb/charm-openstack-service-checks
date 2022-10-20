"""Test helper library functions."""
from unittest import mock
from unittest.mock import MagicMock

from charmhelpers.core import hookenv

import keystoneauth1

from lib_openstack_service_checks import (
    OSCConfigError,
    OSCHelper,
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
                "credentials_project=services, domain=service_domain, volume_api_version=3"  # noqa:E501
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
                "volume_api_version": "3",
            },
        ),
        (
            (
                'username=nagios, password=password, region_name=RegionOne, auth_url="http://XX.XX.XX.XX:5000/v2.0",'  # noqa:E501
                "credentials_project=services, volume_api_version=3"
            ),
            {
                "username": "nagios",
                "password": "password",
                "tenant_name": "services",
                "region_name": "RegionOne",
                "auth_url": "http://XX.XX.XX.XX:5000/v2.0",
                "volume_api_version": "3",
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


@pytest.mark.parametrize(
    "value, exp_ids", [("1,2,3,,4", ["1", "2", "3", "4"]), ("", []), ("all", ["all"])]
)
def test_get_resource_ids(value, exp_ids):
    """Test getting list of ids from config option."""
    with mock.patch("charmhelpers.core.hookenv.config", return_value={"test": value}):
        helper = OSCHelper()
        ids = helper._get_resource_ids("test")

        assert ids == exp_ids


@pytest.mark.parametrize(
    "resource, ids, skip_ids, exp_kwargs",
    [
        (
            "network",
            ["1", "2", "3"],
            None,
            {
                "shortname": "networks",
                "description": "Check networks: 1,2,3 (skips: )",
                "check_cmd": "/usr/local/lib/nagios/plugins/check_resources.py network --id 1 --id 2 --id 3",  # noqa:E501
            },
        ),
        (
            "server",
            ["1", "2", "3"],
            None,
            {
                "shortname": "servers",
                "description": "Check servers: 1,2,3 (skips: )",
                "check_cmd": "/usr/local/lib/nagios/plugins/check_resources.py server --id 1 --id 2 --id 3",  # noqa:E501
            },
        ),
        (
            "server",
            ["all"],
            ["1"],
            {
                "shortname": "servers",
                "description": "Check servers: all (skips: 1)",
                "check_cmd": "/usr/local/lib/nagios/plugins/check_resources.py server --all --skip-id 1",  # noqa:E501
            },
        ),
    ],
)
def test_helper_get_resource_check_kwargs(resource, ids, skip_ids, exp_kwargs):
    """Test generating shortname, CMD and description for check."""
    with mock.patch("charmhelpers.core.hookenv.config", return_value={}):
        helper = OSCHelper()
        kwargs = helper._get_resource_check_kwargs(resource, ids, skip_ids)

        assert kwargs == exp_kwargs


@mock.patch("charmhelpers.core.hookenv.config")
def test_render_resource_check_by_existence(mock_config):
    """Test rendering NRPE check for OpenStack resource."""
    nrpe = MagicMock()

    # no configuration
    mock_config.return_value = {}
    OSCHelper()._render_resource_check_by_existence(nrpe, "network")
    nrpe.add_check.assert_not_called()
    nrpe.remove_check.assert_called_once()
    nrpe.reset_mock()

    # wrong configuration
    mock_config.return_value = {"check-networks": "all"}
    with pytest.raises(OSCConfigError):
        OSCHelper()._render_resource_check_by_existence(nrpe, "network")

    nrpe.reset_mock()

    # proper configuration
    mock_config.return_value = {"check-networks": "1,2,3"}
    OSCHelper()._render_resource_check_by_existence(nrpe, "network")
    nrpe.add_check.assert_called_once()
    nrpe.remove_check.assert_not_called()
    nrpe.reset_mock()


@mock.patch("charmhelpers.core.hookenv.config")
def test_render_resources_check_by_status(mock_config):
    """Test rendering NRPE check for OpenStack resource."""
    nrpe = MagicMock()

    # no configuration
    mock_config.return_value = {}
    OSCHelper()._render_resources_check_by_status(nrpe, "server")
    nrpe.add_check.assert_not_called()
    nrpe.remove_check.assert_called_once()
    nrpe.reset_mock()

    # wrong configuration
    mock_config.return_value = {"check-servers": "1", "skip-servers": "1,2,3"}
    with mock.patch("charmhelpers.core.hookenv.log") as mock_log:
        OSCHelper()._render_resources_check_by_status(nrpe, "server")
        mock_log.assert_any_call("skip-servers will be omitted", hookenv.WARNING)

    nrpe.add_check.assert_called_once()
    nrpe.remove_check.assert_not_called()
    nrpe.reset_mock()

    # proper configuration
    mock_config.return_value = {"check-servers": "all", "skip-server": "1,2,3"}
    OSCHelper()._render_resources_check_by_status(nrpe, "server")
    nrpe.add_check.assert_called_once()
    nrpe.remove_check.assert_not_called()
    nrpe.reset_mock()


@pytest.mark.parametrize("interface", ["admin", "internal", "public"])
@mock.patch("charmhelpers.core.hookenv.config")
def test__render_http_endpoint_checks(mock_config, interface):
    """Test render NRPE checks for http endpoints."""
    nrpe = MagicMock()
    test_url = "/"
    test_host = "http://localhost"
    test_port = "80"
    test_kwargs = {"interface": interface}

    test_cmd = "{} -H {} -p {} -u {}".format(
        "/usr/lib/nagios/plugins/check_http",
        test_host,
        test_port,
        test_url,
    )

    # enable check_{}_urls
    mock_config.return_value = {"check_{}_urls".format(interface): True}
    OSCHelper()._render_http_endpoint_checks(
        test_url, test_host, test_port, nrpe, **test_kwargs
    )
    nrpe.add_check.assert_called_with(
        check_cmd=test_cmd,
        shortname="check_http",
        description="Added nrpe check for http endpoint.",
    )
    nrpe.reset_mock()

    # disable check_{}_urls
    mock_config.return_value = {}
    OSCHelper()._render_http_endpoint_checks(
        test_url, test_host, test_port, nrpe, **test_kwargs
    )
    nrpe.remove_check.assert_called_with(
        shortname="check_http",
    )
    nrpe.reset_mock()


@pytest.mark.parametrize("interface", ["admin", "internal", "public"])
@mock.patch("charmhelpers.core.hookenv.config")
def test__render_https_endpoint_checks(mock_config, interface):
    """Test render NRPE checks for https endpoints."""
    nrpe = MagicMock()
    test_url = "/"
    test_host = "https://localhost"
    test_port = "80"
    test_kwargs = {"interface": interface}

    test_cmd = "{} -H {} -p {} -u {} -c {} -w {}".format(
        "/usr/local/lib/nagios/plugins/check_ssl_cert",
        test_host,
        test_port,
        test_url,
        14,  # default value for "tls_crit_days"
        30,  # default value for "tls_warn_days"
    )

    # enable check_{}_urls
    mock_config.return_value = {"check_{}_urls".format(interface): True}
    OSCHelper()._render_https_endpoint_checks(
        test_url, test_host, test_port, nrpe, **test_kwargs
    )
    nrpe.add_check.assert_called_with(
        check_cmd=test_cmd,
        shortname="check_ssl_cert",
        description="Added nrpe check for https endpoint.",
    )
    nrpe.reset_mock()

    # disable check_{}_urls
    mock_config.return_value = {}
    OSCHelper()._render_https_endpoint_checks(
        test_url, test_host, test_port, nrpe, **test_kwargs
    )
    nrpe.remove_check.assert_called_with(
        shortname="check_ssl_cert",
    )
    nrpe.reset_mock()


@pytest.mark.parametrize("v3_interface", ["admin", "internal", "public"])
def test__normalize_endpoint_attr(v3_interface):
    """Test normalize the attributes in service catalog endpoint between v2 and v3."""
    v2_interface = v3_interface + "url"
    mock_endpoint = MagicMock()
    mock_endpoint.mock_add_spec([v2_interface])
    setattr(mock_endpoint, v2_interface, "http://localhost/")
    pytest.raises(AttributeError, getattr, mock_endpoint, "interface")
    pytest.raises(AttributeError, getattr, mock_endpoint, "url")
    with mock.patch("charmhelpers.core.hookenv.config", return_value={}):
        interface, url = OSCHelper()._normalize_endpoint_attr(mock_endpoint)
    assert interface == v3_interface
    assert url == getattr(mock_endpoint, v2_interface)


@mock.patch("lib_openstack_service_checks.OSCHelper._render_https_endpoint_checks")
@mock.patch("lib_openstack_service_checks.OSCHelper._render_http_endpoint_checks")
def test_create_endpoint_checks__simple_stream(
    mock_render_http, mock_render_https, mock_simple_stream_endpoint
):
    """Test create endpoint check for simple-stream service."""
    OSCHelper().create_endpoint_checks()
    mock_render_http.assert_not_called()
    mock_render_https.assert_not_called()


@pytest.mark.parametrize("v2_interface_url", ["adminurl", "internalurl", "publicurl"])
@mock.patch("lib_openstack_service_checks.OSCHelper._render_https_endpoint_checks")
@mock.patch("lib_openstack_service_checks.OSCHelper._render_http_endpoint_checks")
def test_create_endpoint_checks__v2_keystone(
    mock_render_http, mock_render_https, v2_interface_url, mock_v2_keystone_endpoint
):
    """Test create endpoint check for v2 keystone service."""
    pytest.raises(AttributeError, getattr, mock_v2_keystone_endpoint, "interface")
    setattr(mock_v2_keystone_endpoint, v2_interface_url, "https://localhost/")
    OSCHelper().create_endpoint_checks()
    mock_render_http.assert_not_called()
    mock_render_https.assert_not_called()


@pytest.mark.parametrize(
    "v3_interface,result",
    [
        (
            {
                "scheme": "http",
                "interface": "admin",
            },
            (1, 0),
        ),
        (
            {
                "scheme": "https",
                "interface": "admin",
            },
            (1, 1),
        ),
        (
            {
                "scheme": "http",
                "interface": "internal",
            },
            (1, 0),
        ),
        (
            {
                "scheme": "https",
                "interface": "internal",
            },
            (1, 1),
        ),
        (
            {
                "scheme": "http",
                "interface": "public",
            },
            (1, 0),
        ),
        (
            {
                "scheme": "https",
                "interface": "public",
            },
            (1, 1),
        ),
    ],
)
@mock.patch("lib_openstack_service_checks.OSCHelper._render_https_endpoint_checks")
@mock.patch("lib_openstack_service_checks.OSCHelper._render_http_endpoint_checks")
def test_create_endpoint_checks__v2_services(
    mock_render_http,
    mock_render_https,
    v3_interface,
    result,
    mock_any_endpoint,
):
    """Test create endpoint check for v2 services."""
    v2_interface_url = v3_interface["interface"] + "url"
    mock_any_endpoint.mock_add_spec([v2_interface_url])
    setattr(
        mock_any_endpoint,
        v2_interface_url,
        "{}://localhost/".format(v3_interface["scheme"]),
    )
    pytest.raises(AttributeError, getattr, mock_any_endpoint, "interface")
    pytest.raises(AttributeError, getattr, mock_any_endpoint, "url")

    OSCHelper().create_endpoint_checks()
    assert mock_any_endpoint.interface == v3_interface["interface"]
    assert mock_any_endpoint.url == "{}://localhost/".format(v3_interface["scheme"])
    assert mock_render_http.call_count == result[0]
    assert mock_render_https.call_count == result[1]


@pytest.mark.parametrize(
    "v3_interface,result",
    [
        (
            {
                "scheme": "http",
                "interface": "admin",
            },
            (1, 0),
        ),
        (
            {
                "scheme": "https",
                "interface": "admin",
            },
            (1, 1),
        ),
        (
            {
                "scheme": "http",
                "interface": "internal",
            },
            (1, 0),
        ),
        (
            {
                "scheme": "https",
                "interface": "internal",
            },
            (1, 1),
        ),
        (
            {
                "scheme": "http",
                "interface": "public",
            },
            (1, 0),
        ),
        (
            {
                "scheme": "https",
                "interface": "public",
            },
            (1, 1),
        ),
    ],
)
@mock.patch("lib_openstack_service_checks.OSCHelper._render_https_endpoint_checks")
@mock.patch("lib_openstack_service_checks.OSCHelper._render_http_endpoint_checks")
def test_create_endpoint_checks__v3_services(
    mock_render_http,
    mock_render_https,
    v3_interface,
    result,
    mock_any_endpoint,
):
    """Test create endpoint check for v3 services."""
    setattr(mock_any_endpoint, "interface", v3_interface["interface"])
    setattr(
        mock_any_endpoint,
        "url",
        "{}://localhost/".format(v3_interface["scheme"]),
    )
    OSCHelper().create_endpoint_checks()
    assert mock_render_http.call_count == result[0]
    assert mock_render_https.call_count == result[1]
