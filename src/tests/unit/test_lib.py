#!/usr/bin/python3
from collections import OrderedDict
from pytest import mark


def test_openstackservicechecks_common_properties(openstackservicechecks):
    '''Verify the most common properties from the class or default config.yaml'''
    assert isinstance(openstackservicechecks.charm_config, dict)
    assert openstackservicechecks.novarc == '/var/lib/nagios/nagios.novarc'
    assert openstackservicechecks.pluginsdir == '/usr/local/lib/nagios/plugins/'
    assert openstackservicechecks.nova_warn == 2
    assert openstackservicechecks.nova_crit == 1
    assert openstackservicechecks.skip_disabled == ''
    assert openstackservicechecks.check_dns == ''


def test_openstackservicechecks_get_keystone_credentials_unitdata(
        openstackservicechecks, mock_unitdata_keystonecreds, mock_hookenv_status_set):
    """Checks the expected behavior when 'os-credentials' are not shared, but the application is related to keystone.
    """
    assert openstackservicechecks.get_keystone_credentials == OrderedDict(
        {'username': 'nagios', 'password': 'password', 'project_name': 'services', 'tenant_name': 'services',
         'user_domain_name': 'service_domain', 'project_domain_name': 'service_domain'}
    )
    assert mock_hookenv_status_set.args[0] == ['blocked', 'Missing os-credentials vars: auth_url']
    assert mock_hookenv_status_set.args[1] == ['active', 'Keystone credentials shared']


@mark.parametrize('os_credentials,expected', [
    (('username=nagios, password=password, region_name=RegionOne, auth_url="http://XX.XX.XX.XX:5000/v3",'
     'credentials_project=services, domain=service_domain'),
     {'username': 'nagios', 'password': 'password', 'project_name': 'services', 'auth_version': 3,
      'user_domain_name': 'service_domain', 'project_domain_name': 'service_domain', 'region_name': 'RegionOne',
      'auth_url': 'http://XX.XX.XX.XX:5000/v3'},
     ),
    (('username=nagios, password=password, region_name=RegionOne, auth_url="http://XX.XX.XX.XX:5000/v2.0",'
      'credentials_project=services'),
     {'username': 'nagios', 'password': 'password', 'tenant_name': 'services', 'region_name': 'RegionOne',
      'auth_url': 'http://XX.XX.XX.XX:5000/v2.0'},
     )
])
def test_openstackservicechecks_get_keystone_credentials_oscredentials(
        os_credentials, expected, openstackservicechecks, mock_unitdata_keystonecreds):
    """Checks the expected behavior when keystone v2 and v3 data is shared via the 'os-credentials' config parameter.
    """
    openstackservicechecks.charm_config['os-credentials'] = os_credentials
    assert openstackservicechecks.get_keystone_credentials == OrderedDict(expected)


@mark.parametrize('os_credentials,expected', [
    (('username=nagios, password=password, region_name=RegionOne, auth_url="http://XX.XX.XX.XX:5000/v3",'
      'credentials_project=services'),
     'domain',
     ),
    ('username=nagios, password=password, region_name=RegionOne, auth_url="http://XX.XX.XX.XX:5000/v2.0",',
     'credentials_project',
     ),
    ('username=nagios, password=password, region_name=RegionOne, credentials_project=services, domain=service_domain',
     'auth_url',
     ),
])
def test_openstackservicechecks_get_keystone_credentials_oscredentials_missingvars(
        os_credentials, expected, openstackservicechecks, monkeypatch, mock_hookenv_status_set):
    """Checks expected behavior when there is missing data shared via the 'os-credentials' config parameter,
    and the application is not related to keystone.
    """
    monkeypatch.setattr('lib_openstack_service_checks.unitdata.kv', lambda: {})
    openstackservicechecks.charm_config['os-credentials'] = os_credentials
    assert openstackservicechecks.get_keystone_credentials is None
    assert mock_hookenv_status_set.args == ['blocked', 'Missing os-credentials vars: {}'.format(expected)]


@mark.parametrize('trusted_ssl_ca,expected', [
    (None, True),
    ('', True),
    ('dGVzdAo=', 'True'),
])
def test_openstackservicechecks_fix_ssl(trusted_ssl_ca, expected, openstackservicechecks):
    """When trusted_ssl_ca parameter is None, value will be taken from config.yaml"""
    if trusted_ssl_ca is not None:
        openstackservicechecks.charm_config['trusted_ssl_ca'] = trusted_ssl_ca
    assert openstackservicechecks.fix_ssl() is True
