import pytest


def test_openstackservicechecks_common_properties(openstackservicechecks):
    '''Verify the most common properties from the class or default config.yaml'''
    assert isinstance(openstackservicechecks.charm_config, dict)
    assert openstackservicechecks.novarc == '/var/lib/nagios/nagios.novarc'
    assert openstackservicechecks.plugins_dir == '/usr/local/lib/nagios/plugins/'
    assert openstackservicechecks.nova_warn == 2
    assert openstackservicechecks.nova_crit == 1
    assert openstackservicechecks.skip_disabled == ''
    assert openstackservicechecks.check_dns == ''
    assert not openstackservicechecks.is_rally_enabled
    assert not openstackservicechecks.skipped_rally_checks


def test_openstackservicechecks_get_keystone_credentials_unitdata(
        openstackservicechecks, mock_unitdata_keystonecreds):
    """Checks the expected behavior when 'os-credentials' are not shared, but the application is related to keystone.
    """
    assert openstackservicechecks.get_keystone_credentials() == {
        'username': 'nagios', 'password': 'password', 'project_name': 'services',
        'tenant_name': 'services', 'user_domain_name': 'service_domain',
        'project_domain_name': 'service_domain'
        }


@pytest.mark.parametrize('os_credentials,expected', [
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
    assert openstackservicechecks.get_os_credentials() == expected


@pytest.mark.parametrize('skip_rally,result', [
    ('nova,neutron', [True, True, False, False]),
    ('cinder,neutron', [False, True, True, False]),
    ('glance', [True, False, True, True]),
    ('nova neutron', [True, True, True, True]),  # needs to be comma-separated
    ('', [True, True, True, True]),
])
def test_get_rally_checks_context(skip_rally, result, openstackservicechecks):
    openstackservicechecks.charm_config['skip-rally'] = skip_rally
    expected = {comp: result[num]
                for num, comp in enumerate('cinder glance nova neutron'.split())}
    assert openstackservicechecks._get_rally_checks_context() == expected
