import unittest.mock as mock
import os
import sys

import pytest

TEST_DIR = os.path.dirname(__file__)
CHECKS_DIR = os.path.join(TEST_DIR, '..', '..', 'files', 'plugins')
sys.path.append(CHECKS_DIR)


# If layer options are used, add this to openstackservicechecks
# and import layer in lib_openstack_service_checks
@pytest.fixture
def mock_layers(monkeypatch):
    import sys
    sys.modules['charms.layer'] = mock.Mock()
    sys.modules['reactive'] = mock.Mock()
    # Mock any functions in layers that need to be mocked here

    def options(layer):
        # mock options for layers here
        if layer == 'example-layer':
            options = {'port': 9999}
            return options
        else:
            return None

    monkeypatch.setattr('lib_openstack_service_checks.layer.options', options)


@pytest.fixture
def mock_hookenv_config(monkeypatch):
    import yaml

    def mock_config():
        cfg = {}
        yml = yaml.safe_load(open('./config.yaml'))

        # Load all defaults
        for key, value in yml['options'].items():
            cfg[key] = value['default']

        # Manually add cfg from other layers
        # cfg['my-other-layer'] = 'mock'
        return cfg

    monkeypatch.setattr('lib_openstack_service_checks.hookenv.config', mock_config)


@pytest.fixture
def mock_remote_unit(monkeypatch):
    monkeypatch.setattr('lib_openstack_service_checks.hookenv.remote_unit', lambda: 'unit-mock/0')


@pytest.fixture
def mock_charm_dir(monkeypatch):
    monkeypatch.setattr('lib_openstack_service_checks.hookenv.charm_dir', lambda: '/mock/charm/dir')


@pytest.fixture
def mock_unitdata_keystonecreds(monkeypatch):
    creds = {'keystonecreds': {'username': 'nagios',
                               'password': 'password',
                               'project_name': 'services',
                               'tenant_name': 'services',
                               'user_domain_name': 'service_domain',
                               'project_domain_name': 'service_domain',
                               }
             }
    monkeypatch.setattr('lib_openstack_service_checks.unitdata.kv', lambda: creds)


@pytest.fixture
def openstackservicechecks(tmpdir, mock_hookenv_config, mock_charm_dir, monkeypatch):
    from lib_openstack_service_checks import OSCHelper
    helper = OSCHelper()

    # Any other functions that load helper will get this version
    monkeypatch.setattr('lib_openstack_service_checks.hookenv.log', lambda msg, level='INFO': None)
    monkeypatch.setattr('lib_openstack_service_checks.OSCHelper', lambda: helper)

    return helper
