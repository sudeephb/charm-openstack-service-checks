#!/usr/bin/python3
import mock
import pytest


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
        yml = yaml.load(open('./config.yaml'))

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


# @pytest.fixture
# def mock_openstackservicechecks_parse_os_credentials(monkeypatch):
#     monkeypatch.setattr(
#         'lib_openstack_service_checks.OpenstackservicechecksHelper.parse_os_credentials', lambda: {})


@pytest.fixture
def mock_unitdata_keystonecreds(monkeypatch):
    creds = {'keystonecreds': {'username': 'nagios', 'password': 'password', 'project_name': 'services',
                               'tenant_name': 'services', 'user_domain_name': 'service_domain',
                               'project_domain_name': 'service_domain'}}
    monkeypatch.setattr('lib_openstack_service_checks.unitdata.kv', lambda: creds)


@pytest.fixture
def mock_hookenv_status_set(monkeypatch):
    class CheckArgs(object):
        def __init__(self):
            self._args = []

        def __call__(self, *args):
            self._args.append(list(args))

        @property
        def args(self):
            if len(self._args) > 1:
                return self._args
            else:
                return self._args[0]

    obj = CheckArgs()
    monkeypatch.setattr('lib_openstack_service_checks.hookenv.status_set', obj)
    return obj


@pytest.fixture
def openstackservicechecks(tmpdir, mock_hookenv_config, mock_charm_dir, monkeypatch):
    def mock_subprocess_call(arg):
        assert arg == ["/usr/sbin/update-ca-certificates"]

    from lib_openstack_service_checks import OpenstackservicechecksHelper
    helper = OpenstackservicechecksHelper()
    helper._write_tls_cert = lambda x: None

    # Any other functions that load helper will get this version
    monkeypatch.setattr('lib_openstack_service_checks.hookenv.log', lambda msg, level='INFO': None)
    monkeypatch.setattr('lib_openstack_service_checks.subprocess.call', mock_subprocess_call)
    monkeypatch.setattr('lib_openstack_service_checks.OpenstackservicechecksHelper', lambda: helper)

    return helper
