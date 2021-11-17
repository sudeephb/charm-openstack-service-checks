"""Initialize the pytest unittesting environment."""

import sys
import unittest.mock as mock
from os.path import abspath, dirname, join

import pytest

TEST_DIR = dirname(abspath(__file__))
REACTIVE_DIR = dirname(dirname(TEST_DIR))
CHARM_DIR = REACTIVE_DIR
FILES_DIR = join(CHARM_DIR, "files")
CHECKS_DIR = join(FILES_DIR, "plugins")
sys.path.append(FILES_DIR)
sys.path.append(CHECKS_DIR)


# If layer options are used, add this to openstackservicechecks
# and import layer in lib_openstack_service_checks
@pytest.fixture
def mock_layers(monkeypatch):
    """Mock charms.layer."""
    import sys

    sys.modules["charms.layer"] = mock.Mock()
    sys.modules["reactive"] = mock.Mock()
    # Mock any functions in layers that need to be mocked here

    def options(layer):
        # mock options for layers here
        if layer == "example-layer":
            options = {"port": 9999}
            return options
        else:
            return None

    monkeypatch.setattr("lib_openstack_service_checks.layer.options", options)


@pytest.fixture
def mock_hookenv_config(monkeypatch):
    """Mock hookenv.config."""
    import yaml

    def mock_config():
        cfg = {}
        yml = yaml.safe_load(open("./config.yaml"))

        # Load all defaults
        for key, value in yml["options"].items():
            cfg[key] = value["default"]

        # Manually add cfg from other layers
        # cfg['my-other-layer'] = 'mock'
        return cfg

    monkeypatch.setattr("lib_openstack_service_checks.hookenv.config", mock_config)


@pytest.fixture
def mock_remote_unit(monkeypatch):
    """Mock remote_unit as unit-mock/0."""
    monkeypatch.setattr(
        "lib_openstack_service_checks.hookenv.remote_unit", lambda: "unit-mock/0"
    )


@pytest.fixture
def mock_charm_dir(monkeypatch):
    """Mock hookenv.charm_dir."""
    monkeypatch.setattr(
        "lib_openstack_service_checks.hookenv.charm_dir", lambda: "/mock/charm/dir"
    )


@pytest.fixture
def mock_unitdata_keystonecreds(monkeypatch):
    """Mock keystone credentials from unitdata.kv."""
    creds = {
        "keystonecreds": {
            "username": "nagios",
            "password": "password",
            "project_name": "services",
            "tenant_name": "services",
            "user_domain_name": "service_domain",
            "project_domain_name": "service_domain",
        }
    }
    monkeypatch.setattr("lib_openstack_service_checks.unitdata.kv", lambda: creds)


@pytest.fixture
def openstackservicechecks(tmpdir, mock_hookenv_config, mock_charm_dir, monkeypatch):
    """Mock the OSCHelper library bits."""
    from lib_openstack_service_checks import OSCHelper

    helper = OSCHelper()

    # Any other functions that load helper will get this version
    monkeypatch.setattr(
        "lib_openstack_service_checks.hookenv.log", lambda msg, level="INFO": None
    )
    monkeypatch.setattr("lib_openstack_service_checks.OSCHelper", lambda: helper)

    return helper
