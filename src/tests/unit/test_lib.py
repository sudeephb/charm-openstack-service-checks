#!/usr/bin/python3


class TestLib():
    def test_pytest(self):
        assert True

    def test_openstackservicechecks(self, openstackservicechecks):
        ''' See if the helper fixture works to load charm configs '''
        assert isinstance(openstackservicechecks.charm_config, dict)

    # Include tests for functions in lib_openstack_service_checks
