"""Test deployment of openstack-service-checks charm."""

import logging
import time
import unittest
from time import sleep

import zaza.model as model


class TestBase(unittest.TestCase):
    """Base Class for charm functional tests."""

    @classmethod
    def setUpClass(cls):
        """Run setup for tests."""
        cls.model_name = model.get_juju_model()
        cls.application_name = "openstack-service-checks"
        cls.lead_unit_name = model.get_lead_unit_name(
            cls.application_name, model_name=cls.model_name
        )
        cls.units = model.get_units(cls.application_name, model_name=cls.model_name)
        cls.osc_ip = model.get_app_ips(cls.application_name)[0]


class TestOpenStackServiceChecks(TestBase):
    """Test OpenStack service checks."""

    def test_01_verify_default_nrpe_checks(self):
        """Verify nrpe check exists."""
        logging.debug(
            "Verify the nrpe checks are created and have the required content..."
        )

        filenames = [
            "/etc/nagios/nrpe.d/check_{service}_{endpoint}.cfg".format(
                service=service, endpoint=endpoint
            )
            for service in "keystone neutron nova swift".split()
            for endpoint in "admin internal public".split()
        ]
        filenames.extend(
            [
                "/etc/nagios/nrpe.d/check_cinder_services.cfg",
                "/etc/nagios/nrpe.d/check_neutron_agents.cfg",
                "/etc/nagios/nrpe.d/check_nova_services.cfg",
                "/etc/nagios/nrpe.d/check_floating_ips.cfg",
                "/etc/nagios/nrpe.d/check_ports.cfg",
                "/etc/nagios/nrpe.d/check_servers.cfg",
            ]
        )
        for nrpe_check in filenames:
            logging.info("Checking content of '{}' nrpe check".format(nrpe_check))
            cmd = "cat " + nrpe_check
            result = model.run_on_unit(self.lead_unit_name, cmd)
            code = result.get("Code")
            if code != 0:
                logging.warning(
                    "Unable to find nrpe check {} at /etc/nagios/nrpe.d/".format(
                        nrpe_check
                    )
                )

                raise model.CommandRunFailed(cmd, result)

    def test_02_openstackservicechecks_update_endpoint(self):
        """Verify endpoint check is updated."""
        expect_port = "8080"
        model.set_application_config("ceph-radosgw", {"port": expect_port})
        model.block_until_all_units_idle()

        for _ in range(10):
            # Need to retry this as endpoint update takes some time to propagate
            check_configs = []
            for endpoint in "admin internal public".split():
                filename = "/etc/nagios/nrpe.d/check_swift_{}.cfg".format(endpoint)
                cmd = "cat {}".format(filename)
                result = model.run_on_unit(self.lead_unit_name, cmd)
                check_configs.append(result.get("Stdout"))
            if all([" -p {} ".format(expect_port) in s for s in check_configs]):
                break
            sleep(4)
        else:
            self.assertTrue(
                False,
                "Port {} not in all endpoints: {}".format(expect_port, check_configs),
            )

    def test_03_openstackservicechecks_remove_endpoint_checks(self):
        """Verify nrpe checks are removed."""
        endpoint_checks_config = {
            "check_{endpoint}_urls".format(endpoint=endpoint): "false"
            for endpoint in "admin internal public".split()
        }

        model.set_application_config(self.application_name, endpoint_checks_config)
        model.block_until_all_units_idle()
        filenames = [
            "/etc/nagios/nrpe.d/check_{service}_{endpoint}.cfg".format(
                service=service, endpoint=endpoint
            )
            for service in "keystone neutron nova".split()
            for endpoint in "admin internal public".split()
        ]
        for filename in filenames:
            cmd = "cat {}".format(filename)
            result = model.run_on_unit(self.lead_unit_name, cmd)
            self.assertTrue(result.get("Code") != 0)
        # re-enable endpoint checks
        endpoint_checks_config = [
            "check_{endpoint}_urls".format(endpoint=endpoint)
            for endpoint in "admin internal public".split()
        ]
        model.reset_application_config(self.application_name, endpoint_checks_config)
        model.block_until_all_units_idle()

    def test_04_openstackservicechecks_enable_rally(self):
        """Verify rally is enabled."""
        filenames = ["/etc/cron.d/osc_rally", "/etc/nagios/nrpe.d/check_rally.cfg"]
        model.set_application_config(self.application_name, {"check-rally": "true"})

        # model.block_until_all_units_idle fire too quick before config change
        # So we sleep a while wait for application react.
        time.sleep(10)
        model.block_until_all_units_idle()
        for filename in filenames:
            cmd = "cat {}".format(filename)
            result = model.run_on_unit(self.lead_unit_name, cmd)
            content = result.get("Stdout")
            self.assertTrue(result.get("Code") == 0)
            self.assertTrue(len(content) > 0)

    def test_05_openstackservicechecks_enable_contrail_analytics_vip(self):
        """Verify contrail analytics VIP is enabled."""
        filename = "/etc/nagios/nrpe.d/check_contrail_analytics_alarms.cfg"
        model.set_application_config(
            self.application_name, {"contrail_analytics_vip": ""}
        )
        model.block_until_all_units_idle()
        cmd = "cat {}".format(filename)
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertTrue(result.get("Code") != 0)
        model.set_application_config(
            self.application_name,
            {
                "contrail_analytics_vip": "127.0.0.1",
                "contrail_ignored_alarms": "vrouter,testable",
            },
        )
        model.block_until_all_units_idle()
        result = model.run_on_unit(self.lead_unit_name, cmd)
        content = result.get("Stdout")
        self.assertTrue(result.get("Code") == 0)
        self.assertTrue("--ignored vrouter,testable" in content)

    def test_06_openstackservicechecks_disable_check_neutron_agents(self):
        """Verify neutron agent check is disabled."""
        filename = "/etc/nagios/nrpe.d/check_neutron_agents.cfg"
        model.set_application_config(
            self.application_name, {"check-neutron-agents": "false"}
        )
        model.block_until_all_units_idle()
        cmd = "cat {}".format(filename)
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertTrue(result.get("Code") != 0)

        model.set_application_config(
            self.application_name, {"check-neutron-agents": "true"}
        )
        model.block_until_all_units_idle()
        result = model.run_on_unit(self.lead_unit_name, cmd)
        content = result.get("Stdout")
        self.assertTrue(result.get("Code") == 0)
        self.assertTrue(len(content) > 0)

    def test_07_openstackservicechecks_disable_check_masakari(self):
        """Verify masakari is disabled."""
        filename = "/etc/nagios/nrpe.d/check_masakari_segment_host.cfg"
        model.set_application_config(self.application_name, {"check-masakari": "false"})
        model.block_until_all_units_idle()
        cmd = "cat {}".format(filename)
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertTrue(result.get("Code") != 0)

        model.set_application_config(self.application_name, {"check-masakari": "true"})
        model.block_until_all_units_idle()
        result = model.run_on_unit(self.lead_unit_name, cmd)
        content = result.get("Stdout")
        self.assertTrue(result.get("Code") == 0)
        self.assertTrue(len(content) > 0)

    def test_08_openstackservicechecks_resources_check(self):
        """Test run resource check."""
        cmd = "/usr/local/lib/nagios/plugins/check_resources.py --all server"
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertIn("OK:  servers", result.get("Stdout", ""))

    def test_09_openstackservicechecks_configuration_resources_check(self):
        """Verify the functionality of the resource check configuration."""
        exp_command = (
            "command[check_servers]=/usr/local/lib/nagios/plugins/check_resources.py "
            "server"
        )
        cmd = "cat /etc/nagios/nrpe.d/check_servers.cfg"

        # test configuration without change
        result = model.run_on_unit(self.lead_unit_name, cmd)
        assert "{} --all".format(exp_command) in result.get("Stdout", "")

        # test wrong configuration
        model.set_application_config(self.application_name, {"check-networks": "all"})
        model.block_until_unit_wl_status(self.units[0].name, "blocked")

        model.set_application_config(self.application_name, {"check-networks": ""})
        model.block_until_all_units_idle()

        # test valid configuration
        model.set_application_config(self.application_name, {"check-servers": "1,2"})

        # model.block_until_all_units_idle fire too quick before config change
        # So we sleep a while wait for application react.
        time.sleep(10)
        model.block_until_all_units_idle()

        result = model.run_on_unit(self.lead_unit_name, cmd)
        assert "{} --id 1 --id 2".format(exp_command) in result.get("Stdout", "")

        model.set_application_config(self.application_name, {"check-servers": "all"})
        model.block_until_all_units_idle()

    def test_10_openstackservicechecks_check_horizon(self):
        """Verify horizon check is disabled/enabled as configured."""
        filename = "/etc/nagios/nrpe.d/check_horizon.cfg"
        model.set_application_config(self.application_name, {"check-horizon": "false"})
        model.block_until_all_units_idle()
        cmd = "cat {}".format(filename)
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertTrue(result.get("Code") != 0)

        model.set_application_config(self.application_name, {"check-horizon": "true"})
        model.block_until_all_units_idle()
        result = model.run_on_unit(self.lead_unit_name, cmd)
        content = result.get("Stdout")
        self.assertTrue(result.get("Code") == 0)
        self.assertTrue(len(content) > 0)

    def test_11_prometheus_check_mysql_innodb_cluster(self):
        """Verify mysql innodb cluster status."""
        model.block_until_all_units_idle()
        # Skip test if applications not exists.
        try:
            model.get_application("mysql-innodb-cluster")
            model.get_application("prometheus2")
        except KeyError:
            raise unittest.SkipTest(
                "Application mysql-innodb-cluster or prometheus2 not exists"
            )
        filename = "/etc/nagios/nrpe.d/check_mysql_innodb_cluster.cfg"
        cmd = "cat {}".format(filename)
        result = model.run_on_unit(self.lead_unit_name, cmd)
        logging.info(result)

        self.assertEquals(result.get("Code"), 0)

    def test_99_openstackservicechecks_invalid_keystone_workload_status(self):
        """Verify keystone workload status.

        notes::
          This test should always be the last test.
          It will break the keystone unit,
          and you will need to run `juju resolve` to fix it.
        """
        lead_keystone = model.get_lead_unit_name("keystone", model_name=self.model_name)
        kst_cfg = model.get_application_config("keystone")
        default_port = kst_cfg["service-port"].get("value") or kst_cfg[
            "service-port"
        ].get("default")
        new_svc_port = int(default_port) + 1
        model.block_until_all_units_idle()
        model.set_application_config("keystone", {"service-port": str(new_svc_port)})

        model.run_action(lead_keystone, "pause")

        ks_unit = model.get_units("keystone", model_name=self.model_name)[0]

        model.block_until_unit_wl_status(ks_unit.name, "maintenance")
        model.block_until_unit_wl_status(self.units[0].name, "blocked")
        machine = model.get_machines(self.application_name)[0]
        model.block_until_units_on_machine_are_idle(machine.entity_id)

        expected_msg = (
            "Keystone server error was encountered trying to list keystone "
            "resources. Check keystone server health. View juju logs for "
            "more info."
        )
        osc_unit = model.get_units(
            "openstack-service-checks", model_name=self.model_name
        )[0]
        status_msg = osc_unit.workload_status_message
        model.run_action(lead_keystone, "resume")
        model.set_application_config("keystone", {"service-port": str(default_port)})
        assert status_msg == expected_msg


class TestOpenStackServiceChecksCinder(TestBase):
    """Test OpenStack service checks for cinder."""

    def test_01_openstack_check_cinder_service(self):
        """Verify cinder service."""
        model.block_until_all_units_idle()
        cmd = "python3 /usr/local/lib/nagios/plugins/check_cinder_services.py"
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertEquals(result.get("Code"), 0)  # Get response from cinder
