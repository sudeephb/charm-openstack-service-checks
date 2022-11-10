"""Helper library for openstack-service-checks charm."""

import collections
import configparser
import glob
import os
import pwd
import re
import subprocess
from urllib.parse import urlparse


from charmhelpers import fetch
from charmhelpers.contrib.charmsupport.nrpe import NRPE
from charmhelpers.contrib.openstack.utils import config_flags_parser
from charmhelpers.core import hookenv, host, unitdata
from charmhelpers.core.templating import render

from charms.reactive import any_file_changed, endpoint_from_name

import keystoneauth1

from keystoneclient import session

# `requests` relies on package `certifi` to find ca certs.
# certifi deb package will return `/etc/ssl/certs/ca-certificates.crt` as expected,
# while its python package will return its builtin `cacert.pem`, which is
# Mozilla Root Certificates.
# when charm runs in venv, cetifi python package will be installed.
# So when we use self-signed certs (e.g: form vault) to verify, even if
# we included it in `/etc/ssl/certs/ca-certificates.crt`, it will be ignored
# by requests and cause [SSL: CERTIFICATE_VERIFY_FAILED] error.
# ref: LP#1924816
# this envvar will ensure requests to use system bundle for ssl verify
# instead of `certifi/cacert.pem`
os.environ["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
# NOTE (rgildein): If there is any change in this list or the list below, it is
# necessary to modify RESOURCES and RESOURCES_BY_EXISTENCE in
# files.plugins.check_resources
RESOURCES_CHECKS_BY_EXISTENCE = ["security-group", "subnet", "network"]
RESOURCES_CHECKS_WITH_STATUS = ["server", "floating-ip", "port"]


class OSCCredentialsError(Exception):
    """Define OSCCredentialError exception."""

    pass


class OSCKeystoneError(Exception):
    """Define OSCKeystoneError exception."""

    @property
    def workload_status(self):
        """Implement workload_status method from Exception class."""
        raise NotImplementedError


class OSCKeystoneServerError(OSCKeystoneError):
    """Define OSCKeystoneServerError exception."""

    @property
    def workload_status(self):
        """Implement workload_status method from Exception class."""
        return (
            "Keystone server error was encountered trying to list keystone "
            "resources. Check keystone server health. "
            "View juju logs for more info."
        )


class OSCKeystoneClientError(OSCKeystoneError):
    """Define OSCKeystoneClientError exception."""

    @property
    def workload_status(self):
        """Implement workload_status method from Exception class."""
        return (
            "Keystone client request error was encountered trying to "
            "keystone resources. Check keystone auth creds and url."
            "View juju logs for more info."
        )


class OSCSslError(OSCKeystoneError):
    """Define OSCSslError exception."""

    @property
    def workload_status(self):
        """Implement workload_status method from Exception class."""
        return (
            "SSL error was encountered when requesting Keystone for "
            "resource list.  Check trusted_ssl_ca config option. "
            "View juju logs for more info."
        )


class OSCConfigError(Exception):
    """Define OSCConfigError exception."""

    def __init__(self, message):
        """Set message used in workload_status."""
        self.message = message

    @property
    def workload_status(self):
        """Implement workload_status method from Exception class."""
        return self.message


class OSCHelper:
    """Define OSCHelper object."""

    def __init__(self):
        """Initialize charm configs and null keystone client into Helper object."""
        self.charm_config = hookenv.config()
        self._keystone_client = None

    def store_keystone_credentials(self, creds):
        """Store keystone credentials."""
        kv = unitdata.kv()
        kv.set("keystonecreds", creds)
        kv.set("rallyinstalled", False)

    @property
    def novarc(self):
        """Define path to novarc config file for checks."""
        return "/var/lib/nagios/nagios.novarc"

    @property
    def contrail_analytics_vip(self):
        """Expose the contrail_analytics_vip charm config value."""
        return self.charm_config["contrail_analytics_vip"]

    @property
    def contrail_ignored(self):
        return self.charm_config["contrail_ignored_alarms"]

    @property
    def plugins_dir(self):
        return "/usr/local/lib/nagios/plugins/"

    @property
    def scripts_dir(self):
        return "/usr/local/bin/"

    @property
    def rally_cron_file(self):
        return "/etc/cron.d/osc_rally"

    @property
    def is_rally_enabled(self):
        return self.charm_config["check-rally"]

    @property
    def is_neutron_agents_check_enabled(self):
        return self.charm_config["check-neutron-agents"]

    @property
    def is_masakari_check_enabled(self):
        return self.charm_config["check-masakari"]

    @property
    def is_octavia_check_enabled(self):
        return self.charm_config["check-octavia"]

    @property
    def octavia_amp_image_tag(self):
        return self.charm_config["octavia-amp-image-tag"]

    @property
    def octavia_amp_image_days(self):
        return self.charm_config["octavia-amp-image-days"]

    @property
    def skipped_rally_checks(self):
        skipped_os_components = self.charm_config["skip-rally"].strip()
        if not skipped_os_components:
            return []

        # filter skip-rally input to match available (or supported) components that
        # should be disabled
        available_os_components = "cinder glance nova neutron".split()
        return [
            comp.strip().lower()
            for comp in skipped_os_components.split(",")
            if comp.strip().lower() in available_os_components
        ]

    @property
    def rally_cron_schedule(self):
        schedule = self.charm_config["rally-cron-schedule"]
        if schedule.strip() == "" or len(schedule.strip().split()) != 5:
            return "*/15 * * * *"
        else:
            return schedule.strip()

    def get_os_credentials(self):
        ident_creds = config_flags_parser(self.charm_config["os-credentials"])
        if not ident_creds.get("auth_url"):
            raise OSCCredentialsError("auth_url")
        elif "/v3" in ident_creds.get("auth_url"):
            extra_attrs = ["domain"]
            creds = {"auth_version": 3}
        else:
            extra_attrs = []
            creds = {}

        common_attrs = (
            "username password region_name auth_url"
            " credentials_project volume_api_version"
        ).split()
        all_attrs = common_attrs + extra_attrs
        missing = [k for k in all_attrs if k not in ident_creds]
        if missing:
            raise OSCCredentialsError(", ".join(missing))

        ident_creds["auth_url"] = ident_creds["auth_url"].strip("\"'")
        creds.update(
            dict(
                [
                    (k, ident_creds.get(k))
                    for k in all_attrs
                    if k not in ("credentials_project", "domain")
                ]
            )
        )
        if extra_attrs:
            creds.update(
                {
                    "project_name": ident_creds["credentials_project"],
                    "user_domain_name": ident_creds["domain"],
                    "project_domain_name": ident_creds["domain"],
                }
            )
        else:
            creds["tenant_name"] = ident_creds["credentials_project"]

        return creds

    def get_keystone_credentials(self):
        """Retrieve keystone credentials from either config or relation data.

        If config 'os-crendentials' is set, return that info otherwise look
        for a keystonecreds relation data'

        :return: dict of credential information for keystone
        """
        return unitdata.kv().get("keystonecreds")

    @property
    def nova_warn(self):
        return self.charm_config.get("nova_warn")

    @property
    def nova_crit(self):
        return self.charm_config.get("nova_crit")

    @property
    def nova_skip_aggregates(self):
        skipped_aggregates = self.charm_config.get("skipped_host_aggregates")
        # We have to make sure there are no malicious injections in the code
        # as this gets passed to a python script via bash
        regex = r"([\w_-]+(?:,[\w_-]+)*)"
        sanitized = ",".join(re.findall(regex, skipped_aggregates))
        sanitized = [s for s in sanitized.split(",") if s != ""]
        sanitized = ",".join(sanitized)
        return sanitized

    @property
    def skip_disabled(self):
        if self.charm_config.get("skip-disabled"):
            return "--skip-disabled"
        else:
            return ""

    @property
    def check_dns(self):
        return self.charm_config.get("check-dns")

    @property
    def check_allocations(self):
        return self.charm_config.get("check-allocations")

    @property
    def check_mysql_innodb_cluster(self):
        return self.charm_config.get("check-mysql-innodb-cluster")

    def update_plugins(self):
        charm_plugin_dir = os.path.join(hookenv.charm_dir(), "files", "plugins/")
        host.rsync(charm_plugin_dir, self.plugins_dir, options=["--executability"])

    def _render_nova_checks(self, nrpe):
        """Nova services health."""
        nova_check_command = os.path.join(self.plugins_dir, "check_nova_services.py")
        check_command = "{} --warn {} --crit {} --skip-aggregates {} {}".format(
            nova_check_command,
            self.nova_warn,
            self.nova_crit,
            self.nova_skip_aggregates,
            self.skip_disabled,
        ).strip()
        nrpe.add_check(
            shortname="nova_services",
            description="Check that enabled Nova services are up",
            check_cmd=check_command,
        )

    def _render_neutron_checks(self, nrpe):
        """Neutron agents health."""
        if self.is_neutron_agents_check_enabled:
            nrpe.add_check(
                shortname="neutron_agents",
                description="Check that enabled Neutron agents are up",
                check_cmd=os.path.join(self.plugins_dir, "check_neutron_agents.sh"),
            )
        else:
            nrpe.remove_check(shortname="neutron_agents")

    def _render_port_security_checks(self, nrpe):
        """Port security health."""
        shortname = "port_security"
        check_script = os.path.join(self.plugins_dir, "check_port_security.py")
        cron_file = "/etc/cron.d/osc_{}".format(shortname)
        if self.charm_config["check-port-security"]:
            nrpe.add_check(
                shortname=shortname,
                check_cmd=check_script,
                description="Check port security",
            )
            # add cron file to run auto remediation
            # cron job must run as frequent as possible, which is 1 min
            # max age depends on cron interval, make it slightly bigger than 1 min
            cron_cmd = "{} --auto-remediation --max-age 90".format(check_script)
            email_recipients = self.charm_config["email_recipients"]
            if email_recipients:
                cron_cmd += " --email-recipients {}".format(email_recipients)
            email_from_addr = self.charm_config["email_from_addr"]
            if email_from_addr:
                cron_cmd += " --email-from-addr {}".format(email_from_addr)
            cron_line = "* * * * * nagios {}".format(cron_cmd)
            with open(cron_file, "w") as fd:
                fd.write("# Juju generated - DO NOT EDIT\n{}\n\n".format(cron_line))
        else:
            nrpe.remove_check(shortname=shortname)
            # remove cron file
            try:
                os.remove(cron_file)
            except OSError:
                pass

    def _render_masakari_checks(self, nrpe):
        """Masakari segment host maintenance check."""
        if self.is_masakari_check_enabled:
            nrpe.add_check(
                shortname="masakari_segment_host",
                description="Check masakari segment hosts are not on maintenance",
                check_cmd=os.path.join(self.plugins_dir, "check_masakari.py"),
            )
        else:
            nrpe.remove_check(shortname="masakari_segment_host")

    def _render_cinder_checks(self, nrpe):
        # Cinder services health
        cinder_check_command = os.path.join(
            self.plugins_dir, "check_cinder_services.py"
        )
        check_command = "{} {}".format(cinder_check_command, self.skip_disabled)
        nrpe.add_check(
            shortname="cinder_services",
            description="Check that enabled Cinder services are up",
            check_cmd=check_command,
        )

    def _remove_octavia_checks(self, nrpe):
        for check in ("loadbalancers", "pools", "image"):
            nrpe.remove_check(shortname="octavia_{}".format(check))

    def _render_octavia_checks(self, nrpe):
        # only care about octavia after 18.04
        if host.lsb_release()["DISTRIB_RELEASE"] < "18.04":
            return

        # if its not enabled in config, remove checks
        if not self.is_octavia_check_enabled:
            self._remove_octavia_checks(nrpe)
            return

        # if its not listed as an endpoint, remove checks
        if "octavia" not in self.endpoint_service_names.values():
            self._remove_octavia_checks(nrpe)
            return

        # else, render the octavia service-specific checks
        fetch.apt_install(["python3-octaviaclient"], fatal=True)
        script = os.path.join(self.plugins_dir, "check_octavia.py")

        for check in ("loadbalancers", "pools", "image"):
            check_cmd = "{} --check {}".format(script, check)
            if check == "image":
                check_cmd += " --amp-image-tag {}".format(self.octavia_amp_image_tag)
                check_cmd += " --amp-image-days {}".format(self.octavia_amp_image_days)
            ignore = self.charm_config.get("octavia-%s-ignored" % check)
            if ignore:
                check_cmd += " --ignored {}".format(ignore)
            nrpe.add_check(
                shortname="octavia_{}".format(check),
                description="Check octavia {} status".format(check),
                check_cmd=check_cmd,
            )

    def _render_contrail_checks(self, nrpe):
        if self.contrail_analytics_vip:
            contrail_check_command = "{} --host {}".format(
                os.path.join(self.plugins_dir, "check_contrail_analytics_alarms.py"),
                self.contrail_analytics_vip,
            )
            if self.contrail_ignored:
                contrail_check_command += " --ignored {}".format(self.contrail_ignored)
            nrpe.add_check(
                shortname="contrail_analytics_alarms",
                description="Check Contrail Analytics alarms",
                check_cmd=contrail_check_command,
            )
        else:
            nrpe.remove_check(shortname="contrail_analytics_alarms")

    def _render_dns_checks(self, nrpe):
        if len(self.check_dns):
            nrpe.add_check(
                shortname="dns_multi",
                description="Check DNS names are resolvable",
                check_cmd="{} {}".format(
                    os.path.join(self.plugins_dir, "check_dns_multi.sh"),
                    " ".join(self.check_dns.split()),
                ),
            )
        else:
            nrpe.remove_check(shortname="dns_multi")

    def _remove_mysql_innodb_cluster_checks(self, nrpe):
        shortname = "mysql_innodb_cluster"
        nrpe.remove_check(shortname=shortname)

    def _render_mysql_innodb_cluster_checks(self, nrpe):
        shortname = "mysql_innodb_cluster"

        endpoint = endpoint_from_name("prometheus")

        if (
            len(endpoint.services()) == 0
            or not endpoint
            or not self.check_mysql_innodb_cluster
        ):
            self._remove_mysql_innodb_cluster_checks(nrpe)
            return

        check_script = os.path.join(
            self.plugins_dir,
            "check_mysql_innodb_cluster.py",
        )

        host_info = endpoint.services()[0]["hosts"][0]
        address = "http://{}:{}".format(host_info["hostname"], host_info["port"])
        check_script += " --address {}".format(address)

        nrpe.add_check(
            shortname=shortname,
            check_cmd=check_script,
            description="Check mysql innodb cluster health",
        )

    def _remove_allocation_checks(self, nrpe, shortname, cron_file):
        nrpe.remove_check(shortname=shortname)
        # remove cron file
        try:
            os.remove(cron_file)
        except OSError:
            pass

    def _render_allocation_checks(self, nrpe):
        shortname = "allocations"
        check_script = os.path.join(self.plugins_dir, "check_allocations.py")
        cron_file = "/etc/cron.d/osc_{}".format(shortname)

        distrib_release = host.lsb_release()["DISTRIB_RELEASE"]
        if distrib_release < "20.04":
            hookenv.log(
                "allocations check does not support on {}".format(
                    distrib_release,
                    hookenv.WARNING,
                )
            )
            self._remove_allocation_checks(nrpe, shortname, cron_file)
            return

        if not self.check_allocations:
            self._remove_allocation_checks(nrpe, shortname, cron_file)
            return

        if "placement" not in self.endpoint_service_names.values():
            self._remove_allocation_checks(nrpe, shortname, cron_file)
            return

        nrpe.add_check(
            shortname=shortname,
            check_cmd=check_script,
            description="Check Nova/placement allocations status",
        )

        # NOTE: the actual check runs in cron to prevent NRPE timeouts on larger clouds
        cron_script = os.path.join(
            hookenv.charm_dir(), "files", "run_allocation_checks.py"
        )
        host.rsync(cron_script, self.scripts_dir, options=["--executability"])

        cron_cmd = os.path.join(self.scripts_dir, "run_allocation_checks.py")

        ignored = self.charm_config.get("allocations-instances-ignored")
        if ignored:
            cron_cmd += " --ignored {}".format(ignored)

        cron_line = "*/5 * * * * nagios {}".format(cron_cmd)
        with open(cron_file, "w") as fd:
            fd.write("# Juju generated - DO NOT EDIT\n{}\n\n".format(cron_line))

    def _get_resource_ids(self, name):
        """Get list of ids separated by comma from config option."""
        ids = self.charm_config.get(name, "").split(",")
        return [id_.strip() for id_ in ids if id_]

    def _get_resource_check_kwargs(self, resource, ids, skip_ids=None):
        """Generate shortname, CMD and description for check.

        :param resource: type of resource
        :type resource: str
        :param ids: list of IDs/`all`
        :type ids: List[str]
        :param skip_ids: list of IDs to be skipped
        :type skip_ids: Optional[List[str]]
        """
        skip_ids = skip_ids or []
        check_script = os.path.join(self.plugins_dir, "check_resources.py")
        cmd = "{} {}".format(check_script, resource)

        if "all" in ids:
            cmd += " --all"
            cmd += "".join([" --skip-id {}".format(id_) for id_ in skip_ids])
        else:
            cmd += "".join([" --id {}".format(id_) for id_ in ids])

        description = "Check {}s: {}".format(resource, ",".join(ids))
        description += " (skips: {})".format(",".join(skip_ids))

        return {
            "shortname": "{}s".format(resource.replace("-", "_")),
            "check_cmd": cmd,
            "description": description,
        }

    def _render_resource_check_by_existence(self, nrpe, resource):
        """Render NRPE check for OpenStack resource."""
        ids = self._get_resource_ids("check-{}s".format(resource))
        if "all" in ids:
            raise OSCConfigError(
                "check-{}s does not support value " "`all`".format(resource)
            )

        check_kwargs = self._get_resource_check_kwargs(resource, ids)
        if self.charm_config.get("check-{}s".format(resource)):
            nrpe.add_check(**check_kwargs)
            hookenv.log(
                "Added nrpe check {shortname}: {check_cmd}".format(**check_kwargs)
            )
        else:
            nrpe.remove_check(**check_kwargs)
            hookenv.log(
                "Removed nrpe check {shortname}: {check_cmd}".format(**check_kwargs)
            )

    def _render_resources_check_by_status(self, nrpe, resource):
        """Render NRPE check for OpenStack resource."""
        ids = self._get_resource_ids("check-{}s".format(resource))
        skip_ids = self._get_resource_ids("skip-{}s".format(resource))
        if "all" not in ids and skip_ids:
            hookenv.log("skip-{}s will be omitted".format(resource), hookenv.WARNING)

        check_kwargs = self._get_resource_check_kwargs(resource, ids, skip_ids)
        if self.charm_config.get("check-{}s".format(resource)):
            nrpe.add_check(**check_kwargs)
            hookenv.log(
                "Added nrpe check {shortname}: {check_cmd}".format(**check_kwargs)
            )
        else:
            nrpe.remove_check(**check_kwargs)
            hookenv.log(
                "Removed nrpe check {shortname}: {check_cmd}".format(**check_kwargs)
            )

    def render_horizon_checks(self, horizon_ip):
        """Render nrpe check for connectivity and login to horizon."""
        nrpe = NRPE()
        nrpe.add_check(
            shortname="horizon",
            description="Check connectivity and login",
            check_cmd=os.path.join(self.plugins_dir, "check_horizon.py")
            + f" --ip {horizon_ip}",  # noqa: W503
        )
        nrpe.write()

    def remove_horizon_checks(self):
        nrpe = NRPE()
        hookenv.log("Removing horizon checks")
        nrpe.remove_check(shortname="horizon")
        nrpe.write()

    def render_checks(self, creds):
        render(
            source="nagios.novarc",
            target=self.novarc,
            context=creds,
            owner="nagios",
            group="nagios",
        )

        nrpe = NRPE()
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)

        self.update_plugins()

        # Initialize the keystone client for property use in render methods
        self.get_keystone_client(creds)

        self._render_nova_checks(nrpe)
        self._render_neutron_checks(nrpe)
        self._render_port_security_checks(nrpe)
        self._render_cinder_checks(nrpe)
        self._render_octavia_checks(nrpe)
        self._render_contrail_checks(nrpe)
        self._render_dns_checks(nrpe)
        self._render_masakari_checks(nrpe)
        self._render_allocation_checks(nrpe)
        self._render_mysql_innodb_cluster_checks(nrpe)

        # render resource checks that are checked by existence
        for resource in RESOURCES_CHECKS_BY_EXISTENCE:
            self._render_resource_check_by_existence(nrpe, resource)

        # render resource checks that are checked by their status
        for resource in RESOURCES_CHECKS_WITH_STATUS:
            self._render_resources_check_by_status(nrpe, resource)

        nrpe.write()
        self.create_endpoint_checks()

    def _split_url(self, netloc, scheme):
        """Split URL and return host and port tuple.

        http(s)://host:port or http(s)://host will return a host and a port

        Even if a port is not specified, this helper will return a host and a port
        (guessing it from the protocol used, if needed)

        :param netloc: network location part as returned by urllib.urlparse
        :type netloc: str
        :param scheme: URL scheme specifier as returned by urllib.urlparse
        :returns: str
        :rtype: Tuple[str, str]
        """
        if netloc.find(":") == -1:
            # no port specified
            host = netloc
            port = 80 if scheme == "http" else 443
        else:
            host, port = netloc.split(":")

        return host, port

    def _render_http_endpoint_checks(self, url, host, port, nrpe, interface, **kwargs):
        """Render NRPE checks for http endpoint."""
        if self.charm_config.get("check_{}_urls".format(interface)):
            command = "{} -H {} -p {} -u {}".format(
                "/usr/lib/nagios/plugins/check_http", host, port, url
            )
            nrpe.add_check(
                shortname=kwargs.get("shortname", "check_http"),
                description=kwargs.get(
                    "description", "Added nrpe check for http endpoint."
                ),
                check_cmd=command,
            )
            hookenv.log(kwargs.get("create_log", "Added nrpe check for http endpoint"))
        else:
            nrpe.remove_check(shortname=kwargs.get("shortname", "check_http"))
            hookenv.log(
                kwargs.get("remove_log", "Removed nrpe check for http endpoint")
            )

    def _render_https_endpoint_checks(self, url, host, port, nrpe, interface, **kwargs):
        """Render NRPE checks for https endpoint and its certificate chain."""
        if self.charm_config.get("check_{}_urls".format(interface)):
            command = "{} -H {} -p {} -u {} -c {} -w {}".format(
                os.path.join(self.plugins_dir, "check_ssl_cert"),
                host,
                port,
                url,
                self.charm_config.get("tls_crit_days", 14),
                self.charm_config.get("tls_warn_days", 30),
            )
            nrpe.add_check(
                shortname=kwargs.get("shortname", "check_ssl_cert"),
                description=kwargs.get(
                    "description", "Added nrpe check for https endpoint."
                ),
                check_cmd=command,
            )
            hookenv.log(kwargs.get("create_log", "Added nrpe check for https endpoint"))
        else:
            nrpe.remove_check(shortname=kwargs.get("shortname", "check_ssl_cert"))
            hookenv.log(
                kwargs.get("remove_log", "Removed nrpe check for https endpoint")
            )

    def _normalize_endpoint_attr(self, endpoint):
        """Normalize the attributes in service catalog endpoint between v2 and v3."""
        for v3_interface in ["admin", "internal", "public"]:
            v2_interface_url_name = "{}url".format(v3_interface)
            if not hasattr(endpoint, v2_interface_url_name):
                continue
            return v3_interface, getattr(endpoint, v2_interface_url_name)

    def create_endpoint_checks(self, creds=None):
        """
        Create an NRPE check for each Keystone catalog endpoint.

        Read the Keystone catalog, and create a check for each endpoint listed.
        If there is a healthcheck endpoint for the API, use that URL, otherwise check
        the url '/'.
        If SSL, add a check for the cert.

        v2 endpoint needs the 'interface' attribute:
        <Endpoint {'id': 'XXXXX', 'region': 'RegionOne',
        'publicurl': 'http://10.x.x.x:9696', 'service_id': 'YYY',
        'internalurl': 'http://10.x.x.x:9696', 'enabled': True,
        'adminurl': 'http://10.x.x.x:9696'}>
        """
        # provide URLs that can be used for healthcheck for some services
        # This also provides a nasty hack-ish way to add switches if we need
        # for some services.
        health_check_params = {
            "aodh": "/healthcheck",
            "barbican": "/v1 -e Unauthorized",
            "ceilometer": "/ -e Unauthorized -d x-openstack-request-id",
            "cinderv1": "/v1 -e Unauthorized -d x-openstack-request-id",
            "cinderv2": "/v2 -e Unauthorized",
            "cinderv3": "/v3 -e Unauthorized -d x-openstack-request-id",
            "designate": "/v2 -e Unauthorized",
            "glance": "/healthcheck",
            "gnocchi": "/v1 -e Unauthorized",
            "heat": "/v1 -e Unauthorized",
            "keystone": "/healthcheck",
            "nova": "/healthcheck",
            "octavia": "/v2 -e Unauthorized",
            "placement": "/healthcheck -e Unauthorized -d x-openstack-request-id",
            "s3": self.charm_config.get("s3_check_params", "/"),
            "swift": self.charm_config.get("swift_check_params", "/"),
        }

        self.get_keystone_client(creds)
        nrpe = NRPE()

        for endpoint in self.keystone_endpoints:
            service_name = self.endpoint_service_names[endpoint.id]
            endpoint.healthcheck_url = health_check_params.get(service_name, "/")

            # Note(aluria): glance-simplestreams-sync does not provide an API to check
            if service_name == "image-stream":
                continue

            if not hasattr(endpoint, "interface"):
                # Note(aluria): filter:healthcheck is not configured in Keystone v2
                # https://docs.openstack.org/keystone/pike/configuration.html#health-check-middleware
                if service_name == "keystone":
                    continue
                endpoint.interface, endpoint.url = self._normalize_endpoint_attr(
                    endpoint
                )

            check_url = urlparse(endpoint.url)
            host, port = self._split_url(check_url.netloc, check_url.scheme)

            nrpe_shortname = "{}_{}".format(service_name, endpoint.interface)
            self._render_http_endpoint_checks(
                url=endpoint.healthcheck_url,
                host=host,
                port=port,
                nrpe=nrpe,
                interface=endpoint.interface,
                shortname=nrpe_shortname,
                description="Endpoint url check for {} {}".format(
                    service_name, endpoint.interface
                ),
                create_log="Added nrpe http endpoint check for {}, {}".format(
                    service_name, endpoint.interface
                ),
                remove_log="Removed nrpe http endpoint check for {}, {}".format(
                    service_name, endpoint.interface
                ),
            )

            if check_url.scheme == "https":
                url = endpoint.healthcheck_url.strip().split(" ")[0]
                nrpe_shortname = "{}_{}_cert".format(service_name, endpoint.interface)
                self._render_https_endpoint_checks(
                    url=url,
                    host=host,
                    port=port,
                    nrpe=nrpe,
                    shortname=nrpe_shortname,
                    interface=endpoint.interface,
                    description="Certificate expiry check for {} {}".format(
                        service_name, endpoint.interface
                    ),
                    create_log="Added nrpe cert expiry check for: {}, {}".format(
                        service_name, endpoint.interface
                    ),
                    remove_log="Removed nrpe cert expiry check for: {}, {}".format(
                        service_name, endpoint.interface
                    ),
                )

        nrpe.write()

    def get_keystone_client(self, creds):
        """Import the appropriate Keystone client depending on API version.

        Use credential info to determine the Keystone API version, and make a
        client session object that is to be used for authenticated
        communication with Keystone.

        :returns: a keystoneclient Client object
        """
        # Skip creating a keystone client if one is already initialized
        if self._keystone_client is not None:
            return

        # don't try to initialize a client without credentials
        if creds is None:
            raise OSCKeystoneServerError(
                "Unable to list the endpoints yet: no credentials provided."
            )

        if int(creds.get("auth_version", 0)) >= 3:
            from keystoneclient.v3 import client
            from keystoneclient.auth.identity import v3 as kst_version

            auth_fields = (
                "username password auth_url user_domain_name "
                "project_domain_name project_name"
            ).split()
        else:
            from keystoneclient.v2_0 import client
            from keystoneclient.auth.identity import v2 as kst_version

            auth_fields = "username password auth_url tenant_name".split()

        auth_creds = dict([(key, creds.get(key)) for key in auth_fields])
        auth = kst_version.Password(**auth_creds)
        sess = session.Session(auth=auth)
        self._keystone_client = client.Client(session=sess)

        if self._keystone_client is None:
            raise OSCKeystoneServerError(
                "Unable to list the endpoints yet: "
                "could not connect to the Identity Service"
            )

    @property
    def keystone_endpoints(self):
        endpoints = self._safe_keystone_client_list("endpoints")
        hookenv.log("Endpoints from keystone: {}".format(endpoints))
        return endpoints

    @property
    def keystone_services(self):
        services = self._safe_keystone_client_list("services")
        hookenv.log("Services from keystone: {}".format(services))
        return services

    @property
    def keystone_enabled_services(self):
        enabled_services = [svc for svc in self.keystone_services if svc.enabled]
        return enabled_services

    @property
    def endpoint_service_names(self):
        endpoint_service_names = dict()
        for endpoint in self.keystone_endpoints:
            for svc in self.keystone_enabled_services:
                if svc.id == endpoint.service_id:
                    endpoint_service_names[endpoint.id] = svc.name
                    continue
        return endpoint_service_names

    def _safe_keystone_client_list(self, object_type):
        list_command = getattr(self._keystone_client, object_type).list
        try:
            response = list_command()
        except (
            keystoneauth1.exceptions.http.InternalServerError,
            keystoneauth1.exceptions.connection.ConnectFailure,
        ) as server_error:
            raise OSCKeystoneServerError(
                "Keystone server unable to list keystone {}: {}".format(
                    server_error, object_type
                )
            )
        except keystoneauth1.exceptions.http.BadRequest as client_error:
            raise OSCKeystoneClientError(
                "Keystone client error when listing {}: {}".format(
                    client_error, object_type
                )
            )
        except keystoneauth1.exceptions.connection.SSLError as ssl_error:
            raise OSCSslError(
                "Keystone ssl error when listing {}: {}".format(ssl_error, object_type)
            )
        return response

    @property
    def _load_envvars(self, novarc="/var/lib/nagios/nagios.novarc"):
        if not os.path.exists(novarc):
            return False

        output = subprocess.check_output(
            ["/bin/bash", "-c", "source {} && env".format(novarc)]
        )
        i = 0
        for line in output.decode("utf-8").splitlines():
            if not line.startswith("OS_"):
                continue
            key, value = line.split("=")
            os.environ[key] = value
            i += 1

        return i >= 3

    def _run_as(self, user, user_cmd):
        try:
            pwd.getpwnam(user)
            # preserve envvars and run as `user`
            cmd = ["sudo", "-Eu", user]

            # convert command into a list
            if isinstance(user_cmd, str):
                # split string into arguments
                cmd.extend(user_cmd.split())
            elif isinstance(user_cmd, list):
                cmd.extend(user_cmd)
            else:
                hookenv.log(
                    "_run_as - can't run as user {} the command: {}".format(
                        user, user_cmd
                    )
                )
                return False

            subprocess.check_call(cmd)
            return True

        except KeyError as error:
            hookenv.log("_run_as - user does not exist => {}".format(str(error)))
            return False
        except subprocess.CalledProcessError as error:
            hookenv.log("_run_as - cmd failed => {}".format(str(error)))
            if error.stderr:
                hookenv.log("_run_as stderr => {}".format(error.stderr))
            if error.stdout:
                hookenv.log("_run_as stderr => {}".format(error.stdout))
            return False

    @property
    def _rallyuser(self):
        return "nagiososc"

    def install_rally(self):
        kv = unitdata.kv()
        if kv.get("rallyinstalled", False):
            return True

        if not self._load_envvars:
            hookenv.log("install_rally - could not load nagios.novarc")
            return False

        user = self._rallyuser
        host.adduser(user)
        host.mkdir(
            os.path.join("/home", user),
            owner=user,
            group=user,
            perms=0o755,
            force=False,
        )

        for tool in ["rally", "tempest"]:
            toolname = "fcbtest.{}init".format(tool)
            installed = self._run_as(user, [toolname])
            if not installed:
                hookenv.log("install_rally - could not initialize {}".format(tool))
                return False

        kv.set("rallyinstalled", True)
        return True

    def _regenerate_tempest_conf(self, tempestfile):
        config = configparser.ConfigParser()
        config.read(tempestfile)
        for section in config.keys():
            for key, value in config[section].items():
                try:
                    if section != "DEFAULT" and key in config["DEFAULT"].keys():
                        # avoid copying the DEFAULT config options to remaining sections
                        continue
                except KeyError:
                    # DEFAULT section does not exist
                    pass

                # Enable Cinder, which is a default OpenStack service
                if section == "service_available" and key == "cinder":
                    config[section][key] = "True"

        with open(tempestfile, "w") as fd:
            config.write(fd)

    def reconfigure_tempest(self):
        """Enable cinder tests.

        Expects an external network already configured

        Sample:
        RALLY_VERIFIER=7b9d06ef-e651-4da3-a56b-ecac67c595c5
        RALLY_VERIFICATION=4a730963-083f-4e1e-8c55-f2b4b9c9c0ac
        RALLY_DEPLOYMENT=a75657c6-9eea-4f00-9117-2580fe056a80
        RALLY_ENV=a75657c6-9eea-4f00-9117-2580fe056a80
        """
        rally_conf = ["/home", self._rallyuser, "snap", "fcbtest", "current", ".rally"]
        rally_globalconfig = os.path.join(*rally_conf, "globals")
        if not os.path.isfile(rally_globalconfig):
            return False

        uuids = collections.defaultdict(lambda: "*")
        with open(rally_globalconfig, "r") as fd:
            for line in fd.readlines():
                key, value = line.strip().split("=")
                if key in ["RALLY_VERIFIER", "RALLY_DEPLOYMENT"]:
                    uuids[key] = value

        tempest_path = os.path.join(
            *rally_conf,
            "verification",
            "verifier-{RALLY_VERIFIER}".format(**uuids),
            "for-deployment-{RALLY_DEPLOYMENT}".format(**uuids),
            "tempest.conf",
        )
        tempestfile = glob.glob(tempest_path)
        if len(tempestfile) == 0:
            # No tempest.conf file generated, yet
            return False

        if not any_file_changed([tempestfile[0]]):
            return False

        self._regenerate_tempest_conf(tempestfile[0])
        return True

    def _get_rally_checks_context(self):
        os_components_skip_list = self.skipped_rally_checks
        ctxt = {}
        for comp in "cinder glance nova neutron".split():
            ctxt.update({comp: comp not in os_components_skip_list})
        return ctxt

    def update_rally_checkfiles(self):
        if not self.is_rally_enabled:
            return

        # Copy run_rally.sh to /usr/local/bin
        rally_script = os.path.join(hookenv.charm_dir(), "files", "run_rally.py")
        host.rsync(rally_script, self.scripts_dir, options=["--executability"])

        ostestsfile = os.path.join("/home", self._rallyuser, "ostests.txt")
        render(
            source="ostests.txt.j2",
            target=ostestsfile,
            context=self._get_rally_checks_context(),
            owner=self._rallyuser,
            group=self._rallyuser,
        )

        proxy_settings = hookenv.env_proxy_settings()
        if proxy_settings:
            content = "\n".join(
                [
                    "{}={}".format(proxy_var, proxy_var_val)
                    for proxy_var, proxy_var_val in proxy_settings.items()
                ]
            )
        else:
            content = ""

        context = {
            "schedule": self.rally_cron_schedule,
            "user": self._rallyuser,
            "cmd": os.path.join(self.scripts_dir, "run_rally.py"),
        }
        content += (
            "\n#\n{schedule} {user} timeout -k 840s -s SIGTERM 780s {cmd}".format(
                **context
            )
        )
        with open(self.rally_cron_file, "w") as fd:
            fd.write("# Juju generated - DO NOT EDIT\n{}\n\n".format(content))

    def configure_rally_check(self):
        kv = unitdata.kv()
        if kv.get("rallyconfigured", False):
            return

        self.update_rally_checkfiles()
        rally_check = os.path.join(self.plugins_dir, "check_rally.py")
        nrpe = NRPE()
        nrpe.add_check(
            shortname="rally",
            description="Check that all rally tests pass",
            check_cmd=rally_check,
        )
        nrpe.write()
        kv.set("rallyconfigured", True)

    def remove_rally_check(self):
        filename = self.rally_cron_file
        if os.path.exists(filename):
            os.unlink(filename)

        if os.path.exists("/etc/nagios/nrpe.d/check_rally.cfg"):
            nrpe = NRPE()
            nrpe.remove_check(shortname="rally")
            nrpe.write()

    def deploy_rally(self):
        if self.is_rally_enabled:
            installed = self.install_rally()
            if not installed:
                return False
            self.configure_rally_check()
        else:
            self.remove_rally_check()
            unitdata.kv().set("rallyconfigured", False)
        return True
