import collections
import glob
import os
import pwd
import re
import subprocess
from urllib.parse import urlparse

import configparser

from charmhelpers.core.templating import render
from charmhelpers.contrib.openstack.utils import config_flags_parser
from charmhelpers.core import hookenv, host, unitdata
from charmhelpers.contrib.charmsupport.nrpe import NRPE
from charms.reactive import any_file_changed
import keystoneauth1
from keystoneclient import session


class OSCCredentialsError(Exception):
    pass


class OSCEndpointError(OSCCredentialsError):
    pass


class OSCHelper():
    def __init__(self):
        self.charm_config = hookenv.config()
        self._keystone_client = None

    def store_keystone_credentials(self, creds):
        '''store keystone credentials'''
        kv = unitdata.kv()
        kv.set('keystonecreds', creds)
        kv.set('rallyinstalled', False)

    @property
    def novarc(self):
        return '/var/lib/nagios/nagios.novarc'

    @property
    def plugins_dir(self):
        return '/usr/local/lib/nagios/plugins/'

    @property
    def scripts_dir(self):
        return '/usr/local/bin/'

    @property
    def rally_cron_file(self):
        return '/etc/cron.d/osc_rally'

    @property
    def is_rally_enabled(self):
        return self.charm_config['check-rally']

    @property
    def skipped_rally_checks(self):
        skipped_os_components = self.charm_config['skip-rally'].strip()
        if not skipped_os_components:
            return []

        # filter skip-rally input to match available (or supported) components that
        # should be disabled
        available_os_components = 'cinder glance nova neutron'.split()
        return [comp.strip().lower() for comp in skipped_os_components.split(',')
                if comp.strip().lower() in available_os_components]

    @property
    def rally_cron_schedule(self):
        schedule = self.charm_config['rally-cron-schedule']
        if schedule.strip() == '' or len(schedule.strip().split()) != 5:
            return '*/15 * * * *'
        else:
            return schedule.strip()

    def get_os_credentials(self):
        ident_creds = config_flags_parser(self.charm_config['os-credentials'])
        if not ident_creds.get('auth_url'):
            raise OSCCredentialsError('auth_url')
        elif '/v3' in ident_creds.get('auth_url'):
            extra_attrs = ['domain']
            creds = {'auth_version': 3}
        else:
            extra_attrs = []
            creds = {}

        common_attrs = ('username password region_name auth_url'
                        ' credentials_project').split()
        all_attrs = common_attrs + extra_attrs
        missing = [k for k in all_attrs if k not in ident_creds]
        if missing:
            raise OSCCredentialsError(', '.join(missing))

        ident_creds['auth_url'] = ident_creds['auth_url'].strip('\"\'')
        creds.update(dict([(k, ident_creds.get(k))
                           for k in all_attrs
                           if k not in ('credentials_project', 'domain')]))
        if extra_attrs:
            creds.update({'project_name': ident_creds['credentials_project'],
                          'user_domain_name': ident_creds['domain'],
                          'project_domain_name': ident_creds['domain'],
                          })
        else:
            creds['tenant_name'] = ident_creds['credentials_project']

        return creds

    def get_keystone_credentials(self):
        '''retrieve keystone credentials from either config or relation data

        If config 'os-crendentials' is set, return that info otherwise look for a keystonecreds relation data'

        :return: dict of credential information for keystone
        '''
        return unitdata.kv().get('keystonecreds')

    @property
    def nova_warn(self):
        return self.charm_config.get('nova_warn')

    @property
    def nova_crit(self):
        return self.charm_config.get('nova_crit')

    @property
    def nova_skip_aggregates(self):
        skipped_aggregates = self.charm_config.get('skipped_host_aggregates')
        # We have to make sure there are no malicious injections in the code
        # as this gets passed to a python script via bash
        regex = r'(\w+[,\w+]*)'
        sanitized = ",".join(re.findall(regex, skipped_aggregates))
        sanitized = [s for s in sanitized.split(',') if s != ""]
        sanitized = ",".join(sanitized)
        return sanitized

    @property
    def skip_disabled(self):
        if self.charm_config.get('skip-disabled'):
            return '--skip-disabled'
        else:
            return ''

    @property
    def check_dns(self):
        return self.charm_config.get('check-dns')

    def update_plugins(self):
        charm_plugin_dir = os.path.join(hookenv.charm_dir(), 'files', 'plugins/')
        host.rsync(charm_plugin_dir, self.plugins_dir, options=['--executability'])

    def render_checks(self, creds):
        render(source='nagios.novarc', target=self.novarc, context=creds,
               owner='nagios', group='nagios')

        nrpe = NRPE()
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)

        self.update_plugins()
        nova_check_command = os.path.join(self.plugins_dir, 'check_nova_services.py')
        check_command = '{} --warn {} --crit {} --skip-aggregates {} {}'.format(
            nova_check_command, self.nova_warn, self.nova_crit, self.nova_skip_aggregates,
            self.skip_disabled).strip()
        nrpe.add_check(shortname='nova_services',
                       description='Check that enabled Nova services are up',
                       check_cmd=check_command,
                       )

        nrpe.add_check(shortname='neutron_agents',
                       description='Check that enabled Neutron agents are up',
                       check_cmd=os.path.join(self.plugins_dir,
                                              'check_neutron_agents.sh'),
                       )

        if len(self.check_dns):
            nrpe.add_check(shortname='dns_multi',
                           description='Check DNS names are resolvable',
                           check_cmd='{} {}'.format(
                               os.path.join(self.plugins_dir,
                                            'check_dns_multi.sh'),
                               ' '.join(self.check_dns.split())),
                           )
        else:
            nrpe.remove_check(shortname='dns_multi')
        nrpe.write()

        self.create_endpoint_checks(creds)

    def _split_url(self, netloc, scheme):
        """http(s)://host:port or http(s)://host will return a host and a port

        Even if a port is not specified, this helper will return a host and a port
        (guessing it from the protocol used, if needed)

        :param netloc: network location part as returned by urllib.urlparse
        :type netloc: str
        :param scheme: URL scheme specifier as returned by urllib.urlparse
        :returns: str
        :rtype: Tuple[str, str]
        """
        if netloc.find(':') == -1:
            # no port specified
            host = netloc
            port = 80 if scheme == 'http' else 443
        else:
            host, port = netloc.split(':')

        return host, port

    def create_endpoint_checks(self, creds):
        """
        Create an NRPE check for each Keystone catalog endpoint.

        Read the Keystone catalog, and create a check for each endpoint listed.
        If there is a healthcheck endpoint for the API, use that URL, otherwise check
        the url '/'.
        If SSL, add a check for the cert.

        v2 endpoint needs the 'interface' attribute:
        <Endpoint {'id': 'XXXXX', 'region': 'RegionOne', 'publicurl': 'http://10.x.x.x:9696',
        'service_id': 'YYY', 'internalurl': 'http://10.x.x.x:9696', 'enabled': True,
        'adminurl': 'http://10.x.x.x:9696'}>
        """
        # provide URLs that can be used for healthcheck for some services
        # This also provides a nasty hack-ish way to add switches if we need
        # for some services.
        health_check_params = {
            'aodh': '/healthcheck',
            'barbican': '/v1 -e Unauthorized',
            'ceilometer': '/ -e Unauthorized -d x-openstack-request-id',
            'cinderv1': '/v1 -e Unauthorized -d x-openstack-request-id',
            'cinderv2': '/v2 -e Unauthorized -d x-openstack-request-id',
            'cinderv3': '/v3 -e Unauthorized -d x-openstack-request-id',
            'glance': '/healthcheck',
            'gnocchi': '/v1 -e Unauthorized',
            'heat': '/v1 -e Unauthorized -d X-Openstack-Request-Id',
            'keystone': '/healthcheck',
            'nova': '/healthcheck',
            'placement': '/healthcheck -e Unauthorized -d x-openstack-request-id',
            's3': '/healthcheck',
            'swift': self.charm_config.get('swift_check_params', '/'),
            }

        self.get_keystone_client(creds)
        endpoints = self.keystone_endpoints
        services = [svc for svc in self.keystone_services if svc.enabled]
        nrpe = NRPE()
        skip_service = set()
        for endpoint in endpoints:
            endpoint.service_names = [x.name
                                      for x in services
                                      if x.id == endpoint.service_id]
            service_name = endpoint.service_names[0]
            endpoint.healthcheck_url = health_check_params.get(service_name, '/')

            # Note(aluria): glance-simplestreams-sync does not provide an API to check
            if service_name == 'image-stream':
                continue

            if not hasattr(endpoint, 'interface'):
                if service_name == 'keystone':
                    # Note(aluria): filter:healthcheck is not configured in v2
                    # https://docs.openstack.org/keystone/pike/configuration.html#health-check-middleware
                    continue
                for interface in 'admin internal public'.split():
                    old_interface_name = '{}url'.format(interface)
                    if not hasattr(endpoint, old_interface_name):
                        continue
                    endpoint.interface = interface
                    endpoint.url = getattr(endpoint, old_interface_name)
                    skip_service.add(service_name)
                    break

            check_url = urlparse(endpoint.url)
            if not self.charm_config.get('check_{}_urls'.format(endpoint.interface)):
                nrpe.remove_check(shortname='{}_{}'.format(service_name, endpoint.interface))
                if check_url.scheme == 'https':
                    nrpe.remove_check(shortname='{}_{}_cert'.format(service_name, endpoint.interface))
                continue

            cmd_params = ['/usr/lib/nagios/plugins/check_http']
            host, port = self._split_url(check_url.netloc, check_url.scheme)
            cmd_params.append('-H {} -p {}'.format(host, port))
            cmd_params.append('-u {}'.format(endpoint.healthcheck_url))

            # if this is https, we want to add a check for cert expiry
            # also need to tell check_http use use TLS
            if check_url.scheme == 'https':
                cmd_params.append('-S')
                # Add an extra check for TLS cert expiry
                cmd_params_cert = cmd_params.copy()
                cmd_params_cert.append('-C {},{}'.format(self.charm_config['tls_warn_days'] or 30,
                                                         self.charm_config['tls_crit_days'] or 14))
                nrpe.add_check(shortname='{}_{}_cert'.format(service_name, endpoint.interface),
                               description='Certificate expiry check for {} {}'.format(service_name,
                                                                                       endpoint.interface),
                               check_cmd=' '.join(cmd_params_cert))

            # Add the actual health check for the URL
            nrpe.add_check(shortname='{}_{}'.format(service_name, endpoint.interface),
                           description='Endpoint url check for {} {}'.format(service_name, endpoint.interface),
                           check_cmd=' '.join(cmd_params))

        nrpe.write()

    def get_keystone_client(self, creds):
        """Import the appropriate Keystone client depending on API version.

        Use credential info to determine the Keystone API version, and make a
        client session object that is to be used for authenticated
        communication with Keystone.

        :returns: a keystoneclient Client object
        """
        if int(creds.get('auth_version', 0)) >= 3:
            from keystoneclient.v3 import client
            from keystoneclient.auth.identity import v3 as kst_version
            auth_fields = 'username password auth_url user_domain_name project_domain_name project_name'.split()
        else:
            from keystoneclient.v2_0 import client
            from keystoneclient.auth.identity import v2 as kst_version
            auth_fields = 'username password auth_url tenant_name'.split()

        auth_creds = dict([(key, creds.get(key)) for key in auth_fields])
        auth = kst_version.Password(**auth_creds)
        sess = session.Session(auth=auth)
        self._keystone_client = client.Client(session=sess)

        if self._keystone_client is None:
            raise OSCEndpointError('Unable to list the endpoint errors, yet: '
                                   'could not connect to the Identity Service')

    @property
    def keystone_endpoints(self):
        try:
            return self._keystone_client.endpoints.list()
        except keystoneauth1.exceptions.http.InternalServerError as error:
            raise OSCEndpointError(
                'Unable to list the keystone endpoints, yet: {}'.format(error))

    @property
    def keystone_services(self):
        return self._keystone_client.services.list()

    @property
    def _load_envvars(self, novarc='/var/lib/nagios/nagios.novarc'):
        if not os.path.exists(novarc):
            return False

        output = subprocess.check_output(['/bin/bash', '-c', 'source {} && env'.format(novarc)])
        i = 0
        for line in output.decode('utf-8').splitlines():
            if not line.startswith('OS_'):
                continue
            key, value = line.split('=')
            os.environ[key] = value
            i += 1

        return i >= 3

    def _run_as(self, user, user_cmd):
        try:
            pwd.getpwnam(user)
            # preserve envvars and run as `user`
            cmd = ['sudo', '-Eu', user]

            # convert command into a list
            if isinstance(user_cmd, str):
                # split string into arguments
                cmd.extend(user_cmd.split())
            elif isinstance(user_cmd, list):
                cmd.extend(user_cmd)
            else:
                hookenv.log("_run_as - can't run as user {} the command: {}".format(user, user_cmd))
                return False

            subprocess.check_call(cmd)
            return True

        except KeyError as error:
            hookenv.log('_run_as - user does not exist => {}'.format(str(error)))
            return False
        except subprocess.CalledProcessError as error:
            hookenv.log('_run_as - cmd failed => {}'.format(str(error)))
            if error.stderr:
                hookenv.log('_run_as stderr => {}'.format(error.stderr))
            if error.stdout:
                hookenv.log('_run_as stderr => {}'.format(error.stdout))
            return False

    @property
    def _rallyuser(self):
        return 'nagiososc'

    def install_rally(self):
        kv = unitdata.kv()
        if kv.get('rallyinstalled', False):
            return True

        if not self._load_envvars:
            hookenv.log('install_rally - could not load nagios.novarc')
            return False

        user = self._rallyuser
        host.adduser(user)
        host.mkdir(os.path.join('/home', user), owner=user, group=user, perms=0o755, force=False)

        for tool in ['rally', 'tempest']:
            toolname = 'fcbtest.{}init'.format(tool)
            installed = self._run_as(user, [toolname])
            if not installed:
                hookenv.log('install_rally - could not initialize {}'.format(tool))
                return False

        kv.set('rallyinstalled', True)
        return True

    def _regenerate_tempest_conf(self, tempestfile):
        config = configparser.ConfigParser()
        config.read(tempestfile)
        for section in config.keys():
            for key, value in config[section].items():
                try:
                    if section != 'DEFAULT' and key in config['DEFAULT'].keys():
                        # avoid copying the DEFAULT config options to the rest of sections
                        continue
                except KeyError:
                    # DEFAULT section does not exist
                    pass

                # Enable Cinder, which is a default OpenStack service
                if section == 'service_available' and key == 'cinder':
                    config[section][key] = 'True'

        with open(tempestfile, 'w') as fd:
            config.write(fd)

    def reconfigure_tempest(self):
        """Expects an external network already configured, and enables cinder tests

        Sample:
        RALLY_VERIFIER=7b9d06ef-e651-4da3-a56b-ecac67c595c5
        RALLY_VERIFICATION=4a730963-083f-4e1e-8c55-f2b4b9c9c0ac
        RALLY_DEPLOYMENT=a75657c6-9eea-4f00-9117-2580fe056a80
        RALLY_ENV=a75657c6-9eea-4f00-9117-2580fe056a80
        """
        RALLY_CONF = ['/home', self._rallyuser, 'snap', 'fcbtest', 'current', '.rally']
        rally_globalconfig = os.path.join(*RALLY_CONF, 'globals')
        if not os.path.isfile(rally_globalconfig):
            return False

        uuids = collections.defaultdict(lambda: '*')
        with open(rally_globalconfig, 'r') as fd:
            for line in fd.readlines():
                key, value = line.strip().split('=')
                if key in ['RALLY_VERIFIER', 'RALLY_DEPLOYMENT']:
                    uuids[key] = value

        tempest_path = os.path.join(*RALLY_CONF, 'verification',
                                    'verifier-{RALLY_VERIFIER}'.format(**uuids),
                                    'for-deployment-{RALLY_DEPLOYMENT}'.format(**uuids),
                                    'tempest.conf')
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
        for comp in 'cinder glance nova neutron'.split():
            ctxt.update({comp: comp not in os_components_skip_list})
        return ctxt

    def update_rally_checkfiles(self):
        if not self.is_rally_enabled:
            return

        # Copy run_rally.sh to /usr/local/bin
        rally_script = os.path.join(hookenv.charm_dir(), 'files', 'run_rally.py')
        host.rsync(rally_script, self.scripts_dir, options=['--executability'])

        ostestsfile = os.path.join('/home', self._rallyuser, 'ostests.txt')
        render(source='ostests.txt.j2', target=ostestsfile,
               context=self._get_rally_checks_context(),
               owner=self._rallyuser, group=self._rallyuser)

        context = {
            'schedule': self.rally_cron_schedule,
            'user': self._rallyuser,
            'cmd': os.path.join(self.scripts_dir, 'run_rally.py'),
        }
        content = '{schedule} {user} timeout -k 840s -s SIGTERM 780s {cmd}'.format(**context)
        with open(self.rally_cron_file, 'w') as fd:
            fd.write('# Juju generated - DO NOT EDIT\n{}\n'.format(content))

    def configure_rally_check(self):
        kv = unitdata.kv()
        if kv.get('rallyconfigured', False):
            return

        self.update_rally_checkfiles()
        rally_check = os.path.join(self.plugins_dir, 'check_rally.py')
        nrpe = NRPE()
        nrpe.add_check(shortname='rally',
                       description='Check that all rally tests pass',
                       check_cmd=rally_check,
                       )
        nrpe.write()
        kv.set('rallyconfigured', True)

    def remove_rally_check(self):
        filename = self.rally_cron_file
        if os.path.exists(filename):
            os.unlink(filename)

        if os.path.exists('/etc/nagios/nrpe.d/check_rally.cfg'):
            nrpe = NRPE()
            nrpe.remove_check(shortname='rally')
            nrpe.write()

    def deploy_rally(self):
        if self.is_rally_enabled:
            installed = self.install_rally()
            if not installed:
                return False
            self.configure_rally_check()
        else:
            self.remove_rally_check()
            unitdata.kv().set('rallyconfigured', False)
        return True
