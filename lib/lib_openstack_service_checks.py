import os
from urllib.parse import urlparse

from charmhelpers.core.templating import render
from charmhelpers.contrib.openstack.utils import config_flags_parser
from charmhelpers.core import hookenv, host, unitdata
from charmhelpers.contrib.charmsupport.nrpe import NRPE
import keystoneauth1
from keystoneclient import session


class OSCCredentialsError(Exception):
    pass


class OSCEndpointError(OSCCredentialsError):
    pass


class OSCHelper():
    def __init__(self):
        self.charm_config = hookenv.config()

    def store_keystone_credentials(self, creds):
        '''store keystone credentials'''
        unitdata.kv().set('keystonecreds', creds)
        return

    @property
    def novarc(self):
        return '/var/lib/nagios/nagios.novarc'

    @property
    def plugins_dir(self):
        return '/usr/local/lib/nagios/plugins/'

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
    def nova_skip(self):
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

    def render_checks(self, creds):
        render(source='nagios.novarc', target=self.novarc, context=creds,
               owner='nagios', group='nagios')

        nrpe = NRPE()
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)

        charm_plugin_dir = os.path.join(hookenv.charm_dir(),
                                        'files',
                                        'plugins/')
        host.rsync(charm_plugin_dir,
                   self.plugins_dir,
                   options=['--executability'])

        nova_check_command = os.path.join(self.plugins_dir,
                                          'check_nova_services.py')
        check_command = '{} --warn {} --crit {} --skip {} {}'.format(
            nova_check_command, self.nova_warn, self.nova_crit, self.nova_skip,
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
            'barbican': '/ -e Unauthorized -d x-openstack-request-id',
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
        keystone_client = self.get_keystone_client(creds)
        try:
            endpoints = keystone_client.endpoints.list()
        except keystoneauth1.exceptions.http.InternalServerError as error:
            raise OSCEndpointError(
                'Unable to list the keystone endpoints, yet: {}'.format(error))

        services = [x for x in keystone_client.services.list() if x.enabled]
        nrpe = NRPE()
        skip_service = set()
        for endpoint in endpoints:
            endpoint.service_names = [x.name
                                      for x in services
                                      if x.id == endpoint.service_id]
            service_name = endpoint.service_names[0]
            endpoint.healthcheck_url = health_check_params.get(service_name, '/')
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
            if self.charm_config.get('check_{}_urls'.format(endpoint.interface)):
                cmd_params = ['/usr/lib/nagios/plugins/check_http']
                host, port = check_url.netloc.split(':')
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
            else:
                nrpe.remove_check(shortname='{}_{}'.format(service_name, endpoint.interface))
                if check_url.scheme == 'https':
                    nrpe.remove_check(shortname='{}_{}_cert'.format(service_name, endpoint.interface))
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
        return client.Client(session=sess)
