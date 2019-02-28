from __future__ import print_function
import base64
import os
import subprocess
from charms.reactive import (
    when,
    when_not,
    set_state,
    remove_state,
)

from charmhelpers.core.templating import render
from charmhelpers.contrib.openstack.utils import config_flags_parser
from charmhelpers.core import (
    host,
    hookenv,
    unitdata,
)

from charmhelpers.contrib.charmsupport.nrpe import NRPE
from urllib.parse import urlparse

config = hookenv.config()
NOVARC = '/var/lib/nagios/nagios.novarc'
PLUGINS_DIR = '/usr/local/lib/nagios/plugins/'


@when_not('os-service-checks.installed')
def install_service_checks():
    # Apt package installs are handled by the apt layer
    set_state('os-service-checks.installed')
    remove_state('os-service-checks.configured')
    hookenv.status_set('active', 'Ready')


@when('identity-credentials.connected')
def configure_ident_username(keystone):
    username = 'nagios'
    keystone.request_credentials(username)


@when('identity-credentials.available')
def save_creds(keystone):
    """
    Collect and save credentials from Keystone relation.

    Get credentials from the Keystone relation,
    reformat them into something the Keystone client
    can use, and save them into the unitdata.
    """
    creds = {
        'username': keystone.credentials_username(),
        'password': keystone.credentials_password(),
        'region': keystone.region(),
    }
    if keystone.api_version() == '3':
        api_url = "v3"
        try:
            domain = keystone.domain()
        except AttributeError:
            domain = 'service_domain'
        # keystone relation sends info back with funny names, fix here
        creds.update({
            'project_name': keystone.credentials_project(),
            'auth_version': '3',
            'user_domain_name': domain,
            'project_domain_name': domain
        })
    else:
        api_url = "v2.0"
        creds['tenant_name'] = keystone.credentials_project()

    auth_url = "%s://%s:%s/%s" % (keystone.auth_protocol(),
                                  keystone.auth_host(), keystone.auth_port(),
                                  api_url)
    creds['auth_url'] = auth_url
    unitdata.kv().set('keystonecreds', creds)
    remove_state('os-service-checks.configured')


# allow user to override credentials (and the need to be related to Keystone)
# with 'os-credentials'
def get_credentials():
    """
    Get credential info from either config or relation data.

    If config 'os-credentials' is set, return that info otherwise look for for a keystonecreds relation data.

    :return: dictionary of credential information for Keystone.
    """
    ident_creds = config_flags_parser(config.get('os-credentials'))
    if ident_creds:
        creds = {
            'username': ident_creds['username'],
            'password': ident_creds['password'],
            'region': ident_creds['region_name'],
            'auth_url': ident_creds['auth_url'],
        }
        if '/v3' in ident_creds['auth_url']:
            creds.update({
                'project_name': ident_creds['credentials_project'],
                'auth_version': '3',
                'user_domain_name': ident_creds['domain'],
                'project_domain_name': ident_creds['domain'],
            })
        else:
            creds['tenant_name'] = ident_creds['credentials_project']
    else:
        kv = unitdata.kv()
        creds = kv.get('keystonecreds')
        old_creds = kv.get('keystone-relation-creds')
        if old_creds and not creds:
            # This set of creds needs an update to a newer format
            creds['username'] = old_creds.pop('credentials_username')
            creds['password'] = old_creds.pop('credentials_password')
            creds['project_name'] = old_creds.pop('credentials_project')
            creds['tenant_name'] = old_creds['project_name']
            creds['user_domain_name'] = old_creds.pop('credentials_user_domain', None)
            creds['project_domain_name'] = old_creds.pop('credentials_project_domain', None)
            kv.set('keystonecreds', creds)
            kv.update(creds, 'keystonecreds')
    return creds


def render_checks():
    nrpe = NRPE()
    if not os.path.exists(PLUGINS_DIR):
        os.makedirs(PLUGINS_DIR)
    charm_file_dir = os.path.join(hookenv.charm_dir(), 'files')
    charm_plugin_dir = os.path.join(charm_file_dir, 'plugins')
    host.rsync(
        charm_plugin_dir,
        '/usr/local/lib/nagios/',
        options=['--executability']
    )

    warn = config.get("nova_warn")
    crit = config.get("nova_crit")
    skip_disabled = config.get("skip-disabled")
    check_dns = config.get("check-dns")
    nova_check_command = os.path.join(PLUGINS_DIR, 'check_nova_services.py')
    check_command = '{} --warn {} --crit {}'.format(nova_check_command, warn, crit)

    if skip_disabled:
        check_command = check_command + ' --skip-disabled'

    nrpe.add_check(shortname='nova_services',
                   description='Check that enabled Nova services are up',
                   check_cmd=check_command)

    nrpe.add_check(shortname='neutron_agents',
                   description='Check that enabled Neutron agents are up',
                   check_cmd=os.path.join(PLUGINS_DIR, 'check_neutron_agents.sh'))

    if len(check_dns):
        nrpe.add_check(shortname='dns_multi',
                       description='Check DNS names are resolvable',
                       check_cmd=PLUGINS_DIR + 'check_dns_multi.sh ' + ' '.join(check_dns.split()))
    else:
        nrpe.remove_check(shortname='dns_multi')

    endpoint_checks = create_endpoint_checks()
    for check in endpoint_checks:
        nrpe.add_check(**check)
    nrpe.write()


@when('nrpe-external-master.available')
def nrpe_connected(nem):
    remove_state('os-service-checks.configured')


@when('os-service-checks.installed')
@when_not('os-service-checks.configured')
def render_config():
    if config.get('trusted_ssl_ca', None):
        fix_ssl()
    creds = get_credentials()
    if not creds:
        hookenv.log('render_config: No credentials yet, skipping')
        return
    hookenv.log('render_config: Got credentials for username={}'.format(
        creds['username']))
    render('nagios.novarc', NOVARC, creds,
           owner='nagios', group='nagios')
    render_checks()
    set_state('os-service-checks.configured')
    remove_state('os-service-checks.started')


@when('os-service-checks.configured')
@when_not('os-service-checks.started')
def do_restart():
    hookenv.log('Reloading nagios-nrpe-server')
    host.service_restart('nagios-nrpe-server')
    hookenv.status_set('active', 'Ready')
    set_state('os-service-checks.started')


def fix_ssl():
    cert_file = '/usr/local/share/ca-certificates/openstack-service-checks.crt'
    trusted_ssl_ca = config.get('trusted_ssl_ca').strip()
    hookenv.log("Writing ssl ca cert:{}".format(trusted_ssl_ca))
    cert_content = base64.b64decode(trusted_ssl_ca).decode()
    with open(cert_file, 'w') as f:
        print(cert_content, file=f)
    subprocess.call(["/usr/sbin/update-ca-certificates"])


def create_endpoint_checks():
    """
    Create an NRPE check for each Keystone catalog endpoint.

    Read the Keystone catalog, and create a check for each endpoint listed.
    If there is a healthcheck endpoint for the API, use that URL, otherwise check
    the url '/'.
    If SSL, add a check for the cert.
    """
    # provide URLs that can be used for healthcheck for some services
    # This also provides a nasty hack-ish way to add switches if we need
    # for some services.
    health_check_params = {
        'keystone': '/healthcheck',
        's3': '/healthcheck',
        'aodh': '/healthcheck',
        'cinderv3': '/v3 -e Unauthorized -d x-openstack-request-id',
        'cinderv2': '/v2 -e Unauthorized -d x-openstack-request-id',
        'cinderv1': '/v1 -e Unauthorized -d x-openstack-request-id',
        'glance': '/healthcheck',
        'nova': '/healthcheck',
    }

    creds = get_credentials()
    keystone_client = get_keystone_client(creds)
    endpoints = keystone_client.endpoints.list()
    services = [x for x in keystone_client.services.list() if x.enabled]
    nrpe_checks = []
    for endpoint in endpoints:
        endpoint.service_names = [x.name for x in services if x.id == endpoint.service_id]
        service_name = endpoint.service_names[0]
        endpoint.healthcheck_url = health_check_params.get(service_name, '/')
        if config.get('check_{}_urls'.format(endpoint.interface)):
            cmd_params = ['/usr/lib/nagios/plugins/check_http ']
            check_url = urlparse(endpoint.url)
            host_port = check_url.netloc.split(':')
            cmd_params.append('-H {} -p {}'.format(host_port[0], host_port[1]))
            cmd_params.append('-u {}'.format(endpoint.healthcheck_url))
            # if this is https, we want to add a check for cert expiry
            # also need to tell check_http use use TLS
            if check_url.scheme == 'https':
                cmd_params.append('-S')
                # Add an extra check for TLS cert expiry
                cert_check = ['-C {},{}'.format(
                    config.get('tls_warn_days'),
                    config.get('tls_crit_days'))]
                nrpe_checks.append({
                    'shortname': "{}_{}_cert".format(
                        service_name,
                        endpoint.interface),
                    'description': 'Certificate expiry check for {} {}'.format(
                        service_name,
                        endpoint.interface),
                    'check_cmd': ' '.join(cmd_params + cert_check)
                })
            # Add the actual health check for the URL
            nrpe_checks.append({
                'shortname': "{}_{}".format(
                    service_name,
                    endpoint.interface),
                'description': 'Endpoint url check for {} {}'.format(
                    service_name,
                    endpoint.interface),
                'check_cmd': (' '.join(cmd_params))})
    return nrpe_checks


def get_keystone_client(creds):
    """
    Import the appropriate Keystone client depending on API version.

    Use credential info to determine the Keystone API version, and make a client session object that is to be
    used for authenticated communication with Keystone.

    :returns: a keystoneclient Client object
    """
    from keystoneclient import session
    if int(creds['auth_version']) >= 3:
        from keystoneclient.v3 import client
        from keystoneclient.auth.identity import v3
        auth_fields = ['auth_url', 'password', 'username', 'user_domain_name',
                       'project_domain_name', 'project_name']
        auth_creds = {}
        for key in auth_fields:
            auth_creds[key] = creds[key]
        auth = v3.Password(**auth_creds)

    else:
        from keystoneclient.v2_0 import client
        from keystoneclient.auth.identity import v2
        auth_fields = ['auth_url', 'password', 'username', 'tenant_name']
        auth_creds = {}
        for key in auth_fields:
            auth_creds[key] = creds[key]
        auth = v2.Password(**auth_creds)

    sess = session.Session(auth=auth)
    return client.Client(session=sess)
