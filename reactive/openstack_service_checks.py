# -*- coding: us-ascii -*-
"""
install_osc +------------------------> render_config+--------------> do_restart
                                          ^       +                      ^
conf_kst_user+---> save_creds +-----------+       v                      |
                                                  create_endpoints +-----+

Available states:
    identity-credentials.available: kst creds available
    identity-credentials.connected: kst relation joined
    nrpe-external-master.available: nrpe relation joined
    openstack-service-checks.configured: render_config allowed
    openstack-service-checks.endpoints.configured: create_endpoints allowed
    openstack-service-checks.installed: install_osc entrypoint
    openstack-service-checks.started: if not set, restart nagios-nrpe-server
    openstack-service-checks.stored-creds: kst creds available for the unit
"""
import base64
import subprocess

from charmhelpers.core import hookenv, host, unitdata
from charms.reactive import any_flags_set, clear_flag, is_flag_set, set_flag, when, when_not

from lib_openstack_service_checks import (
    OSCHelper,
    OSCCredentialsError,
    OSCEndpointError
)

CERT_FILE = '/usr/local/share/ca-certificates/openstack-service-checks.crt'
helper = OSCHelper()


@when_not('openstack-service-checks.installed')
@when('nrpe-external-master.available')
def install_openstack_service_checks():
    """Entry point to start configuring the unit

    Triggered if related to the nrpe-external-master relation.
    Some relation data can be initialized if the application is related to
    keystone.
    """
    set_flag('openstack-service-checks.installed')
    clear_flag('openstack-service-checks.configured')


@when_not('identity-credentials.available')
@when('identity-credentials.connected')
def configure_ident_username(keystone):
    """Requests a user to the Identity Service
    """
    username = 'nagios'
    keystone.request_credentials(username)
    clear_flag('openstack-service-checks.stored-creds')


@when_not('openstack-service-checks.stored-creds')
@when('identity-credentials.available')
def save_creds(keystone):
    """Collect and save credentials from Keystone relation.

    Get credentials from the Keystone relation,
    reformat them into something the Keystone client can use, and
    save them into the unitdata.
    """
    creds = {'username': keystone.credentials_username(),
             'password': keystone.credentials_password(),
             'region': keystone.region(),
             }
    if keystone.api_version() == '3':
        api_url = 'v3'
        try:
            domain = keystone.domain()
        except AttributeError:
            domain = 'service_domain'
        # keystone relation sends info back with funny names, fix here
        creds.update({'project_name': keystone.credentials_project(),
                      'auth_version': '3',
                      'user_domain_name': domain,
                      'project_domain_name': domain})
    else:
        api_url = 'v2.0'
        creds['tenant_name'] = keystone.credentials_project()

    creds['auth_url'] = '{proto}://{host}:{port}/{api_url}'.format(
        proto=keystone.auth_protocol(), host=keystone.auth_host(),
        port=keystone.auth_port(), api_url=api_url)

    helper.store_keystone_credentials(creds)
    set_flag('openstack-service-checks.stored-creds')
    clear_flag('openstack-service-checks.configured')


@when_not('identity-credentials.connected')
@when_not('identity-credentials.available')
@when('openstack-service-checks.stored-creds')
def allow_keystone_store_overwrite():
    """Allow unitdata overwrite if keystone relation is recycled.
    """
    clear_flag('openstack-service-checks.stored-creds')


@when('identity-credentials.available.updated')
def update_keystone_store():
    """when identity-service-relation-changed is triggered, update the stored credentials
    """
    allow_keystone_store_overwrite()


def get_credentials():
    """Get credential info from either config or relation data

    If config 'os-credentials' is set, return it. Otherwise look for a
    keystonecreds relation data.
    """
    try:
        creds = helper.get_os_credentials()
    except OSCCredentialsError as error:
        creds = helper.get_keystone_credentials()
        if not creds:
            hookenv.log('render_config: No credentials yet, skipping')
            hookenv.status_set('blocked',
                               'Missing os-credentials vars: {}'.format(error))
            return
    return creds


@when('openstack-service-checks.installed')
@when_not('openstack-service-checks.configured')
def render_config():
    """Render nrpe checks from the templates

    This code is only triggered after the nrpe relation is set. If a relation
    with keystone is later set, it will be re-triggered. On the other hand,
    if a keystone relation exists but not a nrpe relation, it won't be run.

    Furthermore, juju config os-credentials take precedence over keystone
    related data.
    """
    def block_tls_failure(error):
        hookenv.log('update-ca-certificates failed: {}'.format(error),
                    hookenv.ERROR)
        hookenv.status_set('blocked',
                           'update-ca-certificates error. check logs')
        return

    creds = get_credentials()
    if not creds:
        return

    # Fix TLS
    if helper.charm_config['trusted_ssl_ca'].strip():
        trusted_ssl_ca = helper.charm_config['trusted_ssl_ca'].strip()
        hookenv.log('Writing ssl ca cert:{}'.format(trusted_ssl_ca))
        cert_content = base64.b64decode(trusted_ssl_ca).decode()
        try:
            with open(CERT_FILE, 'w') as fd:
                fd.write(cert_content)
            subprocess.call(['/usr/sbin/update-ca-certificates'])

        except subprocess.CalledProcessError as error:
            block_tls_failure(error)
            return
        except PermissionError as error:
            block_tls_failure(error)
            return

    hookenv.log('render_config: Got credentials for'
                ' username={}'.format(creds.get('username')))

    try:
        helper.render_checks(creds)
        set_flag('openstack-service-checks.endpoints.configured')
    except OSCEndpointError as error:
        hookenv.log(error)

    if not helper.deploy_rally():
        # Rally could not be installed (if enabled). No further actions taken
        return

    set_flag('openstack-service-checks.configured')
    clear_flag('openstack-service-checks.started')


@when('openstack-service-checks.installed')
@when('openstack-service-checks.configured')
@when_not('openstack-service-checks.endpoints.configured')
def configure_nrpe_endpoints():
    """Create an NRPE check for each Keystone catalog endpoint.

    Read the Keystone catalog, and create a check for each endpoint listed.
    If there is a healthcheck endpoint for the API, use that URL. Otherwise,
    check the url '/'.

    If TLS is enabled, add a check for the cert.
    """
    creds = get_credentials()
    if not creds:
        return

    try:
        helper.create_endpoint_checks(creds)
        set_flag('openstack-service-checks.endpoints.configured')
        clear_flag('openstack-service-checks.started')
    except OSCEndpointError as error:
        hookenv.log(error)


@when('openstack-service-checks.configured')
@when_not('openstack-service-checks.started')
def do_restart():
    hookenv.log('Reloading nagios-nrpe-server')
    host.service_restart('nagios-nrpe-server')
    hookenv.status_set('active', 'Unit is ready')
    set_flag('openstack-service-checks.started')


@when('nrpe-external-master.available')
def do_reconfigure_nrpe():
    os_credentials_flag = 'config.changed.os-credentials'
    flags = ['config.changed.check_{}_urls'.format(interface) for interface in ['admin', 'internal', 'public']]
    flags.extend(os_credentials_flag)

    if is_flag_set('config.changed'):
        clear_flag('openstack-service-checks.configured')

    if any_flags_set(*flags):
        if is_flag_set(os_credentials_flag):
            clear_flag('openstack-service-checks.configured')
        clear_flag('openstack-service-checks.endpoints.configured')

    if helper.is_rally_enabled:
        helper.reconfigure_tempest()

        if is_flag_set('config.changed.skip-rally'):
            helper.update_rally_checkfiles()


@when_not('nrpe-external-master.available')
def missing_nrpe():
    """Avoid a user action to be missed or overwritten by another hook
    """
    if hookenv.hook_name() != 'update-status':
        hookenv.status_set('blocked', 'Missing relations: nrpe')


@when('openstack-service-checks.installed')
@when('nrpe-external-master.available')
def parse_hooks():
    if hookenv.hook_name() == 'upgrade-charm':
        # Check if creds storage needs to be migrated
        # Old key: keystone-relation-creds
        # New key: keystonecreds
        kv = unitdata.kv()
        creds = kv.get('keystonecreds')
        old_creds = kv.get('keystone-relation-creds')
        if old_creds and not creds:
            # This set of creds needs an update to a newer format
            creds = {
                'username': old_creds['credentials_username'],
                'password': old_creds['credentials_password'],
                'project_name': old_creds['credentials_project'],
                'tenant_name': old_creds['credentials_project'],
                'user_domain_name': old_creds.get('credentials_user_domain'),
                'project_domain_name': old_creds.get('credentials_project_domain'),
                }
            kv.set('keystonecreds', creds)

        if old_creds:
            kv.unset('keystone-relation-creds')

        # update rally check files and plugins, which may have changed
        helper.update_plugins()
        helper.update_rally_checkfiles()

        # render configs again
        do_reconfigure_nrpe()
