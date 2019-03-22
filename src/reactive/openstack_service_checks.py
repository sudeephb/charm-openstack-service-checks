from lib_openstack_service_checks import OpenstackservicechecksHelper
from charmhelpers.core import hookenv, host
from charms.reactive import clear_flag, set_flag, when, when_not

helper = OpenstackservicechecksHelper()


@when_not('openstack-service-checks.installed')
def install_openstack_service_checks():
    set_flag('openstack-service-checks.installed')
    clear_flag('openstack-service-checks.configured')
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
    creds = {'username': keystone.credentials_username(), 'password': keystone.credentials_password(),
             'region': keystone.region()}
    if keystone.api_version() == '3':
        api_url = 'v3'
        try:
            domain = keystone.domain()
        except AttributeError:
            domain = 'service_domain'
        # keystone relation sends info back with funny names, fix here
        creds.update({'project_name': keystone.credentials_project(), 'auth_version': '3', 'user_domain_name': domain,
                      'project_domain_name': domain})
    else:
        api_url = 'v2.0'
        creds['tenant_name'] = keystone.credentials_project()

    creds['auth_url'] = '{}://{}:{}/{}'.format(keystone.auth_protocol(), keystone.auth_host(), keystone.auth_port(),
                                               api_url)

    helper.store_keystone_credentials(creds)
    clear_flag('openstack-service-checks.configured')


@when('nrpe-external-master.available')
def nrpe_connected(nem):
    clear_flag('openstack-service-checks.configured')


@when('openstack-service-checks.installed')
@when_not('openstack-service-checks.configured')
def render_config():
    creds = helper.get_keystone_credentials()
    if not creds:
        hookenv.log('render_config: No credentials yet, skipping')
        return

    if not helper.fix_ssl():
        return

    hookenv.log('render_config: Got credentials for username={}'.format(creds.get('username')))
    clear_flag('openstack-service-checks.epconfigured')

    helper.render_checks(creds)
    hookenv.status_set('active', 'Ready')
    set_flag('openstack-service-checks.configured')
    clear_flag('openstack-service-checks.started')


@when('openstack-service-checks.installed')
@when('openstack-service-checks.configured')
@when_not('openstack-service-checks.epconfigured')
def configure_nrpe_endpoints():
    creds = helper.get_keystone_credentials()
    if not creds:
        hookenv.log('render_config: No credentials yet, skipping')
        return
    helper.create_endpoint_checks(creds)


@when('openstack-service-checks.configured')
@when_not('openstack-service-checks.started')
def do_restart():
    hookenv.log('Reloading nagios-nrpe-server')
    host.service_restart('nagios-nrpe-server')
    hookenv.status_set('active', 'Ready')
    set_flag('openstack-service-checks.started')
