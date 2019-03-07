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
<<<<<<< HEAD
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
    try:
        endpoints = keystone_client.endpoints.list()
    except keystoneauth1.exceptions.http.InternalServerError:
        return None

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
            # assume http port 80 if no port specified
            endpoint_port = 80
            if len(host_port) < 2:
                if check_url.scheme == 'https':
                    endpoint_port = 443
            else:
                endpoint_port = host_port[1]
            cmd_params.append('-H {} -p {}'.format(host_port[0], endpoint_port))
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
=======
    set_flag('openstack-service-checks.started')
>>>>>>> 1447899... Rewrite: helpers moved to lib
