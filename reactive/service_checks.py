import shutil, os
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

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from charmhelpers.contrib.charmsupport.nrpe import NRPE


config = hookenv.config()
install_packages = ['nagios-nrpe-server', 'python-openstackclient']


@when_not('service-checks.installed')
def set_install_service_checks():
    set_state('service-checks.do-install')


@when('service-checks.do-install')
def install_service_checks():
    hookenv.status_set('maintenance', 'Installing software')
    apt_update()
    apt_install(install_packages)
    set_state('service-checks.installed')
    set_state('service-checks.do-check-reconfig')
# setup openstack user


@when('identity-credentials.connected')
def configure_keystone_username(keystone):
    username = 'nagios'
    keystone.configure(username)


@when('identity-credentials.available')
def save_creds(keystone):
    unitdata.kv().set('keystone-relation-creds', keystone.get_creds())
    set_state('service-checks.do-reconfig')


# allow user to override credentials (and the need to be related to keystone)
# with 'os-credentials'
def get_credentials():
    keystone_creds = config_flags_parser(config.get('os-credentials'))
    if keystone_creds:
        creds = {
            'credentials_username': keystone_creds['username'],
            'credentials_password': keystone_creds['password'],
            'credentials_project': keystone_creds.get('tenant_name', 'admin'),
            'region': keystone_creds['region_name'],
            'auth_url': keystone_creds['auth_url'],
        }

    else:
        kv = unitdata.kv()
        creds = kv.get('keystone-relation-creds')
    set_state('exporter.do-reconfig')
    return creds


def render_checks():
    nrpe = NRPE()
    plugins_dir = '/usr/local/lib/nagios/plugins/'
    if not os.path.exists(plugins_dir):
        os.makedirs(plugins_dir)
    nrpe.add_check(shortname='check_nova_services',
                   description='Check that enabled Nova services are up',
                   check_cmd=plugins_dir+'check_nova_services.sh')
    nrpe.add_check(shortname='check_neutron_agents',
                   description='Check that enabled Neutron agents are up',
                   check_cmd=plugins_dir+'check_neutron_agents.sh')


@when('service-checks.do-reconfig')
def render_config():
    creds = get_credentials()
    if not creds:
        hookenv.log('render_config: No credentials yet, skipping')
        return
    hookenv.log('render_config: Got credentials for username={}'.format(
        creds['credentials_username']))
    render('nagios.novarc', '/var/lib/nagios/nagios.novarc', owner='nagios',
           group='nagios')
    render_checks()
    set_state('service-checks.do-restart')


@when('service-checks.do-start')
def do_restart():
    hookenv.log('Reloading nagios-nrpe-server')
    host.service_restart('nagios-nrpe-server')
    hookenv.status_set('active', 'Ready')
    remove_state('service-checks.do-restart')
