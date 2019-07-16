import os

import json
import pytest

# Treat all tests as coroutines
pytestmark = pytest.mark.asyncio

SERIES = ['xenial', 'bionic']
CHARM_BUILD_DIR = os.getenv('CHARM_BUILD_DIR', '.').rstrip('/')


# Custom fixtures

@pytest.fixture(scope='module', params=SERIES)
async def osc_apps(request, model):
    series = request.param
    app = model.applications.get('openstack-service-checks-{}'.format(series))
    return app


@pytest.fixture(scope='module', params=SERIES)
async def units(request, apps):
    return apps.units


def app_names(series=None):
    apps = dict([(app, app)
                 for app in ('keystone neutron-api nova-cloud-controller percona-cluster'
                             ' rabbitmq-server nagios'.split())])
    if not series:
        return apps

    apps.update(dict([(app, '{}-{}'.format(app, series))
                      for app in 'openstack-service-checks nrpe'.split()]))
    return apps


@pytest.fixture(scope='module')
async def deploy_openstack(model):
    apps = app_names()
    active_apps = []
    is_deployed = False
    for app in apps.keys():
        if app in model.applications:
            if app != 'nova-cloud-controller':
                active_apps.append(model.applications[app])
            is_deployed = True
            continue
        app_deploy = await model.deploy('cs:{}'.format(app), series='bionic',
                                        application_name=app, num_units=1)
        if app != 'nova-cloud-controller':
            # Note(aluria): n-c-c is blocked because it needs a compute service,
            # which we don't need for testing
            active_apps.append(app_deploy)

    if is_deployed:
        yield active_apps
        return

    await model.add_relation('{}:shared-db'.format(apps['keystone']),
                             '{}:shared-db'.format(apps['percona-cluster']))

    for app in 'neutron-api nova-cloud-controller'.split():
        # Note(aluria): Both neutron/nova APIs needs rmq, mysql, keystone
        await model.add_relation('{}:amqp'.format(apps[app]),
                                 '{}:amqp'.format(apps['rabbitmq-server']))
        await model.add_relation('{}:shared-db'.format(apps[app]),
                                 '{}:shared-db'.format(apps['percona-cluster']))
        await model.add_relation('{}:identity-service'.format(apps[app]),
                                 '{}:identity-service'.format(apps['keystone']))

    yield active_apps


@pytest.fixture(scope='module', params=SERIES)
async def deploy_app(request, model):
    series = request.param
    apps = app_names(series)

    # Starts a deploy for each series
    if (apps['nrpe'] in model.applications
            and apps['openstack-service-checks'] in model.applications):
        yield model.applications[apps['openstack-service-checks']]
        return

    await model.deploy('cs:nrpe', series=series, application_name=apps['nrpe'], num_units=0)
    osc_app = await model.deploy(os.path.join(CHARM_BUILD_DIR, 'openstack-service-checks'),
                                 series=series, application_name=apps['openstack-service-checks'])

    # Add relations: nagios/nrpe, keystone/osc, nrpe/osc
    await model.add_relation('{}:monitors'.format(apps['nrpe']),
                             '{}:monitors'.format(apps['nagios']))
    for app in 'keystone nrpe'.split():
        await model.add_relation(apps[app], apps['openstack-service-checks'])

    yield osc_app


# Tests

async def test_openstackservicechecks_deploy_openstack(deploy_openstack, model):
    await model.block_until(lambda: all([app.status == 'active' for app in deploy_openstack]),
                            timeout=900)


async def test_openstackservicechecks_deploy(deploy_app, model):
    await model.block_until(lambda: deploy_app.status == 'active', timeout=600)


async def test_openstackservicechecks_verify_default_nrpe_checks(deploy_app, model, file_stat):
    unit = [unit for unit in model.units.values() if unit.entity_id.startswith(deploy_app.name)]
    if len(unit) != 1:
        assert False

    unit = unit[0]
    endpoint_checks_config = ['check_{endpoint}_urls'.format(endpoint=endpoint)
                              for endpoint in 'admin internal public'.split()]
    await deploy_app.reset_config(endpoint_checks_config)
    # Wait until nrpe checks are removed
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)
    filenames = [
        '/etc/nagios/nrpe.d/check_{service}_{endpoint}.cfg'.format(service=service, endpoint=endpoint)
        for service in 'keystone neutron nova placement'.split()
        for endpoint in 'admin internal public'.split()
    ]
    filenames.extend([
        '/etc/nagios/nrpe.d/check_nova_services.cfg',
        '/etc/nagios/nrpe.d/check_neutron_agents.cfg',
    ])
    for filename in filenames:
        test_stat = await file_stat(filename, unit)
        assert test_stat['size'] > 0


async def test_openstackservicechecks_remove_endpoint_checks(deploy_app, model, file_stat):
    unit = [unit for unit in model.units.values() if unit.entity_id.startswith(deploy_app.name)]
    if len(unit) != 1:
        assert False

    unit = unit[0]
    endpoint_checks_config = {'check_{endpoint}_urls'.format(endpoint=endpoint): 'false'
                              for endpoint in 'admin internal public'.split()}
    await deploy_app.set_config(endpoint_checks_config)
    # Wait until nrpe checks are removed
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)
    filenames = [
        '/etc/nagios/nrpe.d/check_{service}_{endpoint}.cfg'.format(service=service, endpoint=endpoint)
        for service in 'keystone neutron nova placement'.split()
        for endpoint in 'admin internal public'.split()
    ]
    for filename in filenames:
        # raises exception because filename does not exist
        with pytest.raises(json.decoder.JSONDecodeError):
            await file_stat(filename, unit)


async def test_openstackservicechecks_enable_rally(deploy_app, model, file_stat):
    unit = [unit for unit in model.units.values() if unit.entity_id.startswith(deploy_app.name)]
    if len(unit) != 1:
        assert False

    unit = unit[0]
    filenames = ['/etc/cron.d/osc_rally', '/etc/nagios/nrpe.d/check_rally.cfg']

    # disable rally nrpe check if it was enabled (ie. from a previous run of functests)
    config = await deploy_app.get_config()
    if config['check-rally']['value']:
        await deploy_app.set_config({'check-rally': 'false'})
        # Wait until nrpe check is set
        await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                                timeout=600)

    # Check BEFORE enabling check-rally
    for filename in filenames:
        # raises exception because filename does not exist
        with pytest.raises(json.decoder.JSONDecodeError):
            await file_stat(filename, unit)

    await deploy_app.set_config({'check-rally': 'true'})
    # Wait until nrpe check is set
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)

    # Check AFTER enabling check-rally
    for filename in filenames:
        test_stat = await file_stat(filename, unit)
        assert test_stat['size'] > 0
