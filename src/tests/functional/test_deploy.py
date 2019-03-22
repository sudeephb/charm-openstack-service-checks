import os
import pytest
import collections

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


def app_names(series):
    apps_list = ('keystone neutron-api nova-cloud-controller percona-cluster rabbitmq-server'
                 ' openstack-service-checks nagios nrpe').split()
    apps = dict([(app, '{}-{}'.format(app, series)) for app in apps_list])
    return apps


@pytest.fixture(scope='module', params=SERIES)
async def deploy_openstack(request, model):
    series = request.param
    nunits = collections.defaultdict(lambda: 1)
    apps = app_names(series)
    active_apps = []
    for app in apps:
        if app == 'openstack-service-checks':
            continue
        if app == 'nrpe':
            nunits[app] = 0
        app_deploy = await model.deploy('cs:{}'.format(app), series=series,
                                        application_name=apps[app], num_units=nunits[app])
        if app not in ('nova-cloud-controller', 'nrpe'):
            active_apps.append(app_deploy)

    await model.add_relation('{}:shared-db'.format(apps['keystone']),
                             '{}:shared-db'.format(apps['percona-cluster']))
    await model.add_relation('{}:monitors'.format(apps['nrpe']),
                             '{}:monitors'.format(apps['nagios']))

    for app in 'neutron-api nova-cloud-controller'.split():
        if app == 'openstack-service-checks':
            continue

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
    osc_app = await model.deploy(os.path.join(CHARM_BUILD_DIR, 'openstack-service-checks'),
                                 series=series, application_name=apps['openstack-service-checks'])

    for app in 'keystone nrpe'.split():
        await model.add_relation(apps[app], apps['openstack-service-checks'])

    yield osc_app


# Tests

async def test_openstackservicechecks_deploy_openstack(deploy_openstack, model):
    await model.block_until(lambda: all([app.status == 'active' for app in deploy_openstack]),
                            timeout=900)


async def test_openstackservicechecks_deploy(deploy_app, model):
    await model.block_until(lambda: deploy_app.status == 'active', timeout=300)
