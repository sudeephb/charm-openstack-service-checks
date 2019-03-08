import os
import pytest
import collections

# Treat all tests as coroutines
pytestmark = pytest.mark.asyncio

series = ['xenial', 'bionic']
charm_build_dir = os.getenv('CHARM_BUILD_DIR', '.').rstrip('/')


# Custom fixtures

@pytest.fixture
async def apps(model):
    apps = []
    for entry in series:
        app = model.applications.get('openstack-service-checks-{}'.format(entry))
        apps.append(app)
    return apps


@pytest.fixture
async def units(apps):
    units = []
    for app in apps:
        units.extend(app.units)
    return units


@pytest.mark.parametrize('series', series)
async def test_openstackservicechecks_deploy(model, series):
    apps_list = ('keystone neutron-api nova-cloud-controller percona-cluster rabbitmq-server'
                 ' openstack-service-checks nagios nrpe').split()
    apps = dict([(app, '{}-{}'.format(app, series)) for app in apps_list])

    # Starts a deploy for each series
    await model.deploy(os.path.join(charm_build_dir, 'openstack-service-checks'), series=series,
                       application_name=apps['openstack-service-checks'])

    nunits = collections.defaultdict(lambda: 1)
    for app in apps_list:
        if app == 'openstack-service-checks':
            continue
        if app == 'nrpe':
            nunits[app] = 0
        await model.deploy('cs:{}'.format(app), series=series, application_name=apps[app], num_units=nunits[app])

    for app in 'neutron-api nova-cloud-controller'.split():
        await model.add_relation('{}:amqp'.format(apps[app]),
                                 '{}:amqp'.format(apps['rabbitmq-server']))
        await model.add_relation('{}:shared-db'.format(apps[app]),
                                 '{}:shared-db'.format(apps['percona-cluster']))
        await model.add_relation('{}:identity-service'.format(apps[app]),
                                 '{}:identity-service'.format(apps['keystone']))

    await model.add_relation('{}:shared-db'.format(apps['keystone']),
                             '{}:shared-db'.format(apps['percona-cluster']))

    for app in 'keystone nrpe'.split():
        await model.add_relation(apps[app],
                                 apps['openstack-service-checks'])

    await model.add_relation('{}:monitors'.format(apps['nrpe']),
                             '{}:monitors'.format(apps['nagios']))

    #
    assert True


# Tests

async def test_openstackservicechecks_status(apps, model):
    # Verifies status for all deployed series of the charm
    for app in apps:
        await model.block_until(lambda: app.status == 'active', timeout=1200)
    assert True
