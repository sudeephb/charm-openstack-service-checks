import asyncio
import os

import pytest

# Treat all tests as coroutines
pytestmark = pytest.mark.asyncio

SERIES = [
    'xenial',
    'bionic',
    'focal',
]
CHARM_BUILD_DIR = os.getenv('CHARM_BUILD_DIR', '.').rstrip('/')


# Custom fixtures

@pytest.fixture(scope='module', params=SERIES)
async def osc_apps(request, model):
    series = request.param
    app = model.applications.get('openstack-service-checks-{}'.format(series))
    return app


class ActionFailed(Exception):
    """Exception raised when action fails."""

    def __init__(self, action):
        """Set information about action failure in message and raise."""
        params = {key: getattr(action, key, "<not-set>")
                  for key in ['name', 'parameters', 'receiver',
                              'message', 'id', 'status',
                              'enqueued', 'started', 'completed']}
        message = ('Run of action "{name}" with parameters "{parameters}" on '
                   '"{receiver}" failed with "{message}" (id={id} '
                   'status={status} enqueued={enqueued} started={started} '
                   'completed={completed})'
                   .format(**params))
        super(ActionFailed, self).__init__(message)


class Agent:
    def __init__(self, unit):
        self.unit = unit

    async def _act(self, action, **kwargs):
        action_obj = await self.unit.run_action(action, **kwargs)
        await action_obj.wait()
        if action_obj.status != 'completed':
            raise ActionFailed(action_obj)

    def status(self, status):
        return (self.unit.workload_status == status and
                self.unit.agent_status == 'idle')

    async def pause(self):
        await self._act('pause')

    async def resume(self):
        await self._act('resume')

    async def block_until(self, lambda_f, timeout=600, wait_period=1):
        await self.unit.model.block_until(
            lambda_f, timeout=timeout, wait_period=wait_period
        )


def app_names(series=None):
    apps = {
        app: app for app in
        ['keystone', 'neutron-api', 'nova-cloud-controller',
         'percona-cluster', 'rabbitmq-server', 'nagios', 'ceph-radosgw']
    }
    if not series:
        return apps

    for app in ['openstack-service-checks', 'nrpe']:
        apps[app] = '{}-{}'.format(app, series)
    return apps


@pytest.fixture(scope='module')
async def deploy_openstack(model):
    blocking_apps = {'nova-cloud-controller', 'ceph-radosgw'}
    apps = app_names()
    active_apps = []
    is_deployed = False
    for app in apps.keys():
        if app in model.applications:
            if app not in blocking_apps:
                active_apps.append(model.applications[app])
            is_deployed = True
            continue
        app_deploy = await model.deploy('cs:{}'.format(app), series='bionic',
                                        application_name=app, num_units=1)
        if app not in blocking_apps:
            # we don't expect blocking apps to become active as we don't
            # configure them fully for this test
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
    await model.add_relation('{}:identity-service'.format(apps['ceph-radosgw']),
                             '{}:identity-service'.format(apps['keystone']))
    yield active_apps


@pytest.fixture(scope='module', params=SERIES)
async def deploy_app(request, deploy_openstack, model):
    await model.block_until(lambda: all([app.status == 'active' for app in deploy_openstack]),
                            timeout=1200)
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
    await model.add_relation(apps['nrpe'], apps['openstack-service-checks'])
    credrel = "{}:identity-credentials"
    await model.add_relation(credrel.format(apps['keystone']),
                             credrel.format(apps['openstack-service-checks']))
    notifrel = "{}:identity-notifications"
    await model.add_relation(notifrel.format(apps['keystone']),
                             notifrel.format(apps['openstack-service-checks']))
    yield osc_app


def unit_from(model, name):
    unit = [unit for unit in model.units.values() if unit.entity_id.startswith(name)]
    assert len(unit) == 1
    return unit[0]


# Tests
async def test_openstackservicechecks_deploy_openstack(deploy_openstack, model):
    await model.block_until(lambda: all([app.status == 'active' for app in deploy_openstack]),
                            timeout=1200)


async def test_openstackservicechecks_deploy(deploy_app, model):
    await model.block_until(lambda: deploy_app.status == 'active', timeout=1200)


async def test_openstackservicechecks_verify_default_nrpe_checks(deploy_app, model, file_stat):
    unit = unit_from(model, deploy_app.name)
    endpoint_checks_config = ['check_{endpoint}_urls'.format(endpoint=endpoint)
                              for endpoint in 'admin internal public'.split()]
    await deploy_app.reset_config(endpoint_checks_config)
    # Wait until nrpe checks are created
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)
    filenames = [
        '/etc/nagios/nrpe.d/check_{service}_{endpoint}.cfg'.format(service=service, endpoint=endpoint)
        for service in 'keystone neutron nova placement swift'.split()
        for endpoint in 'admin internal public'.split()
    ]
    filenames.extend([
        '/etc/nagios/nrpe.d/check_nova_services.cfg',
        '/etc/nagios/nrpe.d/check_neutron_agents.cfg',
    ])
    for filename in filenames:
        test_stat = await file_stat(filename, unit)
        assert test_stat['size'] > 0


async def test_openstackservicechecks_update_endpoint(deploy_app, model, file_stat):
    unit = unit_from(model, deploy_app.name)
    keystone = model.applications['keystone']
    assert len(keystone.units) == 1
    kst_unit = keystone.units[0]
    rgw = model.applications['ceph-radosgw']
    assert len(rgw.units) == 1
    expect_port = '8080'
    await rgw.set_config({'port': expect_port})
    await model.block_until(lambda: rgw.units[0].agent_status == 'idle',
                            timeout=600, wait_period=1)
    await model.block_until(lambda: keystone.status == 'active' and kst_unit.agent_status == 'idle',
                            timeout=600, wait_period=1)
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600, wait_period=1)
    for _ in range(10):
        # Need to retry this as endpoint update takes some time to propagate
        check_configs = []
        for endpoint in 'admin internal public'.split():
            filename = '/etc/nagios/nrpe.d/check_swift_{}.cfg'.format(endpoint)
            action = await unit.run('cat {}'.format(filename))
            result = action.results
            assert result["Code"] == "0", "Error {}: {}".format(filename, result["Stderr"])
            check_configs.append(result["Stdout"])
        if all([" -p {} ".format(expect_port) in s for s in check_configs]):
            break
        await asyncio.sleep(4)
    else:
        assert False, "Port {} not in all endpoints: {}".format(
            expect_port, check_configs)


async def test_openstackservicechecks_remove_endpoint_checks(deploy_app, model, file_stat):
    unit = unit_from(model, deploy_app.name)
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
        with pytest.raises(AssertionError):
            await file_stat(filename, unit)
    # re-enable endpoint checks
    endpoint_checks_config = ['check_{endpoint}_urls'.format(endpoint=endpoint)
                              for endpoint in 'admin internal public'.split()]
    await deploy_app.reset_config(endpoint_checks_config)
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)


async def test_openstackservicechecks_enable_rally(deploy_app, model, file_stat):
    unit = unit_from(model, deploy_app.name)
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
        with pytest.raises(AssertionError):
            await file_stat(filename, unit)

    await deploy_app.set_config({'check-rally': 'true'})
    # Wait until nrpe check is set
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)

    # Check AFTER enabling check-rally
    for filename in filenames:
        test_stat = await file_stat(filename, unit)
        assert test_stat['size'] > 0


async def test_openstackservicechecks_enable_contrail_analytics_vip(deploy_app, model, file_stat, file_contents):
    unit = unit_from(model, deploy_app.name)
    filename = '/etc/nagios/nrpe.d/check_contrail_analytics_alarms.cfg'

    # disable contrail nrpe check if it was enabled
    # (ie. from a previous run of functests)
    config = await deploy_app.get_config()
    if config['contrail_analytics_vip']['value']:
        await deploy_app.set_config({'contrail_analytics_vip': ''})
        # Wait until nrpe check is set
        await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                                timeout=600)

    # Check BEFORE enabling contrail_analytics_vip
    # raises exception because filename does not exist
    with pytest.raises(AssertionError):
        await file_stat(filename, unit)

    await deploy_app.set_config({
        'contrail_analytics_vip': '127.0.0.1',
        'contrail_ignored_alarms': 'vrouter,testable'
    })
    # Wait until nrpe check is set
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)

    # Check AFTER enabling contrail_analytics_vip
    test_stat = await file_stat(filename, unit)
    assert test_stat['size'] > 0

    # Get Contents after enabling contrail_analytics_vip
    test_content = await file_contents(filename, unit)
    assert "--ignored vrouter,testable" in test_content


async def test_openstackservicechecks_disable_check_neutron_agents(deploy_app, model, file_stat):
    unit = unit_from(model, deploy_app.name)
    filename = '/etc/nagios/nrpe.d/check_neutron_agents.cfg'

    # disable neutron_agents nrpe check if it was enabled (ie. from a previous run of functests)
    config = await deploy_app.get_config()
    if config['check-neutron-agents']['value']:
        await deploy_app.set_config({'check-neutron-agents': 'false'})
        # Wait until nrpe check is set
        await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                                timeout=600)

    # Check BEFORE enabling neutron_agents check
    # raises exception because filename does not exist
    with pytest.raises(AssertionError):
        await file_stat(filename, unit)

    await deploy_app.set_config({'check-neutron-agents': 'true'})
    # Wait until nrpe check is set
    await model.block_until(lambda: deploy_app.status == 'active' and unit.agent_status == 'idle',
                            timeout=600)

    # Check AFTER enabling neutron_agents check
    test_stat = await file_stat(filename, unit)
    assert test_stat['size'] > 0


@pytest.fixture(scope='module')
async def paused_keystone(deploy_app, deploy_openstack, model):
    await model.block_until(lambda: all([app.status == 'active' for app in deploy_openstack]),
                            timeout=1200)
    keystone = model.applications['keystone']
    agent = Agent(unit_from(model, 'keystone'))

    # get default port
    kst_cfg = await keystone.get_config()
    default_port = kst_cfg['service-port'].get('value') or kst_cfg['service-port'].get('default')
    new_svc_port = int(default_port) + 1

    # adjust keystone config service-port
    await keystone.set_config({'service-port': str(new_svc_port)})
    await agent.block_until(lambda: agent.status('active'))

    # pause keystone
    await agent.pause()
    await agent.block_until(lambda: agent.status('maintenance'))

    yield keystone

    # resume keystone
    await agent.resume()
    await agent.block_until(lambda: agent.status('active'))

    # restore service-port
    await keystone.set_config({'service-port': str(default_port)})
    await agent.block_until(lambda: agent.status('active'))


@pytest.mark.usefixtures("paused_keystone")
async def test_openstackservicechecks_invalid_keystone_workload_status(model, deploy_app):
    agent = Agent(unit_from(model, deploy_app.name))

    # Wait for osc app to block with expected workload-status
    await agent.block_until(lambda: agent.status('blocked'))
    assert agent.unit.workload_status_message == \
        'Keystone server error was encountered trying to list keystone ' \
        'resources. Check keystone server health. View juju logs for more info.'
