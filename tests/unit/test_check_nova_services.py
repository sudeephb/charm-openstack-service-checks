import pytest
import nagios_plugin3

import check_nova_services


@pytest.mark.parametrize('is_skip_disabled,num_nodes',
                         [
                             (True, 5),
                             (False, 5),
                             (True, 2),
                             (False, 2),
                         ])
def test_check_hosts_up(is_skip_disabled, num_nodes):
    class _TestArgs(object):
        warn = 2
        crit = 1
        skip_disabled = is_skip_disabled

    args = _TestArgs()
    aggregate = '(not-part-of-any-agg)'
    services_compute = [
        {u'status': (u'disabled' if id == 0 else u'enabled'),
         u'binary': u'nova-compute',
         u'zone': u'nova',
         u'state': u'up',
         u'updated_at': u'2019-07-04T09:23:06.000000',
         u'host': u'juju-3efade-{}'.format(id),
         u'disabled_reason': None,
         u'id': id,
         }
        for id in range(num_nodes)
    ]
    hosts = [svc['host'] for svc in services_compute]

    msg_text = 'Host juju-3efade-0 disabled'
    if num_nodes <= 2:
        # 1 host enabled + 1 host disabled == 1 host alive (<=1)
        status_critical = True
        msg_text = ('{}, Host Aggregate (not-part-of-any-agg) has 1 hosts alive'
                    .format(msg_text))
    else:
        # more than args.crit (1) hosts alive (4)
        status_critical = False

    expected = {
        'agg_name': aggregate,
        'msg_text': msg_text,
        'critical': status_critical,
        'warning': not is_skip_disabled or num_nodes <= args.warn,
    }
    actual = check_nova_services.check_hosts_up(args, aggregate, hosts, services_compute)
    assert actual == expected


@pytest.mark.parametrize('is_skip_disabled', [True, False])
def test_check_nova_services(is_skip_disabled, monkeypatch):
    class _TestArgs(object):
        warn = 2
        crit = 1
        skip_disabled = is_skip_disabled

    class _TestNova(object):
        def get(cls, name):
            return _TestNovaJson()

    class _TestNovaJson(object):
        def json(cls):
            return {'aggregates': [],
                    'services': [
                        {u'status': (u'disabled' if id == 0 else u'enabled'),
                         u'binary': u'nova-compute',
                         u'zone': u'nova',
                         u'state': u'up',
                         u'updated_at': u'2019-07-04T09:23:06.000000',
                         u'host': u'juju-3efade-{}'.format(id),
                         u'disabled_reason': None,
                         u'id': id,
                         }
                        for id in range(5)]
                    }

    args = _TestArgs()
    nova = _TestNova()
    check_hosts_up_expected = {
        'agg_name': '(not-part-of-any-agg)',
        'msg_text': 'Host juju-3efade-0 disabled',
        'critical': False,
        'warning': not is_skip_disabled,
    }
    monkeypatch.setattr('check_nova_services.check_hosts_up',
                        lambda args, aggregate, hosts, svcs_compute: check_hosts_up_expected)

    if is_skip_disabled:
        assert check_nova_services.check_nova_services(args, nova) is None
    else:
        with pytest.raises(nagios_plugin3.WarnError) as excinfo:
            check_nova_services.check_nova_services(args, nova)
        assert str(excinfo.value) == 'WARNING: nova-compute, Host juju-3efade-0 disabled'
