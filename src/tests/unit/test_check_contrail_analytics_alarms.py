import json
from os.path import abspath, dirname, join

import check_contrail_analytics_alarms

TEST_DIR = dirname(abspath(__file__))


def test_parse_contrail_alarms():
    with open(join(TEST_DIR, 'contrail_alert_data.json')) as f:
        data = json.load(f)
    parsed = check_contrail_analytics_alarms.parse_contrail_alarms(data)
    assert parsed in """
CRITICAL: total_alarms[11], unacked_or_sev_gt_0[10], total_ignored[0], ignoring r''
CRITICAL: vrouter{compute-10.maas, sev=1, ts[2020-06-25 18:29:23.149146]} Vrouter interface(s) down.
WARNING: control-node{control-8-contrail-rmq, sev=0, ts[2020-06-25 18:29:23.684803]} Node Failure. NodeStatus UVE not present.
CRITICAL: vrouter{compute-6.maas, sev=1, ts[2020-06-25 18:29:23.782174]} Vrouter interface(s) down.
CRITICAL: control-node{control-9-contrail-rmq, sev=0, ts[2020-06-25 18:29:23.786583]} Node Failure. NodeStatus UVE not present.
CRITICAL: vrouter{compute-2.maas, sev=1, ts[2020-06-25 18:29:24.142722]} Vrouter interface(s) down.
CRITICAL: control-node{control-8.maas, sev=1, ts[2020-06-25 18:29:24.293341]} BGP peer mismatch. Not enough BGP peers are up.
CRITICAL: control-node{control-7-contrail-rmq, sev=1, ts[2020-06-25 18:29:24.377040]} BGP peer mismatch. Not enough BGP peers are up.
CRITICAL: control-node{control-9.maas, sev=1, ts[2020-06-25 18:29:25.183842]} BGP peer mismatch. Not enough BGP peers are up.
CRITICAL: vrouter{compute-3.maas, sev=1, ts[2020-06-26 12:20:58.955855]} Vrouter interface(s) down.
CRITICAL: vrouter{compute-1.maas, sev=1, ts[2020-06-29 13:01:53.459050]} Vrouter interface(s) down.
CRITICAL: vrouter{compute-7.maas, sev=1, ts[2020-07-03 18:30:32.481386]} Vrouter interface(s) down.
""" # noqa: ignore=F501


def test_parse_contrail_alarms_filter_vrouter_control_9():
    with open(join(TEST_DIR, 'contrail_alert_data.json')) as f:
        data = json.load(f)
    ignored_re = r'(?:vrouter)|(?:control-9)'
    parsed = check_contrail_analytics_alarms.parse_contrail_alarms(data, ignored=ignored_re)
    assert parsed in """ 
CRITICAL: total_alarms[11], unacked_or_sev_gt_0[10], total_ignored[8], ignoring r'(?:vrouter)|(?:control-9)'
WARNING: control-node{control-8-contrail-rmq, sev=0, ts[2020-06-25 18:29:23.684803]} Node Failure. NodeStatus UVE not present.
CRITICAL: control-node{control-8.maas, sev=1, ts[2020-06-25 18:29:24.293341]} BGP peer mismatch. Not enough BGP peers are up.
CRITICAL: control-node{control-7-contrail-rmq, sev=1, ts[2020-06-25 18:29:24.377040]} BGP peer mismatch. Not enough BGP peers are up.
""" # noqa: ignore=F501


def test_parse_contrail_alarms_filter_critical():
    with open(join(TEST_DIR, 'contrail_alert_data.json')) as f:
        data = json.load(f)
    ignored_re = r'(?:CRITICAL)'
    parsed = check_contrail_analytics_alarms.parse_contrail_alarms(data, ignored=ignored_re)
    assert parsed in """
WARNING: total_alarms[11], unacked_or_sev_gt_0[10], total_ignored[10], ignoring r'(?:CRITICAL)'
WARNING: control-node{control-8-contrail-rmq, sev=0, ts[2020-06-25 18:29:23.684803]} Node Failure. NodeStatus UVE not present.
""" # noqa: ignore=F501


def test_parse_contrail_alarms_all_ignored():
    with open(join(TEST_DIR, 'contrail_alert_data.json')) as f:
        data = json.load(f)
    ignored_re = r'(?:CRITICAL)|(?:WARNING)'
    parsed = check_contrail_analytics_alarms.parse_contrail_alarms(data, ignored=ignored_re)
    assert parsed in """
OK: total_alarms[11], unacked_or_sev_gt_0[10], total_ignored[11], ignoring r'(?:CRITICAL)|(?:WARNING)'
""" # noqa: ignore=F501


def test_parse_contrail_alarms_no_alarms():
    ignored_re = r''
    parsed = check_contrail_analytics_alarms.parse_contrail_alarms({}, ignored=ignored_re)
    assert parsed in """
OK: total_alarms[0], unacked_or_sev_gt_0[0], total_ignored[0], ignoring r''
"""
