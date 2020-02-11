#!/usr/bin/env python3

import argparse
import collections
import datetime
import ipaddress
import os
import os_client_config
import requests
import subprocess

import nagios_plugin3


def parse_contrail_alarms(data):
    """Validate output data from Contrail Analytics Alarms section.

    :param data: dict
    :returns: str

    The returned str shows a summary in the first line (as it will be displayed
    in Nagios alerts). The rest of lines are sorted by timetamp (ts).
    """
    # If ack=False is found, crit_counter+=1; else, return WARNING
    counter = crit_counter = 0
    msgs_list = collections.defaultdict(lambda: [])
    for node_type in data.keys():
        # node_type: analytics-node, database-node, vrouter, ...
        for item in data[node_type]:
            # KVM, LXD or physical node hostname
            hostname = item["name"]
            # timestamp = item["value"]["UVEAlarms"]["__T"] / 1e6
            for alarm in item["value"]["UVEAlarms"]["alarms"]:
                ack = alarm["ack"]
                alarm_info = {
                    'hostname': hostname,
                    'nagios_status': 'WARNING',
                    'desc': alarm["description"],
                    'sev': alarm["severity"],
                    'ts': datetime.datetime.utcfromtimestamp(alarm["timestamp"] / 1e6),
                    'type': alarm["type"],
                }
                counter += 1
                if not ack:
                    crit_counter += 1
                    alarm_info["nagios_status"] = 'CRITICAL'

                alarm_msg = ('{nagios_status}: {node_type}{{{hostname}, sev={sev},'
                             ' ts[{ts}]}} {desc}'.format(
                                 node_type=node_type, **alarm_info))
                msgs_list[alarm["timestamp"]].append(alarm_msg)

    if not msgs_list:
        return 'OK: no alarms'

    msg = 'CRITICAL: ' if crit_counter > 0 else 'WARNING: '
    msg += 'total_alarms[{}], unacked_or_sev_gt_0[{}]\n{}'.format(
        counter, crit_counter, '\n'.join(
            '\n'.join(msgs_list[key]) for key in sorted(msgs_list)))
    return msg


def check_contrail_alarms(contrail_vip, token):
    """Check the alarms in Contrail Analytics.

    @param str vip: VIP of Contrail
    @param str token: Token for the authentication
    @returns: None
    """
    url = 'http://{}:8081/analytics/alarms'.format(contrail_vip)
    headers = {'X-Auth-Token': token}
    try:
        r = requests.get(url=url, headers=headers)
    except requests.exceptions.ConnectionError as error:
        raise nagios_plugin3.CriticalError(
            'CRITICAL: contrail analytics API error: {}'.format(error))

    if r.status_code != 200:
        raise nagios_plugin3.CriticalError(
            'CRITICAL: contrail analytics API return code is {}'.format(r.status_code))

    result = r.json()
    msg = parse_contrail_alarms(result)

    if msg.startswith('CRITICAL: '):
        raise nagios_plugin3.CriticalError(msg)
    elif msg.startswith('WARNING: '):
        raise nagios_plugin3.WarnError(msg)
    print('OK: no unacknowledged or sev>0 contrail analytics alarms')


def load_os_envvars():
    # grab environment vars
    command = ['/bin/bash', '-c', "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b'=')
        os.environ[key.decode('utf-8')] = value.rstrip().decode('utf-8')
    proc.communicate()


def validate_ipv4(ipv4_addr):
    try:
        ipaddress.IPv4Address(ipv4_addr)
    except ipaddress.AddressValueError:
        raise nagios_plugin3.UnknownError(
            'UNKNOWN: invalid contrail IPv4 address {}'.format(ipv4_addr))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check Contrail alarms')
    parser.add_argument('--env', dest='env',
                        default='/var/lib/nagios/nagios.novarc',
                        help='Novarc file to use for this check')
    parser.add_argument('--host', '-H', dest='host', nargs=1,
                        help='Contrail Analytics Virtual IP')
    args = parser.parse_args()

    # Validate Contrail Analytics IP
    contrail_analytics_vip = None
    if isinstance(args.host, list):
        contrail_analytics_vip = args.host[0]
    nagios_plugin3.try_check(validate_ipv4, contrail_analytics_vip)

    # Retrieve token from Keystone
    load_os_envvars()
    keystone_client = os_client_config.session_client('identity', cloud='envvars')
    token = keystone_client.get_token()

    nagios_plugin3.try_check(check_contrail_alarms, contrail_analytics_vip, token)
