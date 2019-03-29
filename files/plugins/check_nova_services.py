#!/usr/bin/env python

import argparse
import nagios_plugin
import os
import os_client_config
import subprocess


def check_hosts_up(args, aggregate, hosts, services_compute):
    # function to check an agg
    # in: list of hosts
    # in: services_compute
    # in: args
    # out: dict, msg_text, status
    status_crit = False
    status_warn = False
    counts = {'down': 0, 'disabled': 0, 'ok': 0}
    local_msg = []
    for host in hosts:
        host_svc = (svc for svc in services_compute if svc['host'] ==
                    host).next()
        if host_svc['status'] == 'enabled':
            if host_svc['state'] not in 'up':
                # enabled and down
                counts['down'] += 1
                local_msg.append("{} down".format(host))
            else:
                # enabled and up, increment the counter
                counts['ok'] += 1
        else:
            counts['disabled'] += 1
            local_msg.append("Host {} disabled".format(host))
    # check the counts
    if counts['down'] > 0:
        status_crit = True
    if counts['disabled'] > 0 and not args.skip_disabled:
        status_warn = True
    if counts['ok'] <= args.warn:
        status_warn = True
        if counts['ok'] <= args.crit:
            status_crit = True
        local_msg.append("Host Aggregate {} has {} hosts alive".format(
            aggregate, counts['ok']))
    nova_status = {
        'agg_name': aggregate,
        'msg_text': ", ".join(local_msg),
        'critical': status_crit,
        'warning': status_warn,
    }
    return nova_status


def check_nova_services(args, nova):
    aggregates = nova.get('/os-aggregates').json()['aggregates']
    services = nova.get('/os-services').json()['services']
    services_compute = [x for x in services if x['binary'] == 'nova-compute']
    msg = ['nova-compute']
    status = []
    hosts_checked = []
    for agg in aggregates:
        # get a list of hosts, pass to the function
        hosts = agg['hosts']
        hosts_checked.append(hosts)
        status.append(check_hosts_up(args, agg['name'], hosts,
                                     services_compute))
    # find hosts that haven't been checked already
    hosts_checked = [item for sublist in hosts_checked for item in sublist]
    hosts_not_checked = [x['host'] for x in services_compute
                         if x['host'] not in hosts_checked]
    if len(hosts_not_checked) > 0:
        status.append(check_hosts_up(args, '(not-part-of-any-agg)', hosts_not_checked,
                                     services_compute))
    status_crit = len([agg['critical'] for agg in status
                       if agg['critical']])
    status_warn = len([agg['warning'] for agg in status
                       if agg['warning']])
    msg.extend([x['msg_text'] for x in status if x['msg_text'] != ''])
    if status_crit:
        output = "CRITICAL: {}".format(", ".join(msg))
        raise nagios_plugin.CriticalError(output)
    if status_warn:
        output = "WARNING: {}".format(", ".join(msg))
        raise nagios_plugin.WarnError(output)
    print("OK: Nova-compute services happy")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check Nova-compute status')
    parser.add_argument('--warn', dest='warn', type=int, default=2,
                        help="Warn at this many hosts running")
    parser.add_argument('--crit', dest='crit', type=int, default=1,
                        help="Critical at this many hosts running or less")
    parser.add_argument('--env', dest='env',
                        default='/var/lib/nagios/nagios.novarc',
                        help="Novarc file to use for this check")
    parser.add_argument('--skip-disabled', dest='skip_disabled',
                        help='Pass this flag not to alert on any disabled nova-compute services',
                        action='store_true')
    args = parser.parse_args()
    # grab environment vars
    command = ['/bin/bash', '-c', "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b'=')
        os.environ[key.decode('utf-8')] = value.rstrip().decode('utf-8')
    proc.communicate()
    nova = os_client_config.session_client('compute', cloud='envvars')
    nagios_plugin.try_check(check_nova_services, args, nova)
