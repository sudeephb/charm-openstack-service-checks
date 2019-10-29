#!/usr/bin/env python3

import argparse
import os
import os_client_config
import requests
import subprocess
import sys

NAGIOS_OK = 0
NAGIOS_WARNING = 1
NAGIOS_CRITICAL = 2


def check_contrail_alarms(vip, token):
    """
    Check the alarms in Contrail.
    @param str vip: VIP of Contrail
    @param str token: Token for the authentication
    @returns: None
    """
    url = 'http://{}:8081/analytics/alarms'.format(vip)
    headers = {
        'X-Auth-Token': token
    }
    r = requests.get(url=url, headers=headers)
    result = r.json()
    print(result)
    if result:
        return NAGIOS_CRITICAL
    return NAGIOS_OK


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check Contrail alarms')
    parser.add_argument('--env', dest='env',
                        default='/var/lib/nagios/nagios.novarc',
                        help='Novarc file to use for this check')
    args = parser.parse_args()
    # grab environment vars
    command = ['/bin/bash', '-c', "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b'=')
        os.environ[key.decode('utf-8')] = value.rstrip().decode('utf-8')
    proc.communicate()

    vip = os.environ['OS_CONTRAIL_ANALYTICS_VIP']
    kst = os_client_config.session_client('identity', cloud='envvars')
    token = kst.get_token()
    sys.exit(check_contrail_alarms(vip, token))
