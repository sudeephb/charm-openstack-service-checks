#!/usr/bin/env python3

from keystoneclient.v3 import client
import argparse
import requests
import sys
import yaml

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


def get_auth_token(auth_url, user, password, project, domain):
    """
    Retrieve an OpenStack token to use to authenticate against Contrail
    @param str auth_url: Keystone authentication URL
    @param str user: OpenStack username
    @param str password: OpenStack password
    @param str project: OpenStack project
    @param str domain: OpenStack domain
    @returns: str. The token or None
    """
    keystone = client.Client(
        auth_url=auth_url,
        username=user,
        password=password,
        project_name=project,
        user_domain_name=domain,
        project_domain_name=domain
    )
    return keystone.auth_ref.get('auth_token')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check Contrail alarms')
    parser.add_argument('--env', dest='env',
                        default='/var/lib/nagios/keystone.yaml',
                        help="Credentials file to use for this check")
    args = parser.parse_args()
    env_file = args.env
    with open(env_file) as f:
        cloud = yaml.safe_load(f)
    auth_url = cloud.get('auth_url')
    user = cloud.get('user')
    password = cloud.get('password')
    project = cloud.get('project')
    domain = cloud.get('domain')
    vip = cloud.get('contrail_analytics_vip')
    token = get_auth_token(auth_url, user, password, project, domain)
    sys.exit(check_contrail_alarms(vip, token))
