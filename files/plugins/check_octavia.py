#!/usr/bin/env python3

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime, timedelta
import openstack

NAGIOS_STATUS_OK = 0
NAGIOS_STATUS_WARNING = 1
NAGIOS_STATUS_CRITICAL = 2
NAGIOS_STATUS_UNKNOWN = 3

NAGIOS_STATUS = {
    NAGIOS_STATUS_OK: 'OK',
    NAGIOS_STATUS_WARNING: 'WARNING',
    NAGIOS_STATUS_CRITICAL: 'CRITICAL',
    NAGIOS_STATUS_UNKNOWN: 'UNKNOWN',
}


def nagios_exit(status, message):
    assert status in NAGIOS_STATUS, "Invalid Nagios status code"
    # prefix status name to message
    output = '{}: {}'.format(NAGIOS_STATUS[status], message)
    print(output)  # nagios requires print to stdout, no stderr
    sys.exit(status)


def check_loadbalancers(connection):
    """check loadbalancers status."""

    lb_mgr = connection.load_balancer
    lb_all = lb_mgr.load_balancers()

    # only check enabled lbs
    lb_enabled = [lb for lb in lb_all if lb.is_admin_state_up]

    # check provisioning_status is ACTIVE for each lb
    bad_lbs = [lb for lb in lb_enabled if lb.provisioning_status != 'ACTIVE']
    if bad_lbs:
        parts = ['loadbalancer {} provisioning_status is {}'.format(
            lb.id, lb.provisioning_status) for lb in bad_lbs]
        message = ', '.join(parts)
        return NAGIOS_STATUS_CRITICAL, message

    # raise WARNING if operating_status is not ONLINE
    bad_lbs = [lb for lb in lb_enabled if lb.operating_status != 'ONLINE']
    if bad_lbs:
        parts = ['loadbalancer {} operating_status is {}'.format(
            lb.id, lb.operating_status) for lb in bad_lbs]
        message = ', '.join(parts)
        return NAGIOS_STATUS_CRITICAL, message

    net_mgr = connection.network
    # check vip port exists for each lb
    bad_lbs = []
    for lb in lb_enabled:
        try:
            net_mgr.get_port(lb.vip_port_id)
        except openstack.exceptions.NotFoundException:
            bad_lbs.append(lb)
    if bad_lbs:
        parts = ['vip port {} for loadbalancer {} not found'.format(
            lb.vip_port_id, lb.id) for lb in bad_lbs]
        message = ', '.join(parts)
        return NAGIOS_STATUS_CRITICAL, message

    # warn about disabled lbs if no other error found
    lb_disabled = [lb for lb in lb_all if not lb.is_admin_state_up]
    if lb_disabled:
        parts = ['loadbalancer {} admin_state_up is False'.format(lb.id)
                 for lb in lb_disabled]
        message = ', '.join(parts)
        return NAGIOS_STATUS_WARNING, message

    return NAGIOS_STATUS_OK, 'loadbalancers are happy'


def check_pools(connection):
    """check pools status."""
    lb_mgr = connection.load_balancer
    pools_all = lb_mgr.pools()
    pools_enabled = [pool for pool in pools_all if pool.is_admin_state_up]

    # check provisioning_status is ACTIVE for each pool
    bad_pools = [pool for pool in pools_enabled if pool.provisioning_status != 'ACTIVE']
    if bad_pools:
        parts = ['pool {} provisioning_status is {}'.format(
            pool.id, pool.provisioning_status) for pool in bad_pools]
        message = ', '.join(parts)
        return NAGIOS_STATUS_CRITICAL, message

    # raise CRITICAL if operating_status is ERROR
    bad_pools = [pool for pool in pools_enabled if pool.operating_status == 'ERROR']
    if bad_pools:
        parts = ['pool {} operating_status is {}'.format(
            pool.id, pool.operating_status) for pool in bad_pools]
        message = ', '.join(parts)
        return NAGIOS_STATUS_CRITICAL, message

    # raise WARNING if operating_status is NO_MONITOR
    bad_pools = [pool for pool in pools_enabled if pool.operating_status == 'NO_MONITOR']
    if bad_pools:
        parts = ['pool {} operating_status is {}'.format(
            pool.id, pool.operating_status) for pool in bad_pools]
        message = ', '.join(parts)
        return NAGIOS_STATUS_WARNING, message

    return NAGIOS_STATUS_OK, 'pools are happy'


def check_amphorae(connection):
    """check amphorae status."""

    lb_mgr = connection.load_balancer

    resp = lb_mgr.get('/v2/octavia/amphorae')
    # python api is not available yet, use url
    if resp.status_code != 200:
        return NAGIOS_STATUS_WARNING, 'amphorae api not working'

    data = json.loads(resp.content)
    # ouput is like {"amphorae": [{...}, {...}, ...]}
    items = data.get('amphorae', [])

    # raise CRITICAL for ERROR status
    bad_status_list = ('ERROR',)
    bad_items = [item for item in items if item['status'] in bad_status_list]
    if bad_items:
        parts = [
            'amphora {} status is {}'.format(item['id'], item['status'])
            for item in bad_items]
        message = ', '.join(parts)
        return NAGIOS_STATUS_CRITICAL, message

    # raise WARNING for these status
    bad_status_list = (
        'PENDING_CREATE', 'PENDING_UPDATE', 'PENDING_DELETE', 'BOOTING')
    bad_items = [item for item in items if item['status'] in bad_status_list]
    if bad_items:
        parts = [
            'amphora {} status is {}'.format(item['id'], item['status'])
            for item in bad_items]
        message = ', '.join(parts)
        return NAGIOS_STATUS_WARNING, message

    return NAGIOS_STATUS_OK, 'amphorae are happy'


def check_image(connection, tag, days):
    img_mgr = connection.image
    images = list(img_mgr.images(tag=tag))

    if not images:
        message = ('Octavia requires image with tag {} to create amphora, '
                   'but none exist').format(tag)
        return NAGIOS_STATUS_CRITICAL, message

    active_images = [image for image in images if image.status == 'active']
    if not active_images:
        parts = ['{}({})'.format(image.name, image.id) for image in images]
        message = ('Octavia requires image with tag {} to create amphora, '
                   'but none is active: {}').format(tag, ', '.join(parts))
        return NAGIOS_STATUS_CRITICAL, message

    # raise WARNING if image is too old
    when = (datetime.now() - timedelta(days=days)).isoformat()
    # updated_at str format: '2019-12-05T18:21:25Z'
    fresh_images = [image for image in active_images if image.updated_at > when]
    if not fresh_images:
        message = ('Octavia requires image with tag {} to create amphora, '
                   'but it is older than {} days').format(tag, days)
        return NAGIOS_STATUS_WARNING, message

    return NAGIOS_STATUS_OK, 'image is ready'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Check Octavia status',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '--env', dest='env', default='/var/lib/nagios/nagios.novarc',
        help='Novarc file to use for this check')

    check_choices = ['loadbalancers', 'amphorae', 'pools', 'image']
    parser.add_argument(
        '--check', dest='check', metavar='|'.join(check_choices),
        type=str, choices=check_choices,
        default=check_choices[0],
        help='which check to run')

    parser.add_argument(
        '--amp-image-tag', dest='amp_image_tag', default='octavia-amphora',
        help='amphora image tag for image check')

    parser.add_argument(
        '--amp-image-days', dest='amp_image_days', type=int, default=365,
        help='raise warning if amphora image is older than these days')

    args = parser.parse_args()
    # source environment vars
    command = ['/bin/bash', '-c', 'source {} && env'.format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b'=')
        os.environ[key.decode('utf-8')] = value.rstrip().decode('utf-8')
    proc.communicate()

    # use closure to make all checks have same signature
    # so we can handle them in same way
    def _check_image(connection):
        return check_image(connection, args.amp_image_tag, args.amp_image_days)

    checks = {
        'loadbalancers': check_loadbalancers,
        'amphorae': check_amphorae,
        'pools': check_pools,
        'image': _check_image,
    }

    connection = openstack.connect(cloud='envvars')
    nagios_exit(*checks[args.check](connection))
