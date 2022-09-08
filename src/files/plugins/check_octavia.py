#!/usr/bin/env python3
"""Define nagios checks for octavia services."""

import argparse
import collections
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta

import openstack


Alarm = collections.namedtuple("Alarm", "lvl, desc")
DEFAULT_IGNORED = r""
NAGIOS_STATUS_OK = 0
NAGIOS_STATUS_WARNING = 1
NAGIOS_STATUS_CRITICAL = 2
NAGIOS_STATUS_UNKNOWN = 3

NAGIOS_STATUS = {
    NAGIOS_STATUS_OK: "OK",
    NAGIOS_STATUS_WARNING: "WARNING",
    NAGIOS_STATUS_CRITICAL: "CRITICAL",
    NAGIOS_STATUS_UNKNOWN: "UNKNOWN",
}


def filter_checks(alarms, ignored=DEFAULT_IGNORED):
    """Reduce results down to an overall check based on the highest level not ignored.

    :param List[Tuple] alarms: list of alarms (lvl, message)
    :param str ignored:        regular expression of messages to ignore
    :return:
    """
    search_re = re.compile(ignored)
    full = [Alarm(lvl, msg) for lvl, msg in alarms]
    ignoring = list(filter(lambda m: search_re.search(m.desc), full)) if ignored else []
    important = set(full) - set(ignoring)

    total_crit = len([a for a in full if a.lvl == NAGIOS_STATUS_CRITICAL])
    important_crit = len([a for a in important if a.lvl == NAGIOS_STATUS_CRITICAL])
    important_count = len(important)
    if important_crit > 0:
        status = NAGIOS_STATUS_CRITICAL
    elif important_count > 0:
        status = NAGIOS_STATUS_WARNING
    else:
        status = NAGIOS_STATUS_OK
    msg = (
        "total_alarms[{}], total_crit[{}], total_ignored[{}], "
        "ignoring r'{}'\n".format(len(full), total_crit, len(ignoring), ignored)
    )
    msg += "\n".join(_.desc for _ in sorted(important))
    return status, msg


def nagios_exit(args, results):
    """Filter ignored checks and ensure proper nagios check return code."""
    unique = sorted(filter(None, set(args.ignored.split(","))))
    ignored_re = r"|".join("(?:{})".format(_) for _ in unique)

    status, message = filter_checks(results, ignored=ignored_re)
    assert status in NAGIOS_STATUS, "Invalid Nagios status code"
    # prefix status name to message
    output = "{}: {}".format(NAGIOS_STATUS[status], message)
    return status, output


def has_lb_health_monitors(connection, lb):
    """Check if a loadbalancer has associated health monitors."""
    lb_mgr = connection.load_balancer
    pools = lb_mgr.pools(loadbalancer_id=lb.id)
    for pool in pools:
        if pool.health_monitor_id is not None:
            return True
    return False


def is_loadbalancer_operating_status_ok(connection, lb):
    """Check if loadbalancer operating status is OK."""
    if lb.operating_status in ["ONLINE", "DRAINING", "NO_MONITOR"]:
        return True
    if lb.operating_status == "OFFLINE" and not has_lb_health_monitors(connection, lb):
        # this is because of LP#1678330
        return True
    return False


def check_loadbalancers(connection):
    """Check loadbalancers status."""
    lb_mgr = connection.load_balancer
    lb_all = lb_mgr.load_balancers()

    # only check enabled lbs
    lb_enabled = [lb for lb in lb_all if lb.is_admin_state_up]

    # check provisioning_status is ACTIVE for each lb
    bad_lbs = [
        (
            NAGIOS_STATUS_CRITICAL,
            "loadbalancer {} provisioning_status is {}".format(
                lb.id, lb.provisioning_status
            ),
        )
        for lb in lb_enabled
        if lb.provisioning_status != "ACTIVE"
    ]

    # raise WARNING if operating_status is not ONLINE
    bad_lbs += [
        (
            NAGIOS_STATUS_CRITICAL,
            "loadbalancer {} operating_status is {}".format(lb.id, lb.operating_status),
        )
        for lb in lb_enabled
        if not is_loadbalancer_operating_status_ok(connection, lb)
    ]

    # check vip port exists for each lb
    net_mgr = connection.network
    vip_lbs = []
    for lb in lb_enabled:
        try:
            net_mgr.get_port(lb.vip_port_id)
        except openstack.exceptions.NotFoundException:
            vip_lbs.append(lb)
    bad_lbs += [
        (
            NAGIOS_STATUS_CRITICAL,
            "vip port {} for loadbalancer {} not found".format(lb.vip_port_id, lb.id),
        )
        for lb in vip_lbs
    ]

    # warn about disabled lbs if no other error found
    bad_lbs += [
        (NAGIOS_STATUS_WARNING, "loadbalancer {} admin_state_up is False".format(lb.id))
        for lb in lb_all
        if not lb.is_admin_state_up
    ]

    return bad_lbs


def check_pools(connection):
    """Check pools status."""
    lb_mgr = connection.load_balancer
    pools_all = lb_mgr.pools()

    # only check enabled pools
    pools_enabled = [pool for pool in pools_all if pool.is_admin_state_up]

    # check provisioning_status is ACTIVE for each pool
    bad_pools = [
        (
            NAGIOS_STATUS_CRITICAL,
            "pool {} provisioning_status is {}".format(
                pool.id, pool.provisioning_status
            ),
        )
        for pool in pools_enabled
        if pool.provisioning_status != "ACTIVE"
    ]

    # raise CRITICAL if operating_status is ERROR
    bad_pools += [
        (
            NAGIOS_STATUS_CRITICAL,
            "pool {} operating_status is {}".format(pool.id, pool.operating_status),
        )
        for pool in pools_enabled
        if pool.operating_status == "ERROR"
    ]

    # raise WARNING if operating_status is NO_MONITOR
    bad_pools += [
        (
            NAGIOS_STATUS_WARNING,
            "pool {} operating_status is {}".format(pool.id, pool.operating_status),
        )
        for pool in pools_enabled
        if pool.operating_status == "NO_MONITOR"
    ]

    return bad_pools


def check_image(connection, tag, days):
    """Check that there is an image with the proper octavia image tag."""
    img_mgr = connection.image
    images = list(img_mgr.images(tag=tag))

    if not images:
        message = (
            "Octavia requires image with tag {} to create amphora, but none exist"
        ).format(tag)
        return [(NAGIOS_STATUS_CRITICAL, message)]

    active_images = [image for image in images if image.status == "active"]
    if not active_images:
        details = ["{}({})".format(image.name, image.id) for image in images]
        message = (
            "Octavia requires image with tag {} to create amphora, "
            "but none are active: {}"
        ).format(tag, ", ".join(details))
        return [(NAGIOS_STATUS_CRITICAL, message)]

    # raise WARNING if image is too old
    when = (datetime.now() - timedelta(days=days)).isoformat()
    # updated_at str format: '2019-12-05T18:21:25Z'
    fresh_images = [image for image in active_images if image.updated_at > when]
    if not fresh_images:
        details = ["{}({})".format(image.name, image.id) for image in images]
        message = (
            "Octavia requires image with tag {} to create amphora, "
            "but all images are older than {} day(s): {}"
            ""
        ).format(tag, days, ", ".join(details))
        return [(NAGIOS_STATUS_WARNING, message)]

    return []


def process_checks(args):
    """Process all octavia checks in a standardized manner.

    Use closure to make all checks have same signature
    so we can handle them in same way
    """

    def _check_image(_connection):
        return check_image(_connection, args.amp_image_tag, args.amp_image_days)

    checks = {
        "loadbalancers": check_loadbalancers,
        "pools": check_pools,
        "image": _check_image,
    }

    connection = openstack.connect(cloud="envvars")
    return nagios_exit(args, checks[args.check](connection))


def main():
    """Define main routine, parse CLI args, and run checks."""
    parser = argparse.ArgumentParser(
        description="Check Octavia status",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--env",
        dest="env",
        default="/var/lib/nagios/nagios.novarc",
        help="Novarc file to use for this check",
    )

    check_choices = ["loadbalancers", "amphorae", "pools", "image"]
    parser.add_argument(
        "--check",
        dest="check",
        metavar="|".join(check_choices),
        type=str,
        choices=check_choices,
        default=check_choices[0],
        help="which check to run",
    )

    parser.add_argument(
        "--ignored",
        dest="ignored",
        type=str,
        default=DEFAULT_IGNORED,
        help="Comma separated list of alerts to ignore",
    )

    parser.add_argument(
        "--amp-image-tag",
        dest="amp_image_tag",
        default="octavia-amphora",
        help="amphora image tag for image check",
    )

    parser.add_argument(
        "--amp-image-days",
        dest="amp_image_days",
        type=int,
        default=365,
        help="raise warning if amphora image is older than these days",
    )

    args = parser.parse_args()
    # source environment vars
    command = ["/bin/bash", "-c", "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        os.environ[key.decode("utf-8")] = value.rstrip().decode("utf-8")
    proc.communicate()

    status, message = process_checks(args)
    print(message)
    sys.exit(status)


if __name__ == "__main__":
    main()
