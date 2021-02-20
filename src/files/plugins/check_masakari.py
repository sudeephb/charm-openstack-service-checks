#!/usr/bin/env python3
"""Define nagios checks for masakari services, bug #1898108 ."""
import argparse
import os
import subprocess
import sys

from keystoneauth1.exceptions.catalog import EndpointNotFound

import openstack

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


def process_checks():
    connection = openstack.connect(cloud="envvars")
    ha_mgr = connection.instance_ha
    segments = ha_mgr.segments()
    hosts_maintenance = []
    for seg in segments:
        hosts = ha_mgr.hosts(seg.uuid)
        on_maintenance = [host.uuid for host in hosts if host.on_maintenance]
        hosts_maintenance.extend(on_maintenance)

    if len(hosts_maintenance) > 0:
        message = (
            "{}: hosts {} are being on maintenance, re-enable the service per "
            "https://docs.openstack.org/project-deploy-guide/charm-deployment-"
            "guide/latest/app-masakari.html#supplementary-information "
        ).format(NAGIOS_STATUS[NAGIOS_STATUS_CRITICAL], hosts_maintenance)
        return NAGIOS_STATUS_CRITICAL, message

    return NAGIOS_STATUS_OK, NAGIOS_STATUS[NAGIOS_STATUS_OK]


def main():
    """Define main routine, parse CLI args, and run checks."""
    parser = argparse.ArgumentParser(
        description="Check masakari segment host maintenance status",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--env",
        dest="env",
        default="/var/lib/nagios/nagios.novarc",
        help="Novarc file to use for this check",
    )

    args = parser.parse_args()
    # source environment vars
    command = ["/bin/bash", "-c", "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        os.environ[key.decode("utf-8")] = value.rstrip().decode("utf-8")
    proc.communicate()
    try:
        status, message = process_checks()
    except EndpointNotFound:
        message = "Masakari is not enabled in the cloud"
        status = NAGIOS_STATUS_WARNING
    print(message)
    sys.exit(status)


if __name__ == "__main__":
    main()
