#!/usr/bin/env python3
"""Detect VM allocation discrepancies between Nova and Placement services."""

import argparse
import json
import os
import re
import subprocess
from collections import defaultdict, namedtuple

import openstack

import os_client_config


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

DEFAULT_IGNORED = r""

ALLOCATIONS_PATH = "/resource_providers/{}/allocations"

OUTPUT_FILE = "/var/lib/nagios/allocations.out"

Alarm = namedtuple("Alarm", "lvl, desc")


def get_nova_instances(connection):
    """Return UUIDs of instances assigned to nova hypervisor."""
    compute = connection.compute
    instances = []
    for vm in compute.servers(details=True, all_projects=True):
        instances.append(vm)
    return instances


def get_resource_providers(placement_client):
    resp = placement_client.get("/resource_providers")
    resp_json = json.loads(resp.content)["resource_providers"]
    resource_providers = []
    for rp in resp_json:
        resource_providers.append({"name": rp["name"], "uuid": rp["uuid"]})
    return resource_providers


def get_placement_instances(placement_client, rp_uuid):
    """Return UUIDs of instances that have allocations against host in Placement."""
    resp = placement_client.get(ALLOCATIONS_PATH.format(rp_uuid))
    resp_json = json.loads(resp.content)
    instances = set(list(resp_json["allocations"].keys()))
    return instances


def get_instances(connection, placement_client):
    """Generate mapping of instances to hosts in Nova and Placement APIs."""
    nova_instances = {}
    placement_instances = {}

    instances = defaultdict(dict)

    # get assigned compute hosts from nova
    nova_instances = get_nova_instances(connection)
    for vm in nova_instances:
        if vm.compute_host is not None:
            if "nova" not in instances[vm.id]:
                instances[vm.id]["nova"] = set()
            instances[vm.id]["nova"].add(vm.compute_host)

    # get allocation data from placement
    resource_providers = get_resource_providers(placement_client)
    for rp in resource_providers:
        placement_instances[rp["name"]] = get_placement_instances(
            placement_client, rp["uuid"]
        )

        for uuid in placement_instances[rp["name"]]:
            if "placement" not in instances[uuid]:
                instances[uuid]["placement"] = set()
            instances[uuid]["placement"].add(rp["name"])

    return instances


def check_allocations(connection, placement_client):
    """Detect inconsistencies between Nova and Placement APIs.

    Collect data about OpenStack instances host assignment and report any
    inconsistencies between Nova and Placement APIs.
    """
    instances = get_instances(connection, placement_client)

    alerts = []

    for uuid, mapping in instances.items():
        nova_hosts = mapping.get("nova", set())
        placement_hosts = mapping.get("placement", set())

        if len(nova_hosts) == 0:
            # NOTE: In this scenario there are leftover entries in placement that need
            # to be cleaned up.
            alerts.append(
                (
                    NAGIOS_STATUS_WARNING,
                    "instance {} is missing in nova: placement host: {}, "
                    "clean up in placement".format(uuid, sorted(list(placement_hosts))),
                )
            )
        elif nova_hosts != placement_hosts:
            # NOTE: In case of any discrepancy between nova and placement,
            # placement needs to be updated.
            alerts.append(
                (
                    NAGIOS_STATUS_WARNING,
                    "instance {} is incorrect in placement: placement host: {}, "
                    "nova host: {}".format(
                        uuid, sorted(list(placement_hosts)), sorted(list(nova_hosts))
                    ),
                )
            )
        # Note: Consider comparing against libvirt hosts to determine where the VM
        # actually runs and to report duplicates

    return alerts


def filter_checks(alarms, ignored=DEFAULT_IGNORED):
    """Reduce results down to an overall check based on the highest level not ignored.

    :param List[Dict] alarms: list of alarms (lvl, message)
    :param str ignored:       regular expression of messages to ignore
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


def save_status(status, message):
    saved_state = {
        "status": status,
        "message": message,
    }
    with open(OUTPUT_FILE, "w") as fd:
        fd.write("{}\n".format(json.dumps(saved_state)))


def main():
    parser = argparse.ArgumentParser(
        description="Check allocations in Nova and Placement"
    )
    parser.add_argument(
        "--env",
        dest="env",
        default="/var/lib/nagios/nagios.novarc",
        help="Novarc file to use for this check",
    )
    parser.add_argument(
        "--ignored",
        dest="ignored",
        default="",
        help="Comma separated UUIDs of ignored instances",
    )
    args = parser.parse_args()

    # grab environment vars
    command = ["/bin/bash", "-c", "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        os.environ[key.decode("utf-8")] = value.rstrip().decode("utf-8")
    proc.communicate()

    connection = openstack.connect(cloud="envvars")
    placement_client = os_client_config.make_rest_client("placement", cloud="envvars")

    alerts = check_allocations(connection, placement_client)
    status, message = nagios_exit(args, alerts)
    save_status(status, message)


if __name__ == "__main__":
    main()
