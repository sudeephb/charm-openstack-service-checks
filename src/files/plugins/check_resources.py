#!/usr/bin/env python3

# Copyright (C) 2022 Canonical Ltd.

# Authors:
#   Robert Gildein <robert.gildein@canonical.com>
"""Define nagios checks for OpenStack resources."""
import argparse
import logging
import os
import subprocess
from typing import List

from nagios_plugin3 import CriticalError, UnknownError, WarnError, try_check

import openstack


APP = os.path.splitext(os.path.basename(__file__))[0]
logger = logging.getLogger(name=APP)

OK_MESSAGE = "{}/{} passed"
SKIP_MESSAGE = "{} skipped"
WARNING_MESSAGE = "{}/{} in UNKNOWN"
DOWN_MESSAGE = "{}/{} are DOWN"
NOT_FOUND_MESSAGE = "{}/{} were not found"
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
# NOTE (rgildein): If there is any change in this list or the list below, it is
# necessary to modify lists in lib_openstack_service_checks.OSCHelper.render_checks
RESOURCES = {
    "network": lambda conn: conn.network.networks(),
    "floating-ip": lambda conn: conn.network.ips(),
    "server": lambda conn: conn.compute.servers(),
    "port": lambda conn: conn.network.ports(),
    "security-group": lambda conn: conn.network.security_groups(),
    "subnet": lambda conn: conn.network.subnets(),
}
PORT_RESOURCES = {
    "network:dhcp": lambda conn: conn.network.ports(device_owner="network:dhcp"),
    "network:distributed": lambda conn: conn.network.ports(
        device_owner="network:distributed"
    ),
}
RESOURCES_BY_EXISTENCE = ["security-group", "subnet", "network"]


class Results:
    """Object to gather all results."""

    def __init__(self):
        """Set initial values."""
        self.exit_code = 0
        self.ok = []
        self.warning = []
        self.critical = []
        self.not_found = []
        self.skipped = []
        self._messages = []

    @property
    def messages(self):
        return [message for _, message in sorted(self._messages, reverse=True)]

    @property
    def count(self):
        return len(self._messages)

    def add_result(self, type_, id_, status=None, exists=True, skip=False):
        if status == "ACTIVE":
            self.ok.append(id_)
            exit_code = NAGIOS_STATUS_OK
            message = "{} '{}' is in {} status".format(type_, id_, status)
        elif status == "DOWN":
            self.critical.append(id_)
            exit_code = NAGIOS_STATUS_CRITICAL
            message = "{} '{}' is in {} status".format(type_, id_, status)
        elif not status and exists and type_ in RESOURCES_BY_EXISTENCE:
            self.ok.append(id_)
            exit_code = NAGIOS_STATUS_OK
            message = "{} '{}' exists".format(type_, id_)
        elif not exists:
            self.not_found.append(id_)
            exit_code = NAGIOS_STATUS_CRITICAL
            message = "{} '{}' was not found".format(type_, id_)
        elif skip:
            self.skipped.append(id_)
            exit_code = NAGIOS_STATUS_OK
            message = "{} '{}' skip".format(type_, id_)
        else:
            self.warning.append(id_)
            exit_code = NAGIOS_STATUS_WARNING
            message = "{} '{}' is in {} status".format(type_, id_, status)

        self.exit_code = max(exit_code, self.exit_code)
        self._messages.append((exit_code, message))
        logger.debug("result was added with (%s, %s)", exit_code, message)


def _resource_filter(resources, ids, skip, check_all, select):
    """Apply `--skip` and `--select` parameter to resources.

    :param resources: OpenStack resource, e.g. network, port, ...
    :type: Generator
    :param ids: OpenStack resource IDs that will be checked
    :type ids: Set[str]
    :param skip: OpenStack resource IDs that will be skipped
    :type skip: Optional[Set[str]]
    :param select: values for OpenStack resources filtering
    :type select: Dict[str, str]
    :param check_all: flag to checking all OpenStack resources
    :type check_all: bool
    :returns: A generator of OpenStack objects
    :rtype: Generator
    """
    skip = skip or {}

    for resource in resources:
        if not check_all and resource.id not in ids:
            logger.debug("`%s` resource will not be checked", resource.id)
            continue
        elif resource.id in skip:
            logger.debug("`%s` resource will be skipped", resource.id)
            continue
        elif check_all:
            # applied select option to filter
            for key, value in (select or {}).items():
                if getattr(resource, key, None) != value:
                    logger.debug("`%s` resource will be skipped", resource.id)
                    continue

        yield resource


def parse_arguments():
    """Parse the check arguments and connect to OpenStack.

    :returns: resource name, set IDs, set IDs to skip,
              values to filter when using `--all` and check all flag
    :rtype: Tuple[str, set, set, dict, bool]
    """
    parser = argparse.ArgumentParser("check_resources")
    parser.add_argument("resource", type=str, help="resource type")
    parser.add_argument("--all", action="store_true", help="check all")
    parser.add_argument(
        "-i",
        "--id",
        action="append",
        type=str,
        default=[],
        help="check specific id (can be used multiple times)",
    )
    parser.add_argument(
        "--skip-id",
        action="append",
        type=str,
        default=[],
        help="skip specific id (can be used multiple times)",
    )
    parser.add_argument(
        "--select",
        action="append",
        type=str,
        default=[],
        help="use `--select` together with `--all`" "(e.g. --select subnet=<id>)",
    )
    parser.add_argument(
        "--env",
        default="/var/lib/nagios/nagios.novarc",
        help="Novarc file to use for this check",
    )
    args = parser.parse_args()

    if args.resource not in RESOURCES:
        parser.error("'{}' resource is not supported".format(args.resource))

    if args.all and args.resource in RESOURCES_BY_EXISTENCE:
        parser.error(
            "flag '--all' is not supported with " "resource {}".format(args.resource)
        )
    if args.all and args.id:
        parser.error("--all/--id' are mutually exclusive")
    elif not args.all and not args.id:
        parser.error("at least one of --all/--id' parameters must be entered")
    elif not args.all and args.skip_id:
        parser.error("'--skip-id' must be used with '--all'")
    elif not args.all and args.select:
        parser.error("'--select' must be used with '--all'")

    return args


def _create_title(resource, results):
    """Get output title."""
    titles = []

    if results.not_found:
        titles.append(NOT_FOUND_MESSAGE.format(len(results.not_found), results.count))

    if results.critical:
        titles.append(DOWN_MESSAGE.format(len(results.critical), results.count))

    if results.warning:
        titles.append(WARNING_MESSAGE.format(len(results.warning), results.count))

    if results.ok:
        titles.append(
            OK_MESSAGE.format(len(results.ok), results.count - len(results.skipped))
        )
        if len(results.skipped) > 0:
            titles.append(SKIP_MESSAGE.format(len(results.skipped)))

    return "{}s {}".format(resource, ", ".join(titles))


def nagios_output(resource, results):
    """Convert checks results to nagios format."""
    messages = os.linesep.join(results.messages)
    title = _create_title(resource, results)
    output = "{}{}{}".format(title, os.linesep, messages)

    # all checks passed
    if results.exit_code == NAGIOS_STATUS_OK:
        print("OK: ", output)
    # some checks with WARNING ERROR
    elif results.exit_code == NAGIOS_STATUS_WARNING:
        raise WarnError("WARNING: {}".format(output))
    # some checks with CRITICAL ERROR
    elif results.exit_code == NAGIOS_STATUS_CRITICAL:
        raise CriticalError("CRITICAL: {}".format(output))
    # some checks with UNKNOWN ERROR
    elif results.exit_code == NAGIOS_STATUS_UNKNOWN:
        raise UnknownError("UNKNOWN: {}".format(output))
    # raise UnknownError if for not valid exit_code
    else:
        raise UnknownError(
            "UNKNOWN: not valid exit_code {} {}" "".format(results.exit_code, output)
        )


def set_openstack_credentials(novarc):
    """Set openstack credentials by sourcing novarc file and environment variables."""
    command = ["/bin/bash", "-c", "source {} && env".format(novarc)]
    logger.debug("loading envvars from %s", novarc)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        os.environ[key.decode("utf-8")] = value.rstrip().decode("utf-8")

    proc.communicate()


def mechanism_skip_ids(connection, resource_type) -> List[str]:
    """Return list of openstack resource IDs.which will be skipped.

    The IDs are skipped due to OpenStack mechanism.
    """
    skip_ids = []
    if resource_type == "port":
        # Skip local port which is created as Metadata Proxy Management
        # https://docs.openstack.org/networking-ovn/latest/contributor/design/metadata_api.html#metadata-proxy-management-logic  # noqa
        localport_ids = [
            port.id for port in PORT_RESOURCES["network:dhcp"](connection)
        ] + [port.id for port in PORT_RESOURCES["network:distributed"](connection)]
        skip_ids += localport_ids
    return skip_ids


def check(resource_type, ids, skip=None, select=None, check_all=False):
    """Check OpenStack resource.

    :param resource_type: OpenStack resource type
    :type resource_type: str
    :param ids: OpenStack resource IDs that will be checked
    :type ids: Set[str]
    :param skip: OpenStack resource IDs that will be skipped
    :type skip: Set[str]
    :param select: values for OpenStack resources filtering
    :type select: Dict[str, str]
    :param check_all: flag to checking all OpenStack resources
    :type check_all: bool
    :raise nagios_plugin3.UnknownError: if resource not valid status
    :raise nagios_plugin3.CriticalError: if resource not found
    :raise nagios_plugin3.CriticalError: if resource status is DOWN
    """
    results = Results()
    connection = openstack.connect(cloud="envvars")
    resources = RESOURCES[resource_type](connection)
    skip = skip or set()
    skip.update(mechanism_skip_ids(
        connection=connection,
        resource_type=resource_type,
    ))
    checked_ids = []

    for resource in _resource_filter(resources, ids, skip, check_all, select):
        checked_ids.append(resource.id)
        if resource_type not in RESOURCES_BY_EXISTENCE:
            resource_status = getattr(resource, "status", "UNKNOWN")
            results.add_result(resource_type, resource.id, resource_status)
        else:
            results.add_result(resource_type, resource.id)

    for id_ in ids:
        if id_ in skip:
            results.add_result(resource_type, id_, skip=True)
        elif id_ not in checked_ids:
            results.add_result(resource_type, id_, exists=False)

    nagios_output(resource_type, results)


def main():
    args = parse_arguments()
    set_openstack_credentials(args.env)
    try_check(
        check,
        args.resource,
        set(args.id),
        set(args.skip_id),
        dict(arg.split("=", 1) for arg in args.select),
        args.all,
    )


if __name__ == "__main__":
    main()
