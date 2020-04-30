#!/usr/bin/env python3

import argparse
import nagios_plugin3
import os
import os_client_config
import subprocess


def check_status(service):
    """Checks attributes of services and reports issues (or OK message).

    Attributes are (among others):
        - binary: cinder-volume, cinder-scheduler
        - host: ie. juju-ba88f7-8
        - state: down, up
        - status: enabled, disabled
    """
    msg = "{}[{}]".format(service["host"], service["binary"])
    status = "OK"  # default
    if service["status"] == "disabled":
        status = "DISABLED"
    elif service["state"] == "down":
        # enabled and down
        status = "DOWN"

    return (status, msg)


def check_cinder_services(args, cinder):
    """Retrieves list of services and returns appropriate nagios return code."""
    services = cinder.get("/os-services").json()["services"]
    if not services:
        output = "UNKNOWN: No cinder services found"
        raise nagios_plugin3.UnknownError(output)

    msgs = {"DISABLED": [], "DOWN": []}
    ok = 0
    for service in services:
        status, msg = check_status(service)
        if status == "DISABLED" and args.skip_disabled:
            continue
        elif status == "OK":
            ok += 1
            continue

        msgs[status].append(msg)

    if ok == 0:
        output = "CRITICAL: No cinder services found healthy"
        raise nagios_plugin3.CriticalError(output)

    if msgs["DOWN"]:
        output = "CRITICAL: {}".format(", ".join(sorted(msgs["DOWN"])))
        if msgs["DISABLED"]:
            output += "; Disabled: {}".format(", ".join(sorted(msgs["DISABLED"])))
        raise nagios_plugin3.CriticalError(output)

    if msgs["DISABLED"]:
        output = "WARNING: Disabled: {}".format(", ".join(sorted(msgs["DISABLED"])))
        raise nagios_plugin3.WarnError(output)

    print("OK: All cinder services happy")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check Cinder status")
    parser.add_argument(
        "--env",
        dest="env",
        default="/var/lib/nagios/nagios.novarc",
        help="Novarc file to use for this check",
    )
    parser.add_argument(
        "--skip-disabled",
        dest="skip_disabled",
        help="Pass this flag not to alert on any disabled cinder service",
        action="store_true",
    )
    args = parser.parse_args()

    # grab environment vars
    command = ["/bin/bash", "-c", "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        os.environ[key.decode("utf-8")] = value.rstrip().decode("utf-8")
    proc.communicate()
    cinder = os_client_config.session_client("volume", cloud="envvars")
    nagios_plugin3.try_check(check_cinder_services, args, cinder)
