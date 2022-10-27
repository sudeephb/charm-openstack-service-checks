#!/usr/bin/env python3
"""Check pormetheus mysql exporter status."""

import argparse
import json
import urllib.request

import nagios_plugin3

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


def check_status(resp_dict):
    """Check attributes of services and reports issues (or OK message).

    :param dict resp_dict: Promethes Querying API V1 return data.
    :returns:
        status - NAGIOS_STATUS KEY
        msg - str
    """
    up_endpoints = {}
    not_up_endpoints = {}
    for endpoint_result in resp_dict["data"]["result"]:
        mysql_up = endpoint_result["value"][1]
        endpoint = endpoint_result["metric"]["instance"]
        if mysql_up == "1":
            up_endpoints[endpoint] = {"mysql_up": mysql_up}
        else:
            not_up_endpoints[endpoint] = {"mysql_up": mysql_up}

    if not_up_endpoints:
        msg = (
            "{}: instances {} can't get metrics."
            " Please check exporter permission and mysql status"
        ).format(
            NAGIOS_STATUS[NAGIOS_STATUS_CRITICAL], ",".join(not_up_endpoints.keys())
        )
        return NAGIOS_STATUS_CRITICAL, msg

    return NAGIOS_STATUS_OK, NAGIOS_STATUS[NAGIOS_STATUS_OK]


def check_mysql_up(args):
    params = {
        "query": "mysql_up",
    }
    query_string = urllib.parse.urlencode(params)
    url = "{}/api/v1/query?{}".format(args.address, query_string)

    with urllib.request.urlopen(url) as resp:
        resp_dict = json.loads(resp.read())
    status, msg = check_status(resp_dict)

    if status == NAGIOS_STATUS_UNKNOWN:
        raise nagios_plugin3.UnknownError(msg)
    elif status == NAGIOS_STATUS_WARNING:
        raise nagios_plugin3.WarnError(msg)
    elif status == NAGIOS_STATUS_CRITICAL:
        raise nagios_plugin3.CriticalError(msg)

    msg = NAGIOS_STATUS[NAGIOS_STATUS_OK]
    print(msg)


def main():
    parser = argparse.ArgumentParser(
        description="Check Prometheus MySQL Exporter status",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--address",
        dest="address",
        required=True,
        help="Prometheus API address",
    )

    args = parser.parse_args()
    nagios_plugin3.try_check(check_mysql_up, args)


if __name__ == "__main__":
    main()
