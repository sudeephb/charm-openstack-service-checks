#!/usr/bin/env python3

import argparse
import collections
import datetime
import ipaddress
import os
import os_client_config
import re
import requests
import subprocess

import nagios_plugin3

DEFAULT_IGNORED = r""
Alarm = collections.namedtuple("Alarm", "ts, desc")


def parse_contrail_alarms(data, ignored=DEFAULT_IGNORED):
    """Validate output data from Contrail Analytics Alarms section.

    :param dict data: Alert data from Contrail API
    :param str ignored: regular expression of alerts to ignore
    :returns: str

    The returned str shows a summary in the first line (as it will be displayed
    in Nagios alerts). The rest of lines are sorted by timetamp (ts).
    """
    # If ack=False is found, crit_counter+=1; else, return WARNING
    msgs = collections.defaultdict(lambda: [])
    for node_type in data.keys():
        # node_type: analytics-node, database-node, vrouter, ...
        for item in data[node_type]:
            # KVM, LXD or physical node hostname
            hostname = item["name"]
            # timestamp = item["value"]["UVEAlarms"]["__T"] / 1e6
            for alarm in item["value"]["UVEAlarms"]["alarms"]:
                ack = alarm["ack"]
                alarm_info = {
                    "hostname": hostname,
                    "nagios_status": "WARNING",
                    "desc": alarm["description"],
                    "sev": alarm["severity"],
                    "ts": datetime.datetime.utcfromtimestamp(alarm["timestamp"] / 1e6),
                    "type": alarm["type"],
                }
                if not ack:
                    alarm_info["nagios_status"] = "CRITICAL"

                alarm_event = (
                    "{nagios_status}: {node_type}{{{hostname}, sev={sev}, "
                    "ts[{ts}]}} {desc}".format(node_type=node_type, **alarm_info)
                )
                msgs[alarm["timestamp"]].append(alarm_event)

    # msgs is a dict keyed on integer timestamp
    # whose values are lists of strings representing the alerts
    search_re = re.compile(ignored)
    full = [Alarm(ts, alert) for ts, alerts in msgs.items() for alert in alerts]
    ignoring = list(filter(lambda m: search_re.search(m.desc), full)) if ignored else []
    important = set(full) - set(ignoring)

    total_crit_count = len([a for a in full if a.desc.startswith("CRITICAL")])
    important_crit = len([a for a in important if a.desc.startswith("CRITICAL")])
    important_count = len(important)
    if important_crit > 0:
        msg = "CRITICAL: "
    elif important_count > 0:
        msg = "WARNING: "
    else:
        msg = "OK: "
    msg += (
        "total_alarms[{}], unacked_or_sev_gt_0[{}], total_ignored[{}], "
        "ignoring r'{}'\n".format(len(full), total_crit_count, len(ignoring), ignored)
    )
    msg += "\n".join(_.desc for _ in sorted(important))
    return msg


def check_contrail_alarms(contrail_vip, token, **kwargs):
    """Check the alarms in Contrail Analytics.

    :param str contrail_vip: VIP of Contrail
    :param str token: Token for the authentication
    :param kwargs: arguments passed to parse_contrail_alarms

    :returns: None
    """
    url = "http://{}:8081/analytics/alarms".format(contrail_vip)
    headers = {"X-Auth-Token": token}
    try:
        r = requests.get(url=url, headers=headers)
    except requests.exceptions.ConnectionError as error:
        raise nagios_plugin3.CriticalError(
            "CRITICAL: contrail analytics API error: {}".format(error)
        )

    if r.status_code != 200:
        raise nagios_plugin3.CriticalError(
            "CRITICAL: contrail analytics API return code is {}".format(r.status_code)
        )

    result = r.json()
    msg = parse_contrail_alarms(result, **kwargs)

    if msg.startswith("CRITICAL: "):
        raise nagios_plugin3.CriticalError(msg)
    elif msg.startswith("WARNING: "):
        raise nagios_plugin3.WarnError(msg)
    print(msg)


def load_os_envvars(args):
    # grab environment vars
    command = ["/bin/bash", "-c", "source {} && env".format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        os.environ[key.decode("utf-8")] = value.rstrip().decode("utf-8")
    proc.communicate()


def validate_ipv4(ipv4_addr):
    try:
        ipaddress.IPv4Address(ipv4_addr)
    except ipaddress.AddressValueError:
        raise nagios_plugin3.UnknownError(
            "UNKNOWN: invalid contrail IPv4 address {}".format(ipv4_addr)
        )


def main():
    parser = argparse.ArgumentParser(description="Check Contrail alarms")
    parser.add_argument(
        "--env",
        dest="env",
        default="/var/lib/nagios/nagios.novarc",
        help="Novarc file to use for this check",
    )
    parser.add_argument(
        "--host", "-H", dest="host", nargs=1, help="Contrail Analytics Virtual IP"
    )
    parser.add_argument(
        "--ignored",
        dest="ignored",
        type=str,
        default=DEFAULT_IGNORED,
        help="Comma separated list of alerts to ignore",
    )
    args = parser.parse_args()

    # Validate Contrail Analytics IP
    contrail_analytics_vip = None
    if isinstance(args.host, list):
        contrail_analytics_vip = args.host[0]
    nagios_plugin3.try_check(validate_ipv4, contrail_analytics_vip)

    # parse ignored list
    unique = sorted(set(args.ignored.split(",")))
    ignored_re = r"|".join("(?:{})".format(_) for _ in unique)

    # Retrieve token from Keystone
    load_os_envvars(args)
    keystone_client = os_client_config.session_client("identity", cloud="envvars")
    token = keystone_client.get_token()

    nagios_plugin3.try_check(
        check_contrail_alarms, contrail_analytics_vip, token, ignored=ignored_re
    )


if __name__ == "__main__":
    main()
