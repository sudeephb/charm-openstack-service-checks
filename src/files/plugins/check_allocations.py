#!/usr/bin/env python3
"""Load saved status of the allocations check and report to Nagios."""

import json
import os
import sys

from nagios_plugin3 import (
    check_file_freshness,
    try_check,
)

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

STATUS_FILE = "/var/lib/nagios/allocations.out"


def main():
    if not os.path.exists(STATUS_FILE):
        print("UNKNOWN: {} does not exist".format(STATUS_FILE))
        sys.exit(NAGIOS_STATUS_UNKNOWN)

    try_check(check_file_freshness, STATUS_FILE)

    with open(STATUS_FILE, "r") as f:
        try:
            saved_state = json.loads(f.read())
            print(saved_state["message"])
            sys.exit(saved_state["status"])
        except json.decoder.JSONDecodeError as error:
            print("UNKNOWN: error[{}]".format(str(error)))
            sys.exit(NAGIOS_STATUS_UNKNOWN)


if __name__ == "__main__":
    main()
