#!/usr/bin/env python3
"""Nagios NRPE check script for port security.

According to doc[0]:

    Hardware offload does not currently support offloading of Neutron Security Group rules.
    Experimental support is expected in Open vSwitch 2.13 when used with Linux >= 5.4 and
    as yet unreleased NIC firmware. It is recommended that port security is disabled on
    Neutron networks being used for hardware offloading use cases due to the performance
    overhead of enforcing security group rules in userspace.

So port security and hardware offloading can not be both enabled on a port.
We call such port a "bad port" in this context.

To prevent it, this script provides 2 working modes:

1) Auto remediation mode

When triggered with `--auto-remediation` option(e.g.: via cron job), it will look for
bad ports, auto remedy them, write result to output file, and send email if any
remediation made.

2) Check mode

When triggered directly (via nrpe), it will check auto remediation output file, raise
nagios alert when file not exist, exceeds max age, or contains error in it.

[0]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-hardware-offload.html  # noqa: E501
"""

import argparse
import logging
import os
import smtplib
import subprocess
import sys
import time
from email.message import EmailMessage

import openstack

openstack.enable_logging(debug=False)  # too noisy, not readable at all.

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

# check_port_security
APP = os.path.splitext(os.path.basename(__file__))[0]
LOG = logging.getLogger(name=APP)
OUTPUT_DEFAULT = "/run/nagios/{}.out".format(APP)


def get_openstack_connection(novarc):
    """Get openstack connection by sourcing novarc file."""
    command = ["/bin/bash", "-c", "source {} && env".format(novarc)]
    LOG.debug("loading envvars from %s", novarc)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        os.environ[key.decode("utf-8")] = value.rstrip().decode("utf-8")
    proc.communicate()
    return openstack.connect(cloud="envvars")


def send_email(subject, content, from_addr, recipients):
    """Send email."""
    if not recipients:
        LOG.warning("no email recipients, email skipped")
        return
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_addr
    message["To"] = recipients  # comma separated emails
    message.set_content(content)
    LOG.info("email message:\n%s", message)
    # quick and dirty way to send email for now
    with smtplib.SMTP(host="localhost", port=25) as smtp:
        smtp.send_message(message)
    LOG.info("email sent")


def get_bad_ports(conn):
    """Get misconfiged ports which have both port security and hardware offload enabled.

    Hardware offload enabled means:

        - binding:vnic_type == "direct"
        - binding:profile={'capabilities': ['switchdev'], ...}

    vnic-type choices:
        direct | direct-physical | macvtap | normal | baremetal | virtio-forwarder
        default: normal
    """
    bad_ports = []
    for port in conn.network.ports():
        # when get, use `is_port_security_enabled`
        # when set, use `port_security_enabled`
        # none of these attrs can be used as filter, have to check by code
        if port.is_port_security_enabled:
            if port.binding_vnic_type == "direct":
                if "switchdev" in port.binding_profile.get("capabilities", []):
                    bad_ports.append(port)
    return bad_ports


def disable_port_security(conn, port, dry_run=False):
    """Disable port security for a port.

    :param port: openstack.network.v2.port.Port

    According to "Disabling port security" section in doc[0]:

        Port level security cannot be disabled if:

        - A security group is assigned to the instance
        - Allowed address pairs are set for the instance

    [0]: https://superuser.openstack.org/articles/managing-port-level-security-openstack/  # noqa: E501
    """
    LOG.info("disable port security on port %s %s", port.id, port.name or "")
    # when get, use `is_port_security_enabled`
    # when set, use `port_security_enabled`
    attrs = {
        "port_security_enabled": False,
    }
    if port.security_group_ids:
        attrs["security_group_ids"] = []
    if port.allowed_address_pairs:
        attrs["allowed_address_pairs"] = []

    if dry_run:
        LOG.info("dry run, port security not disabled")
    else:
        conn.network.update_port(port.id, **attrs)


def auto_remediation(conn, dry_run=False):
    """Run auto remediation and return result lines for each port."""
    lines = []
    for port in get_bad_ports(conn):
        try:
            disable_port_security(conn, port, dry_run=dry_run)
            line = "{} FIXED".format(port.id)
        except Exception as exc:
            # will check keyword "ERROR" in output file
            line = "{} ERROR: {}".format(port.id, exc)
        lines.append(line)
    return lines


def write_output(path, content, append=False):
    """Write output content to file."""
    LOG.debug("writing message to output file %s", path)
    # `open` may fail for permission issue
    try:
        with open(path, "w+" if append else "w") as file_obj:
            file_obj.write(content)
    except Exception:
        # exception info will be added to message
        LOG.exception("write output failed")


def nagios_exit(status, message):
    """Exit script with the way nagios required.

    For any nagios check script, it must:

    - print message to stdout instead of stderr.
    - exit with nagios status code.

    Also, it's a convention to prepend status name to message.
    """
    assert status in NAGIOS_STATUS, "Invalid Nagios status code"
    # prefix status name to message
    output = "{}: {}".format(NAGIOS_STATUS[status], message)
    print(output)  # output to stdout
    sys.exit(status)


def nagios_check(output, max_age):
    """Check output file."""
    if not os.path.isfile(output):
        status = NAGIOS_STATUS_CRITICAL
        message = "auto remediation output file not found: {}".format(output)
        return (status, message)

    stat_result = os.stat(output)
    age = int(time.time() - stat_result.st_mtime)
    max_age = int(max_age)
    if age > max_age:
        status = NAGIOS_STATUS_CRITICAL
        message = "auto remediation output file too old: {} ".format(output)
        return (status, message)

    with open(output) as output_file:
        output_text = output_file.read()
        if "ERROR" in output_text:
            status = NAGIOS_STATUS_CRITICAL
            message = "auto remediation output file contains ERROR: {}".format(output)
            return (status, message)

    status = NAGIOS_STATUS_OK
    # when ok, no need to print file path
    message = "auto remediation output file is healthy"
    return (status, message)


def main():
    parser = argparse.ArgumentParser(
        description="Check Port Security",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print verbose log",
    )

    parser.add_argument(
        "-n",
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="do not actually make changes",
    )

    parser.add_argument(
        "--env",
        dest="env",
        default="/var/lib/nagios/nagios.novarc",
        help="novarc file for openstack authentication",
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=OUTPUT_DEFAULT,
        help="output file path",
    )

    parser.add_argument(
        "-m",
        "--max-age",
        dest="max_age",
        type=int,
        default=90,
        help="output file max age in seconds, should be >= cron job interval",
    )

    parser.add_argument(
        "-l",
        "--list-bad-ports",
        dest="list_bad_ports",
        action="store_true",
        help="list bad ports",
    )

    parser.add_argument(
        "-r",
        "--auto-remediation",
        dest="auto_remediation",
        action="store_true",
        help="trigger auto remediation on bad ports",
    )

    parser.add_argument(
        "--email-from-addr",
        dest="email_from_addr",
        default="{}@localhost".format(APP),
        help="email from address",
    )

    parser.add_argument(
        "-e",
        "--email-recipients",
        dest="email_recipients",
        help="comma separated emails to notify when auto remediation triggered",
    )

    parser.add_argument(
        "-t",
        "-send-test-email",
        dest="send_test_email",
        action="store_true",
        help="send test email, work together with --email-recipients",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level="DEBUG" if args.verbose else "INFO",
        format="%(name)s - %(asctime)s - %(levelname)s: %(message)s",
    )

    if args.auto_remediation:
        conn = get_openstack_connection(args.env)
        # return list of str lines for each port
        lines = auto_remediation(conn, dry_run=args.dry_run)
        if lines:
            content = "\n".join(lines)
        else:
            content = "all ports are healthy"
        # always update output file even no action
        write_output(args.output, content)

        # only send email when auto remediation triggered
        if lines:
            try:
                send_email(
                    "auto remediation triggered on ports",
                    "\n".join(lines),
                    args.email_from_addr,
                    args.email_recipients,
                )
            except Exception as exc:
                LOG.exception("send email failed")
                # nrpe check will alert on email ERROR
                content = "ERROR: {}".format(exc)
                # append, do not clear prev content
                write_output(args.output, content, append=True)
    elif args.list_bad_ports:
        conn = get_openstack_connection(args.env)
        for port in get_bad_ports(conn):
            print("{} {}".format(port.id, port.name))
    elif args.send_test_email:
        send_email(
            "test email from {}".format(APP),
            "test content",
            args.email_from_addr,
            args.email_recipients,
        )
    else:
        nagios_exit(*nagios_check(args.output, args.max_age))


if __name__ == "__main__":
    main()
