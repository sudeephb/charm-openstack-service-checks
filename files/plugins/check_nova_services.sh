#!/bin/bash
# Quick prototype of Nova services check for nagios
#

source /var/lib/nagios/nagios.novarc 2>&1 || exit 1

nova_services=$(openstack compute service list --format=csv -c Binary -c Host -c Status -c State 2>/dev/null | sed -e 's/"//g' -e 's/\r//' | awk -F, '$1 ~ /^(nova|Binary)/')
if [[ ! $nova_services =~ ^Binary ]]; then
    echo "CRITICAL: openstack compute service list failing to show output header, verify connection/auth"
    exit 2
fi
if [[ -z $nova_services ]]; then
    # Arguably this is CRITICAL, but not the point of this check
    echo "WARNING: No Nova services returned"
    exit 1
fi

critical=$(echo "$nova_services" | awk -F, '$3 == "enabled" \
    {if ($4 != "up") print $2, "[" $1 "],"}' | sort)
if [[ -n $critical ]]; then
    echo "CRITICAL: Nova services enabled but down; ${critical//$'\n'/, }"
    exit 2
else
    echo "OK: All enabled Nova services are up"
    exit 0
fi
