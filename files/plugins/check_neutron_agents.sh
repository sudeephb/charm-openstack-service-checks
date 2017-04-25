#!/bin/bash
# Quick prototype of Neutron agents check for nagios
#
# neutron agent-list -fcsv | tr -d \" | awk -F, '$5 ~ /^True/ \
#    {if ($4 != ":-)") print $3, "[", $2, "]"}'
#
# to disable/enable an agent
#    neutron agent-update AGENT_ID --admin-state-up False
#    neutron agent-update AGENT_ID --admin-state-up True

source /var/lib/nagios/nagios.novarc 2>&1 || exit 1

# Filter in 5th column for header (admin_state_up) and boolean value
neutron_agents=$(neutron agent-list -c id -c agent_type -c host -c alive -c admin_state_up -c binary -fcsv 2>/dev/null | tr -d \" | awk -F, '$5 ~ /^(True|False|admin_state_up)/')
if [[ ! $(echo "$neutron_agents" | head -1) =~ admin_state_up ]]; then
    echo "CRITICAL: neutron agent-list failing to show output header, verify connection/auth"
    exit 2
fi
if [[ -z $neutron_agents ]]; then
    # Arguably this is CRITICAL, but not the point of this check
    echo "WARNING: No Neutron agents returned"
    exit 1
fi

critical=$(echo "$neutron_agents" | awk -F, '$5 ~ /^True/ \
    {if ($4 != ":-)") print $3 "[" $2 "," $1 "]"}' | sort)
if [[ -n $critical ]]; then
    echo "CRITICAL: Neutron agents enabled but down; ${critical//$'\n'/, }" | cut -c1-4050
    exit 2
else
    echo "OK: All enabled Neutron agents are up"
    exit 0
fi
