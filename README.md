# Overview

This charm provides OpenStack service checks for Nagios


# Usage

    juju deploy cs:~canonical-bootstack/openstack-service-checks
    juju add-relation openstack-service-checks nrpe

This charm supports relating to keystone via the keystone-credentials
interface.  If you do not wish to use this, you can supply your own credential
set for Openstack by  adding 'os-credentials' setting (see setting description
hints)

    juju config openstack-services-checks os-credentials=" ... "

With Keystone

    juju add-relation openstack-service-checks:identity-credentials keystone:identity-credentials


## API endpoints monitoring

If your OpenStack API endpoints have a common URL for the Admin, Public and
Internal addresses, you should consider disabling some endpoints which would be
duplicated otherwise, e.g.

    juju config openstack-service-checks check_internal_urls=False check_admin_urls=False

If such API endpoints use TLS, new checks will monitor the certificates expiration time:

    juju config openstack-service-checks tls_warn_days=30 tls_crit_days=14

## Compute services monitoring

Compute services are monitored via the 'os-services' interface. Several thresholds can
be adjusted to tweak the alerting system: number of available nodes per host (warning
and critical thresholds), ignore certain host aggregates (by default, no aggregates
are skipped), ignore nodes in 'disabled' state.

    juju config openstack-service-checks nova_warn=2 nova_crit=1
    juju config openstack-service-checks skipped_host_aggregates='hostaggr1,hostaggr2'
    juju config openstack-service-checks skip-disabled=true

## Rally checks

A new nrpe check supports a limited list of rally/tempest tests, which can be
scheduled to run via cron (default cronjob schedule is every 15 minutes). Tests
can also be skipped as follows (available components are cinder, glance, nova and
neutron):

    juju config openstack-service-checks check-rally=true
    juju config openstack-service-checks rally-cron-schedule='*/20 * * * *'
    juju config openstack-service-checks skip-rally='nova,neutron'

# Contact information

Please contact Canonical's BootStack team via the "Submit a bug" link.
Upstream Project Name

 * Website: https://launchpad.net/charm-openstack-service-checks
 * Bug tracker: https://bugs.launchpad.net/charm-openstack-service-checks
