# Overview

This charm provides OpenStack service checks for Nagios


# Usage

    juju deploy cs:~canonical-bootstack/openstack-service-checks
    juju add-relation openstack-service-checks nrpe

This charm supports relating to keystone via the keystone-credentials
interface.  If you do not wish to use this, you can supply your own credential
set for Openstack by  adding 'os-credentials' setting (see setting description
hints)

    juju set openstack-services-checks os-credentials=" ... "

With Keystone

    juju add-relation openstack-service-checks:identity-credentials keystone:identity-credentials

If your OpenStack API endpoints have a common URL for the Admin, Public and
Internal addresses, you should consider disabling some endpoints which would be
duplicated otherwise, e.g.

    juju config openstack-service-checks check_internal_urls=False check_admin_urls=False

