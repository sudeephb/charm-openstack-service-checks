# Overview

This charm provides OpenStack services checks for Nagios

# Build
The fully built charm needs the following source branch
* https://git.launchpad.net/~canonical-bootstack/bootstack-ops/+git/charm-openstack-services-checks

## To build the charm, do:

Prepare the environment

    mkdir -p layers charms/xenial
    export JUJU_REPOSITORY=$PWD/charms

Clone the repositories

    pushd layers
    git clone https://git.launchpad.net/~canonical-bootstack/bootstack-ops/+git/charm-openstack-services-checks
    popd

Build the charm, and symlink for juju-1 compatibility

    charm build layers/charm-openstack-services-checks
    ln -s ../builds/charm-openstack-services-checks charms/xenial


# Usage

    juju deploy local:xenial/openstack-services-checks

This charm supports relating to keystone via the keystone-credentials
interface.  If you do not wish to use this, you can supply your own credential
set for Openstack by  adding 'os-credentials' setting (see setting description
hints)

    juju set openstack-services-checks os-credentials=" ... "
    juju add-relation openstack-services-checks nagios

With Keystone

    juju add-relation openstack-services-checks:identity-credentials keystone:identity-credentials

If your OpenStack API endpoints have a common URL for the Admin, Public and
Internal addresses, you should consider disabling some endpoints which would be
duplicated otherwise, e.g.

    juju config openstack-service-checks check_internal_urls=False check_admin_urls=False
