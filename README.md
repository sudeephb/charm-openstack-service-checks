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

This charm supports relating to keystone, but keystone-credentials interface
seems to be flaky, and hard to remove-relation, so the charm works around this
by adding 'os-credentials' setting (see setting description hints)

    juju set openstack-services-checks os-credentials=" ... "

    juju add-relation openstack-services-checks nagios

With Keystone

    juju add-relation openstack-services-checks:identity-credentials keystone:identity-credentials


