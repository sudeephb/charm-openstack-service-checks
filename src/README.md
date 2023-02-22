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

**Note:** in order to have endpoint checks updated on endpoint changes you *should* also relate identity-notifications:

    juju add-relation keystone:identity-notifications openstack-service-checks:identity-notifications

Alternatively, instead of the above relation, there is also an action "refresh-endpoint-checks" available. Running this action will update the service checks with the current endpoints.

## Octavia Checks

Knowning when an openstack load-balancer is having an issue is an important
operational situation which this charm helps manage.  There is both course
grain control over octavia checks, as well as more fine-grained control by
use of the following config items.

### Course Grain

  * `check-octavia`: `true` or `false` can enable or disable checks

### Fine Grain

  * `octavia-loadbalancers-ignored`
  * `octavia-amphorae-ignored`
  * `octavia-pools-ignored`
  * `octavia-image-ignored`

Each of these config items adds an ignore-list of keywords. Each keyword in
the ignore list will be blocked when it appears in the output of the check.

#### Examples

---------------
Ignoring a test or non-production loadbalancer with the ID=`deadbeef-1234
-56789012-dead-beef` which is __INACTIVE__ or __DEGRADED__.
```bash
juju config my-openstack-service-checks octavia-loadbalancer-ignored='deadbeef-1234-56789012-dead-beef,'
```

Ignoring all loadbalancers which happen to be __DEGRADED__.
```bash
juju config my-openstack-service-checks octavia-loadbalancer-ignored='DEGRADED,'
```

Ignoring amphorae that are stuck in __BOOTING__ state
```bash
juju config my-openstack-service-checks octavia-amphorae-ignored='BOOTING,'
```

## Masakari Checks

Alert when the openstack compute nodes protected by Masakari are on maintenance
during a failure. Follow-up must be done to re-enable the service for nodes
marked by Masakari as being in maintenance state.

    juju config openstack-service-checks check-masakari=true

## Horizon Checks

Alert when the connection or login to openstack-dashboard is unsuccessful. A website
relation with openstack-dashboard is required to enable this.

    juju config openstack-service-checks check-horizon=true

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

## Juju Resources

The rally/tempest tests are installed via the
[fbctest](https://snapcraft.io/fcbtest) snap. The charm supports installing it
from a juju resource, which can be handy in offline deployments. In this case
you'll also have to install the snaps upon which `fcbtest` depends: `core18`
and `snapd`. Prefetch the snaps:

    snap download fcbtest
    snap download core18
    snap download snapd

Provide the snap files as resources to the application:

    for e.g. (change the snap files version accordingly)
    FCBTEST_SNAP_FILE="fcbtest_14.snap"
    CORE18_SNAP_FILE="core18_2074.snap"
    SNAPD_SNAP_FILE="snapd_12398.snap"

    juju deploy cs:~canonical-bootstack/openstack-service-checks \
    --resource fcbtest=$FCBTEST_SNAP_FILE \
    --resource core18=$CORE18_SNAP_FILE \
    --resource snapd=$SNAPD_SNAP_FILE

# Deploy with [openstack-base](https://github.com/openstack-charmers/openstack-bundles/tree/master/stable/openstack-base)

To communication with openstack. We need to provide `os-credentials` and `trusted_ssl_ca` cofiguration in the right way.

**os-credentials** can be either provided by user or looking for the keystone relation `keystone:identity-notifications` and `keystone:identity-credentials`.

Provide by juju config:

```sh
# You can get openrc with this script
source ./openstack-bundles/stable/openstack-base/openrc

env | grep OS_

juju config openstack-service-checks os_credentials="..."
```

By keystone relation:

```sh
juju add-relation keystone:identity-notifications openstack-service-checks:identity-notifications
juju add-relation keystone:identity-credentials openstack-service-checks:identity-credentials
```

**trusted_ssl_ca**

> [Vault configure ca-certificate](https://docs.openstack.org/charm-guide/latest/admin/security/tls.html#add-a-ca-certificate)

```sh
# Vault config
juju actions vault

# Use `get-root-ca` action to get the ca from vault and configure
# Please replace unit name to match your model
juju run-action  --wait vault/0 get-root-ca --format json \
    | jq -r '."unit-vault-0".results.output' \
    | base64 -w 0 \
    | xargs -I {} \
    juju config openstack-service-checks trusted_ssl_ca={}
```

If you are using configuration options provided by the charm such as cinder, you
will need to provide the root CA certificate to the `trusted_ssl_ca`.

# Contact information

Please contact Canonical's BootStack team via the "Submit a bug" link.
Upstream Project Name

 * Website: https://launchpad.net/charm-openstack-service-checks
 * Bug tracker: https://bugs.launchpad.net/charm-openstack-service-checks
