#!/bin/sh

set -e
set -u

# Description: Check all of the DNS names on the command line, and return the worst case.
# Copyright: (c) 2018 Canonical Ltd.
# Author: Paul Gear
# License: Apache 2.0

DIR=$(mktemp -d)
trap 'rm -fr ${DIR}' 0 2 3 15

RET=0
for name in "$@"; do
    rc=0
    /usr/lib/nagios/plugins/check_dns -H $name >$DIR/out 2>>$DIR/err || rc=$?
    if [ $rc -ne 0 ]; then
	# check_dns doesn't seem to use stderr
	cat $DIR/out >> $DIR/err
	if [ $rc -gt $RET ]; then
	    RET=$rc
	fi
    else
	cat $DIR/out >> $DIR/allout
    fi
done

# Display error output first if there was a problem
if [ $RET -ne 0 ]; then
    test -e $DIR/err && cat $DIR/err >&2
fi
test -e $DIR/allout && cat $DIR/allout
exit $RET
