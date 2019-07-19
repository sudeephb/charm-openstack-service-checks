#!/usr/bin/env python3
import datetime
import json
import os
import subprocess
import sys

import shutil
import tempfile

OUTPUT_FILE = '/home/nagiososc/rally.status'
HISTORY_FOLDER = '/home/nagiososc/rallystatuses'


def get_backup_output_filename():
    if not os.path.isdir(HISTORY_FOLDER):
        os.mkdir(HISTORY_FOLDER, mode=0o755)

    weekday = datetime.datetime.today().weekday()
    i = 0
    statusfile = os.path.join(HISTORY_FOLDER, 'rally.status.{}.{}'.format(weekday, i))
    while os.path.exists(statusfile):
        i += 1
        statusfile = os.path.join(HISTORY_FOLDER, 'rally.status.{}.{}'.format(weekday, i))

    return statusfile


def _load_envvars(novarc='/var/lib/nagios/nagios.novarc'):
    if not os.path.exists(novarc):
        return False

    juju_proxy = '/etc/juju-proxy.conf'
    if os.path.isfile(juju_proxy):
        src_configs = '{} && source {}'.format(novarc, juju_proxy)
    else:
        src_configs = novarc

    output = subprocess.check_output(['/bin/bash', '-c', 'source {} && env'.format(src_configs)])
    i = 0
    for line in output.decode('utf-8').splitlines():
        key = line.split('=')[0]
        if not (key.startswith('OS_') or key.count('proxy') > 0 or key.count('PROXY') > 0):
            continue
        key, value = line.split('=')
        os.environ[key] = value
        i += 1

    os.environ['SHELL'] = '/bin/bash'
    os.environ['HOME'] = '/home/nagiososc'
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin'

    return i >= 3


def main(testfile='/home/nagiososc/ostests.txt'):
    if not _load_envvars():
        print('UNKNOWN: could not load OS_ envvars')
        sys.exit(3)

    tempoutputfile = tempfile.mktemp()
    cmd1 = ['fcbtest.rally', 'deployment', 'use', 'snap_generated']
    cmd2 = ['fcbtest.rally', '--use-json', 'verify', 'start', '--load-list', testfile, '--detailed']
    try:
        subprocess.check_output(cmd1, stderr=subprocess.STDOUT)
        output = subprocess.check_output(cmd2, stderr=subprocess.STDOUT)
        with open(tempoutputfile, 'w') as fd:
            fd.write(output.decode('utf-8'))
        shutil.copy2(tempoutputfile, OUTPUT_FILE)
        shutil.copy2(OUTPUT_FILE, get_backup_output_filename())
        os.unlink(tempoutputfile)
    except subprocess.CalledProcessError as error:
        msg = {
            'message': 'CRITICAL: fcbtest.rally command failed. {} - {}'.format(str(error), str(error.stdout)),
        }
        with open(OUTPUT_FILE, 'w') as fd:
            fd.write('{}\n'.format(json.dumps(msg)))

    except IOError as error:
        msg = {
            'message': 'CRITICAL: IOError. {}'.format(str(error)),
        }
        with open(OUTPUT_FILE, 'a') as fd:
            fd.write('{}\n'.format(json.dumps(msg)))


if __name__ == '__main__':
    main()
