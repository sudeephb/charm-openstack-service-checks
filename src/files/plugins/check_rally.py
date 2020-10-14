#!/usr/bin/env python3
import collections
import os
import re
import sys

import json

# ie. {0} tempest.test.test1 ... success
TEMPEST_TEST_RE = r'{\d+} [.\w]+ ... (\w+)'
INPUT_FILE = '/home/nagiososc/rally.status'


def print_results(results):
    status_message = collections.defaultdict(lambda: 'UNKNOWN')  # 3
    status_message.update({
        'success': 'OK',  # 0
        'fail': 'CRITICAL',  # 2
        'skip': 'WARNING',  # 1
    })
    return_codes = {msg: code
                    for code, msg in enumerate(['OK', 'WARNING', 'CRITICAL', 'UNKNOWN'])}
    rc = return_codes['OK']
    summary = collections.defaultdict(lambda: 0)

    output = []
    for result in sorted(results, key=lambda result: result['message']):
        if result.get('message', '').startswith('CRITICAL: '):
            # Exception caused by run_rally.py, without running 'rally verify'
            output.append(result['message'])
            if 'verify' in result['message']:
                summary['fail'] += 1

            continue
        elif result.get('message', '').startswith('{'):
            # only parse json lines - rest, ignore
            test_re = re.match(TEMPEST_TEST_RE, result.get('message', ''))
            if not test_re:
                continue

            test_status = test_re.groups()[0]
            output.append('{}: {}'.format(status_message[test_status],
                                          result['message']))
            summary[test_status] += 1

    # make the first line carry the worst event out of all the parsed ones
    # ie. all ok except one critical event will return the first line (and return code)
    # as critical
    nagios_status = 'OK'
    for status_msg in ['CRITICAL', 'WARNING', 'UNKNOWN', 'OK']:
        status = [msg for msg in status_message.keys()
                  if status_message[msg] == status_msg]
        if not status or status[0] not in summary:
            continue

        status = status[0]
        if summary[status] > 0:
            rc = return_codes[status_msg]
            nagios_status = status_msg
            break

    if len(summary) > 0:
        print('{}: '.format(nagios_status)
              + ', '.join(['{}[{}]'.format(status_msg, summary[status_msg])
                           for status_msg in sorted(summary,
                                                    key=lambda status: summary[status],
                                                    reverse=True)
                           ]))
    print('\n'.join(output))
    return rc


def main(results_filename):
    if not os.path.exists(results_filename):
        print('UNKNOWN: {} does not exist'.format(results_filename))
        return 3

    results = []
    with open(results_filename, 'r') as fd:
        for line in fd.readlines():
            line = line.strip()
            if not line:
                continue
            elif len(line) > 5 and line[-5:] == '\x1b[00m':
                line = line[:-5]

            if not line.startswith('{'):
                results.append({'message': line})
                continue

            try:
                results.append(json.loads(line))
            except json.decoder.JSONDecodeError as error:
                print('UNKNOWN: line[{}], error[{}]'.format(line, str(error)))
                return 3

    rc = print_results(results)
    return rc


if __name__ == '__main__':
    sys.exit(main(INPUT_FILE))
