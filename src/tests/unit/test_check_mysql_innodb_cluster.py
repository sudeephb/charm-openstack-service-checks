"""Test MySQL Innodb Cluster Service Checks."""
import json
import unittest.mock as mock
from argparse import Namespace

import check_mysql_innodb_cluster

import pytest


OK_RESP_DATA = {
    "status": "success",
    "data": {
        "resultType": "vector",
        "result": [
            {
                "metric": {
                    "__name__": "mysql_up",
                    "dns_name": "juju-7cbed0-c2-2.project.serverstack",
                    "group": "promoagents-juju",
                    "instance": "10.5.0.184:9104",
                    "job": "mysql-innodb-cluster",
                },
                "value": ["1660540590.67", "1"],
            },
        ],
    },
}

CRITICAL_RESP_DATA = {
    "status": "success",
    "data": {
        "resultType": "vector",
        "result": [
            {
                "metric": {
                    "__name__": "mysql_up",
                    "dns_name": "juju-7cbed0-c2-2.project.serverstack",
                    "group": "promoagents-juju",
                    "instance": "10.5.0.184:9104",
                    "job": "mysql-innodb-cluster",
                },
                "value": ["1660540590.67", "0"],
            },
        ],
    },
}


@pytest.mark.parametrize(
    "resp_dict,expected_status,expected_msg",
    [
        [
            OK_RESP_DATA,
            0,
            "OK",
        ],
        [
            CRITICAL_RESP_DATA,
            2,
            "CRITICAL: instances 10.5.0.184:9104 can't get metrics. Please check exporter permission and mysql status",  # noqa
        ],
    ],
)
def test_check_status(resp_dict, expected_status, expected_msg):
    status, msg = check_mysql_innodb_cluster.check_status(resp_dict)
    assert status == expected_status
    assert msg == expected_msg


@pytest.mark.parametrize(
    "args",
    [Namespace(address="http://10.5.0.184:9104")],
)
@mock.patch("check_mysql_innodb_cluster.urllib.request.urlopen")
@mock.patch("check_mysql_innodb_cluster.check_status", return_value=("OK", 1))
def test_check_mysql_up(mock_check_status, mock_urlopen, args):
    data = mock.MagicMock()
    context = json.dumps(OK_RESP_DATA, indent=2).encode("utf-8")
    data.read.return_value = context

    mock_urlopen.return_value.__enter__.return_value = data
    check_mysql_innodb_cluster.check_mysql_up(args)

    mock_check_status.assert_called_once_with(
        OK_RESP_DATA,
    )
