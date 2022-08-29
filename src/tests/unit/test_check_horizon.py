"""Test horizon connection and login check scripts."""

import os
import unittest.mock as mock
from os.path import abspath, dirname, join

import check_horizon

import nagios_plugin3

import pytest

from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout

TEST_DIR = dirname(abspath(__file__))

SUCCESS_RESPONSE = """
<!DOCTYPE html>
<html>
  <head>
    <title>
      Instance Overview - OpenStack Dashboard
    </title></head>
<div>
</script>
<li class="divider"></li>
<li>
  <a href="/horizon/auth/logout/" target="_self">
        Sign Out
      </a></li></ul></li><li class="dropdown">
  </li></ul></div>
      </div>
      <div id='main_content'>
<div class="messages">
<toast></toast>
</div>
</html>
"""


FAILURE_RESPONSE = """
<!DOCTYPE html>
<html>
  <head>
    <title>Login - OpenStack Dashboard</title>
<link
  rel="stylesheet"
  href="/static/dashboard/css/b597bc3299cf.css"
  type="text/css" media="screen" />
<script type="text/javascript" src="/static/dashboard/js/811b619bb7c4.js"></script>
  </head>
  <body id="splash" ng-app='horizon.app' ng-strict-di>
    <noscript>
      <div class="alert alert-danger text-center javascript-disabled">
        This application requires JavaScript to be enabled in your web browser.
      </div>
    </noscript>
    <div class="panel-footer">
        <button id="loginBtn" type="submit" class="btn btn-primary pull-right">
          <span>Sign In</span>
        </button>
        <div class="clearfix"></div>
    </div>
  </div>
  </body>
</html>
"""


@mock.patch("check_horizon.requests")
@pytest.mark.parametrize("response_text", [SUCCESS_RESPONSE, FAILURE_RESPONSE])
def test_check_horizon_login(requests, response_text, capfd):
    """Test for successful login to horizon."""
    client = mock.MagicMock()
    client.cookies = {"csrftoken": "testcsrftoken"}
    response = mock.MagicMock()
    response.text = response_text
    client.post.return_value = response
    client.get.return_value = ""
    requests.Session.return_value = client
    if response_text == SUCCESS_RESPONSE:
        check_horizon.horizon_login("", "", "", "")
        out, err = capfd.readouterr()
        assert out == "OK: Login to horizon successful\n"
    else:
        with pytest.raises(nagios_plugin3.CriticalError):
            check_horizon.horizon_login("", "", "", "")


@mock.patch("check_horizon.requests")
def test_check_horizon_connection_good(requests):
    """Test for good connection to horizon."""
    response = mock.MagicMock()
    requests.get.return_value = response
    # test passes if no errors are raised
    check_horizon.check_horizon_connection("")


@mock.patch("check_horizon.requests.get")
@pytest.mark.parametrize(
    "request_exception, nagios_exception",
    [
        (Timeout, nagios_plugin3.WarnError),
        (ConnectionError, nagios_plugin3.CriticalError),
        (HTTPError, nagios_plugin3.CriticalError),
        (RequestException, nagios_plugin3.CriticalError),
    ],
)
def test_check_horizon_connection_bad(get, request_exception, nagios_exception):
    """Test for horizon connection when exceptions occur."""
    get.side_effect = request_exception
    with pytest.raises(nagios_exception):
        check_horizon.check_horizon_connection("")


@mock.patch("check_horizon.check_horizon_connection")
@mock.patch("check_horizon.horizon_login")
def test_main(check_horizon_connection, horizon_login):
    """Test that main function executes without exceptions."""
    check_horizon_connection.return_value = ""
    horizon_login.return_value = ""
    novarc_path = join(TEST_DIR, "horizon_check_test_novarc")
    with mock.patch("sys.argv", ["main", "--env", novarc_path, "--ip", "0.0.0.0"]):
        check_horizon.main()

    # Clear environment variables so that they don't interfere with other tests
    del os.environ["OS_USERNAME"]
    del os.environ["OS_PASSWORD"]
    del os.environ["OS_USER_DOMAIN_NAME"]
