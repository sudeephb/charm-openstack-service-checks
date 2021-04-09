"""Test check port security script."""

import tempfile
import time

import check_port_security


def test_output_not_exist():
    """Test for expected green status."""
    status, message = check_port_security.nagios_check("non-exist.out", 3)
    assert status == check_port_security.NAGIOS_STATUS_CRITICAL
    assert "not found" in message


def test_output_too_old():
    """Test for expected green status."""
    output = tempfile.NamedTemporaryFile(mode="w")
    time.sleep(2)
    status, message = check_port_security.nagios_check(output.name, 1)
    assert status == check_port_security.NAGIOS_STATUS_CRITICAL
    assert "too old" in message


def test_output_with_error():
    """Test for expected green status."""
    output = tempfile.NamedTemporaryFile(mode="w")
    output.write("I have ERROR!")
    output.flush()
    status, message = check_port_security.nagios_check(output.name, 1)
    assert status == check_port_security.NAGIOS_STATUS_CRITICAL
    assert "ERROR" in message


def test_output_healthy():
    """Test for expected green status."""
    output = tempfile.NamedTemporaryFile(mode="w")
    status, message = check_port_security.nagios_check(output.name, 3)
    assert status == check_port_security.NAGIOS_STATUS_OK
    assert "healthy" in message
