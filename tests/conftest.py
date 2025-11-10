import os
import shutil
import subprocess
import sys

import pytest

#
# we assume everwhere our current directory is in the package
# test area, so go ahead and cd there
#
os.chdir(os.path.dirname(__file__))

from test_unit import TestUnit

#
# import modules we need to test, since we chdir()ed, can use relative path
#
sys.path.append("../lib")

import creds


@pytest.fixture
def set_creds_dir(tmp_path):
    """
    Set the credentials directory to a temporary path for testing.
    """
    creds_dir = tmp_path / "creds"
    creds_dir.mkdir()
    yield creds_dir


@pytest.fixture
def set_temp_bearer_token_file(monkeypatch, set_creds_dir):
    """
    Set the BEARER_TOKEN_FILE env to a temporary path for testing.
    """
    monkeypatch.setenv("BEARER_TOKEN_FILE", str(set_creds_dir / "test_bearer_token"))
    yield


@pytest.fixture
def set_temp_x509_user_proxy(monkeypatch, set_creds_dir):
    """
    Set the X509_USER_PROXY env to a temporary path for testing.
    """
    monkeypatch.setenv("X509_USER_PROXY", str(set_creds_dir / "test_x509_user_proxy"))
    yield


@pytest.fixture
def needs_test_managed_proxy(
    monkeypatch,
    set_temp_x509_user_proxy,
    check_user_kerberos_creds,
):
    """
    Fixture to ensure that the X509_USER_PROXY is set to the test managed proxy. This proxy must reside
    at the location specified by INT_X509_USER_PROXY env variable.
    """
    try:
        test_managed_proxy = os.environ["INT_X509_USER_PROXY"]
    except KeyError:
        pytest.fail("INT_X509_USER_PROXY environment variable is not set.")

    try:
        shutil.copy(test_managed_proxy, os.environ["X509_USER_PROXY"])
    except Exception as e:
        pytest.fail(f"Failed to copy test managed proxy into place: {e}")

    yield os.environ["X509_USER_PROXY"]


@pytest.fixture
def needs_token(
    monkeypatch,
    set_temp_bearer_token_file,
    check_user_kerberos_creds,
):
    """
    Fixture to ensure that the BEARER_TOKEN_FILE is set and valid.
    """
    monkeypatch.setenv("GROUP", TestUnit.test_group)
    yield creds.get_creds({"role": "Analysis", "auth_methods": "token"})


@pytest.fixture
def needs_token_file(needs_token):
    """
    Fixture to ensure that the BEARER_TOKEN_FILE is set and valid. Yields the token file rather
    than the full CredentialSet
    """
    yield needs_token.token


@pytest.fixture
def needs_credentials(
    monkeypatch,
    needs_token_file,
    needs_test_managed_proxy,
    check_user_kerberos_creds,
):
    monkeypatch.setenv("GROUP", TestUnit.test_group)
    cred_set_token = needs_token_file
    cred_set_proxy = needs_test_managed_proxy
    yield creds.CredentialSet(token=cred_set_token, proxy=cred_set_proxy)


@pytest.fixture
def clear_x509_user_proxy():
    """Clear environment variable X509_USER_PROXY to test credentials overrides"""
    old_x509_user_proxy_value = os.environ.pop("X509_USER_PROXY", None)
    yield

    # If our test set X509_USER_PROXY, remove it
    os.environ.pop("X509_USER_PROXY", None)

    if old_x509_user_proxy_value is not None:
        os.environ["X509_USER_PROXY"] = old_x509_user_proxy_value


@pytest.fixture
def clear_bearer_token_file():
    """Clear environment variable BEARER_TOKEN_FILE to test credentials overrides"""
    old_bearer_token_file_value = os.environ.pop("BEARER_TOKEN_FILE", None)
    yield

    # If our test set BEARER_TOKEN_FILE, remove it
    os.environ.pop("BEARER_TOKEN_FILE", None)

    if old_bearer_token_file_value is not None:
        os.environ["BEARER_TOKEN_FILE"] = old_bearer_token_file_value


@pytest.fixture
def check_user_kerberos_creds():
    """Make sure we have kerberos credentials before starting the test"""
    proc = subprocess.run(
        ["klist"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="UTF-8"
    )
    if proc.returncode or ("No credentials cache found" in proc.stdout):
        raise Exception(
            f"No kerberos credentials found.  Please run kinit and try again.  Error: {proc.stdout}"
        )


@pytest.fixture
def set_group_fermilab(monkeypatch):
    monkeypatch.setenv("GROUP", "fermilab")


# fs here is referring to a pyfakefs fake file system.  pyfakefs is a pytest plugin.
# By running "pip install pyfakefs", we can use the "fs" fixture in pytest tests and fixtures
@pytest.fixture
def fakefs(fs):
    yield fs


# Credentials fixtures common across multiple modules


@pytest.fixture
def fake_proxy(tmp_path, clear_x509_user_proxy):
    def inner(create_file=True, mode=0o400):
        _fake_proxy = tmp_path / "fake_proxy"
        if create_file:
            _fake_proxy.touch(mode=mode)
        return _fake_proxy

    return inner


@pytest.fixture
def voms_proxy_info_exit_code(tmp_path, monkeypatch):
    def inner(exit_code):
        old_path = os.environ.get("PATH", "")
        fake_exe_path = tmp_path
        monkeypatch.setenv("PATH", str(fake_exe_path) + os.pathsep + old_path)
        script = f"""#!/bin/bash
        exit {exit_code}
        """
        vpi = tmp_path / "voms-proxy-info"
        vpi.write_text(script)
        vpi.chmod(0o755)

    return inner


@pytest.fixture
def set_tmp(monkeypatch, tmp_path):
    tmp = tmp_path
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    return tmp
