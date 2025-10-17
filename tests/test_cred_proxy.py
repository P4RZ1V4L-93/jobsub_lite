import grp
import os
import pathlib
import pwd
import shutil
import sys
import pytest

#
# we assume everwhere our current directory is in the package
# test area, so go ahead and cd there
#
os.chdir(os.path.dirname(__file__))


#
# import modules we need to test, since we chdir()ed, can use relative path
# unless we're testing installed, then use /opt/jobsub_lite/...
#
if os.environ.get("JOBSUB_TEST_INSTALLED", "0") == "1":
    sys.path.append("/opt/jobsub_lite/lib")
else:
    sys.path.append("../lib")
import cred_proxy
from defaults import DEFAULT_ROLE
from test_unit import TestUnit


class TestGetTmp:
    @pytest.mark.unit
    def test_getTmp(self):
        if os.environ.get("TMPDIR", None):
            del os.environ["TMPDIR"]
        res = cred_proxy.getTmp()
        assert res == "/tmp"

    @pytest.mark.unit
    def test_getTmp_override(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", "/var/tmp")
        res = cred_proxy.getTmp()
        assert res == "/var/tmp"


class TestGetExp:
    @pytest.mark.unit
    def test_getExp_GROUP(self, monkeypatch):
        monkeypatch.setenv("GROUP", "samdev")
        res = cred_proxy.getExp()
        assert res == "samdev"

    @pytest.mark.unit
    def test_getExp_no_GROUP(self, monkeypatch):
        monkeypatch.delenv("GROUP", raising=False)
        # Adapted from https://stackoverflow.com/a/9324811
        user = pwd.getpwuid(os.getuid()).pw_name
        gid = pwd.getpwnam(user).pw_gid
        expected_group = grp.getgrgid(gid).gr_name
        assert cred_proxy.getExp() == expected_group


class TestCheckProxy:
    @pytest.mark.unit
    def test_proxy_doesnt_exist(self, fake_proxy):
        """Check that a non-existent proxy raises the correct Exception"""
        _fake_proxy = fake_proxy(create_file=False)
        with pytest.raises(
            cred_proxy.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy file does not exist.",
        ):
            cred_proxy.check_proxy(_fake_proxy)
        with pytest.raises(
            cred_proxy.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy file does not exist.",
        ):
            cred_proxy.check_proxy(str(_fake_proxy))

    @pytest.mark.unit
    def test_proxy_exists_not_readable(self, fake_proxy):
        _fake_proxy = fake_proxy(mode=0o000)
        with pytest.raises(
            cred_proxy.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy file is not readable by the current user.",
        ):
            cred_proxy.check_proxy(_fake_proxy)

    @pytest.mark.unit
    def test_proxy_exists_invalid(self, voms_proxy_info_exit_code, fake_proxy):
        # Create fake voms proxy command that always returns 1 for tests
        voms_proxy_info_exit_code(1)
        _fake_proxy = fake_proxy()

        with pytest.raises(
            cred_proxy.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy is not a valid VOMS proxy or has expired",
        ):
            cred_proxy.check_proxy(_fake_proxy)

    @pytest.mark.unit
    def test_proxy_good(self, voms_proxy_info_exit_code, fake_proxy):
        # Create fake voms proxy command that always returns 0 for tests
        voms_proxy_info_exit_code(0)
        _fake_proxy = fake_proxy()
        cred_proxy.check_proxy(_fake_proxy)


class TestCheckProxyFile:
    @pytest.mark.unit
    def test_proxy_doesnt_exist(self, fake_proxy):
        """Check that a non-existent proxy raises the correct Exception"""
        _fake_proxy = fake_proxy(create_file=False)
        with pytest.raises(
            cred_proxy.JobsubInvalidProxyError,
            match=f"The proxy file does not exist",
        ):
            cred_proxy.check_proxy_file(_fake_proxy)

    @pytest.mark.unit
    def test_proxy_exists_not_readable(self, fake_proxy):
        """Check that a non-readable proxy raises the correct Exception"""
        _fake_proxy = fake_proxy(mode=0o000)
        with pytest.raises(
            cred_proxy.JobsubInvalidProxyError,
            match=f"The proxy file is not readable by the current user",
        ):
            cred_proxy.check_proxy_file(_fake_proxy)

    @pytest.mark.unit
    def test_proxy_good(self, fake_proxy):
        _fake_proxy = fake_proxy()
        cred_proxy.check_proxy_file(_fake_proxy)

    @pytest.mark.integration
    def test_proxy_good_int(self):
        """If we have a valid proxy check_proxy_file should run without raising an Exception.

        This test can be run by either setting the env variable INT_X509_USER_PROXY to point
        to a valid proxy before running the test, or by creating a .env file in the repository
        root directory and setting INT_X509_USER_PROXY to point to a valid proxy in that file
        if using VSCode.
        """
        try:
            _proxy_path = pathlib.Path(os.environ["INT_X509_USER_PROXY"])
        except KeyError:
            pytest.skip("No INT_X509_USER_PROXY env variable set")

        cred_proxy.check_proxy_file(_proxy_path)


class TestCheckValidProxy:
    @pytest.mark.unit
    def test_proxy_invalid(self, voms_proxy_info_exit_code, fake_proxy):
        # Create fake voms proxy command that always returns 1 for tests
        voms_proxy_info_exit_code(1)

        with pytest.raises(
            cred_proxy.JobsubInvalidProxyError,
            match=f"The proxy is not a valid VOMS proxy or has expired",
        ):
            cred_proxy.check_valid_proxy(fake_proxy(create_file=False))

    @pytest.mark.unit
    def test_proxy_good(self, voms_proxy_info_exit_code, fake_proxy):
        # Create fake voms proxy command that always returns 0 for tests
        voms_proxy_info_exit_code(0)
        cred_proxy.check_valid_proxy(fake_proxy(create_file=False))

    @pytest.mark.integration
    def test_proxy_good_int(self):
        """If we have a valid proxy check_valid_proxy should run without raising an Exception.

        This test can be run by either setting the env variable INT_X509_USER_PROXY to point
        to a valid proxy before running the test, or by creating a .env file in the repository
        root directory and setting INT_X509_USER_PROXY to point to a valid proxy in that file
        if using VSCode.
        """
        try:
            _proxy_path = pathlib.Path(os.environ["INT_X509_USER_PROXY"])
        except KeyError:
            pytest.skip("No INT_X509_USER_PROXY env variable set")

        cred_proxy.check_valid_proxy(_proxy_path)


class TestDefaultProxyLocation:
    """Cases:
    1. give role, experiment
    2. leave out role, experiment, monkeypatch group in
    """

    @pytest.mark.unit
    def test_default_proxy_location_role_and_experiment(self):
        res = cred_proxy.default_proxy_location("fermilab", "Analysis")
        expected = pathlib.Path(
            os.path.join(cred_proxy.getTmp(), f"x509up_fermilab_Analysis_{os.getuid()}")
        )
        assert res == expected

    @pytest.mark.unit
    def test_default_proxy_location_no_role_or_experiment(
        self, set_tmp, set_group_fermilab
    ):
        assert cred_proxy.default_proxy_location() == pathlib.Path(
            os.path.join(set_tmp, f"x509up_fermilab_{DEFAULT_ROLE}_{os.getuid()}")
        )
