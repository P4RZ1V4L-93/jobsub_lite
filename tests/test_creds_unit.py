import os
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
import creds
from fake_ifdh import DEFAULT_ROLE
from test_unit import TestUnit


@pytest.fixture
def fake_proxy(tmp_path, clear_x509_user_proxy):
    def inner(create_file=True, mode=0o400):
        _fake_proxy = tmp_path / "fake_proxy"
        if create_file:
            _fake_proxy.touch(mode=mode)
        return _fake_proxy

    return inner


@pytest.fixture
def fake_token(tmp_path, clear_bearer_token_file):
    _fake_token = tmp_path / "fake_token"
    _fake_token.touch(mode=0o400)
    return _fake_token


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


@pytest.fixture
def set_required_method_proxy_only(monkeypatch):
    monkeypatch.setattr(creds, "REQUIRED_AUTH_METHODS", ["proxy"])


@pytest.fixture
def proxy_test_hypot_pro_args(monkeypatch):
    monkeypatch.setenv("GROUP", "hypot")
    return {"auth_methods": "proxy", "group": "hypot", "role": "Production"}


class TestCredUnit:
    """
    Use with pytest... unit tests for ../lib/*.py
    """

    # lib/creds.py routines...

    @pytest.mark.unit
    def test_get_creds_file_exists(
        self, fake_token, clear_x509_user_proxy, clear_bearer_token_file, monkeypatch
    ):
        """get credentials, make sure the credentials file returned
        exist. Default is to get REQUIRED_AUTH_METHODS which is 'token'"""
        os.environ["BEARER_TOKEN_FILE"] = os.path.join(
            os.path.dirname(__file__), "fake_ifdh_tokens", "fermilab.token"
        )
        os.environ["GROUP"] = TestUnit.test_group
        cred_set = creds.get_creds()
        assert os.path.exists(os.environ["BEARER_TOKEN_FILE"])
        assert os.path.exists(cred_set.token)

    @pytest.mark.unit
    def test_get_creds_default_role_set(self, clear_bearer_token_file):
        """get credentials using one of our fake tokens, make sure role is properly set"""
        args = {"auth_methods": os.environ.get("JOBSUB_AUTH_METHODS", "token")}
        os.environ["BEARER_TOKEN_FILE"] = os.path.join(
            os.path.dirname(__file__), "fake_ifdh_tokens", "fermilab.token"
        )
        os.environ["GROUP"] = TestUnit.test_group
        _ = creds.get_creds(args)
        assert args["role"] == DEFAULT_ROLE

    @pytest.mark.unit
    def test_get_creds_token_only(self, clear_x509_user_proxy, clear_bearer_token_file):
        """Get only a token with args.auth_methods = 'token'"""
        args = {"auth_methods": "token"}
        os.environ["GROUP"] = TestUnit.test_group
        cred_set = creds.get_creds(args)
        # Make sure we have a token and the env is set
        assert os.path.exists(os.environ["BEARER_TOKEN_FILE"])
        assert os.path.exists(cred_set.token)
        # Make sure X509_USER_PROXY is not set
        assert os.environ.get("X509_USER_PROXY", None) is None

    @pytest.mark.unit
    def test_get_creds_proxy_only(self, clear_x509_user_proxy, clear_bearer_token_file):
        """If we specify ONLY a supported auth method that is NOT a required auth method,
        raise a TypeError"""
        args = {"auth_methods": "proxy"}
        os.environ["GROUP"] = TestUnit.test_group
        with pytest.raises(TypeError, match="Missing required authorization method"):
            creds.get_creds(args)

    @pytest.mark.unit
    def test_get_creds_proxy_and_token(
        self,
        voms_proxy_info_exit_code,
        clear_x509_user_proxy,
        clear_bearer_token_file,
        fake_proxy,
        fake_token,
    ):
        # We will mock voms-proxy-info to always return 0 in these tests
        voms_proxy_info_exit_code(0)
        _fake_proxy = fake_proxy()

        os.environ["BEARER_TOKEN_FILE"] = os.path.join(
            os.path.dirname(__file__), "fake_ifdh_tokens", "fermilab.token"
        )
        os.environ["X509_USER_PROXY"] = str(_fake_proxy)

        args = {"auth_methods": "proxy,token"}
        os.environ["GROUP"] = TestUnit.test_group
        creds.get_creds(args)

    @pytest.mark.unit
    def test_get_creds_invalid_auth(
        self, clear_x509_user_proxy, clear_bearer_token_file
    ):
        """This should never happen as the get_parser custom action should catch this and
        raise an Exception, but just in case we get past it"""
        args = {"auth_methods": "fakeauth"}
        os.environ["GROUP"] = TestUnit.test_group
        with pytest.raises(TypeError, match="Missing required authorization method"):
            creds.get_creds(args)

    @pytest.mark.unit
    def test_print_cred_paths_from_credset(self, capsys):
        cred_set = creds.CredentialSet(token="tokenlocation", proxy="proxylocation")
        creds.print_cred_paths_from_credset(cred_set)
        out, _ = capsys.readouterr()
        assert out == (
            "token location: tokenlocation\n" "proxy location: proxylocation\n"
        )
        del os.environ["X509_USER_PROXY"]

    @pytest.mark.unit
    def test_proxy_doesnt_exist(self, fake_proxy):
        """Check that a non-existent proxy raises the correct Exception"""
        _fake_proxy = fake_proxy(create_file=False)
        with pytest.raises(
            creds.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy file does not exist.",
        ):
            creds.check_proxy(_fake_proxy)
        with pytest.raises(
            creds.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy file does not exist.",
        ):
            creds.check_proxy(str(_fake_proxy))

    @pytest.mark.unit
    def test_proxy_exists_not_readable(self, fake_proxy):
        _fake_proxy = fake_proxy(mode=0o000)
        with pytest.raises(
            creds.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy file is not readable by the current user.",
        ):
            creds.check_proxy(_fake_proxy)

    @pytest.mark.unit
    def test_proxy_exists_invalid(self, voms_proxy_info_exit_code, fake_proxy):
        # Create fake voms proxy command that always returns 1 for tests
        voms_proxy_info_exit_code(1)
        _fake_proxy = fake_proxy()

        with pytest.raises(
            creds.JobsubInvalidProxyError,
            match=f"The proxy file at {_fake_proxy} is invalid: The proxy is not a valid VOMS proxy or has expired",
        ):
            creds.check_proxy(_fake_proxy)

    @pytest.mark.unit
    def test_proxy_good(self, voms_proxy_info_exit_code, fake_proxy):
        # Create fake voms proxy command that always returns 0 for tests
        voms_proxy_info_exit_code(0)
        _fake_proxy = fake_proxy()
        creds.check_proxy(_fake_proxy)

    # Integration tests:

    # TODO Add pytest-dotenv extension to make these instructions IDE-independent

    @pytest.mark.integration
    def test_get_creds_file_exists_int(self, clear_x509_user_proxy):
        """get credentials, make sure the credentials file returned
        exist. Default is to get REQUIRED_AUTH_METHODS which is 'token'"""
        os.environ["GROUP"] = TestUnit.test_group
        cred_set = creds.get_creds()
        assert os.path.exists(os.environ["BEARER_TOKEN_FILE"])
        assert os.path.exists(cred_set.token)

    @pytest.mark.integration
    def test_proxy_good_int(
        self, set_required_method_proxy_only, proxy_test_hypot_pro_args, monkeypatch
    ):
        """If we have a valid proxy at X509_USER_PROXY, get_creds should return a CredentialSet
        with the proxy attribute set to the proxy's path.

        This test can be run by either setting the env variable INT_X509_USER_PROXY to point
        to a valid proxy before running the test, or by creating a .env file in the repository
        root directory and setting INT_X509_USER_PROXY to point to a valid proxy in that file
        if using VSCode.
        """
        try:
            monkeypatch.setenv("X509_USER_PROXY", os.environ["INT_X509_USER_PROXY"])
        except KeyError:
            pytest.skip("No INT_X509_USER_PROXY env variable set")

        cred_set = creds.get_creds(proxy_test_hypot_pro_args)
        assert cred_set.proxy == os.environ["INT_X509_USER_PROXY"]

    @pytest.mark.integration
    def test_proxy_bad_int(
        self,
        fake_proxy,
        set_required_method_proxy_only,
        proxy_test_hypot_pro_args,
        monkeypatch,
    ):
        _fake_proxy = fake_proxy()
        monkeypatch.setenv("X509_USER_PROXY", str(_fake_proxy))

        with pytest.raises(
            creds.JobsubInvalidProxyError, match="not a valid VOMS proxy"
        ):
            creds.get_creds(proxy_test_hypot_pro_args)

    @pytest.mark.integration
    def test_proxy_doesnt_exist_int(
        self,
        fake_proxy,
        set_required_method_proxy_only,
        proxy_test_hypot_pro_args,
        monkeypatch,
    ):
        monkeypatch.setenv("X509_USER_PROXY", str(fake_proxy(create_file=False)))

        with pytest.raises(creds.JobsubInvalidProxyError, match="does not exist"):
            creds.get_creds(proxy_test_hypot_pro_args)

    @pytest.mark.integration
    def test_proxy_good_default_location_int(
        self,
        proxy_test_hypot_pro_args,
        set_tmp,
        clear_x509_user_proxy,
        set_required_method_proxy_only,
    ):
        """If we have a valid proxy at the default location, get_creds should return a CredentialSet
        with the proxy attribute set to the proxy's path.

        This test can be run by either setting the env variable INT_X509_USER_PROXY to point
        to a valid proxy before running the test, or by creating a .env file in the repository
        root directory and setting INT_X509_USER_PROXY to point to a valid proxy in that file
        if using VSCode."""
        args = proxy_test_hypot_pro_args
        _fake_proxy = set_tmp / f"x509up_{args['group']}_{args['role']}_{os.getuid()}"
        try:
            shutil.copy(os.environ["INT_X509_USER_PROXY"], _fake_proxy)
        except KeyError:
            pytest.skip("No INT_X509_USER_PROXY env variable set")

        cred_set = creds.get_creds(args)
        assert cred_set.proxy == str(_fake_proxy)

    @pytest.mark.integration
    def test_proxy_bad_default_location_int(
        self,
        proxy_test_hypot_pro_args,
        set_tmp,
        clear_x509_user_proxy,
        set_required_method_proxy_only,
    ):
        args = proxy_test_hypot_pro_args
        fake_proxy = set_tmp / f"x509up_{args['group']}_{args['role']}_{os.getuid()}"
        fake_proxy.touch(0o400)

        with pytest.raises(
            creds.JobsubInvalidProxyError, match="not a valid VOMS proxy"
        ):
            creds.get_creds(args)

    @pytest.mark.integration
    def test_proxy_doesnt_exist_default_location_int(
        self,
        proxy_test_hypot_pro_args,
        set_tmp,
        clear_x509_user_proxy,
        set_required_method_proxy_only,
    ):
        with pytest.raises(creds.JobsubInvalidProxyError, match="does not exist"):
            creds.get_creds(proxy_test_hypot_pro_args)


@pytest.mark.parametrize(
    "cmdline_arg,env_var,expected",
    [
        ("flag_setting1,flag_setting2", "", ["flag_setting1", "flag_setting2"]),
        (None, "env_setting1,env_setting2", ["env_setting1", "env_setting2"]),
        ("flag_setting", "env_setting", ["flag_setting"]),
        ("setting", "setting", ["setting"]),
        (None, None, creds.REQUIRED_AUTH_METHODS),
    ],
)
@pytest.mark.unit
def test_resolve_auth_methods(cmdline_arg, env_var, expected, monkeypatch):
    """
    --auth-methods
    JOBSUB_AUTH_METHODS
    REQUIRED_AUTH_METHODS
    """
    if env_var is not None:
        monkeypatch.setenv("JOBSUB_AUTH_METHODS", env_var)
    methods = creds.resolve_auth_methods(cmdline_arg)
    assert methods == expected
