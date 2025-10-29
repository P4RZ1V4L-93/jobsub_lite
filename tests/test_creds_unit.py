import os
import pathlib
import shutil
import sys
import tempfile

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
import cred_proxy
import cred_token
from defaults import DEFAULT_ROLE
from test_unit import TestUnit


@pytest.fixture
def fake_token(tmp_path, clear_bearer_token_file):
    _fake_token = tmp_path / "fake_token"
    _fake_token.touch(mode=0o400)
    return _fake_token


@pytest.fixture
def htgettoken_mock_good(tmp_path, monkeypatch):
    old_path = os.environ.get("PATH", "")
    fake_exe_path = tmp_path
    monkeypatch.setenv("PATH", str(fake_exe_path) + os.pathsep + old_path)
    script = f"""#!/bin/bash
    exit 0
    """
    htgettoken = tmp_path / "htgettoken"
    htgettoken.write_text(script)
    htgettoken.chmod(0o755)


@pytest.fixture
def set_required_method_proxy_only(monkeypatch):
    monkeypatch.setattr(creds, "REQUIRED_AUTH_METHODS", ["proxy"])


@pytest.fixture
def proxy_test_hypot_pro_args(monkeypatch):
    monkeypatch.setenv("GROUP", "hypot")
    return {"auth_methods": "proxy", "group": "hypot", "role": "Production"}


# getRole and derived function test fixtures
default_role_file_dirs = ("/tmp", f'{os.environ.get("HOME")}/.config')


@pytest.fixture
def stage_existing_default_role_files(set_group_fermilab):
    # If we already have a default role file, stage it somewhere else
    staged_temp_files = {}

    uid = os.getuid()
    group = os.environ.get("GROUP")
    filename = f"jobsub_default_role_{group}_{uid}"
    try:
        for file_location in default_role_file_dirs:
            file_dir = pathlib.Path(file_location)
            filepath = file_dir / filename

            if os.path.exists(filepath):
                old_file_temp = tempfile.NamedTemporaryFile(delete=False)
                os.rename(filepath, old_file_temp.name)
                staged_temp_files[filepath] = old_file_temp.name

        yield

    finally:
        # Put any staged files back
        for filepath, staged_file in staged_temp_files.items():
            os.rename(staged_file, filepath)


@pytest.fixture(params=default_role_file_dirs)
def default_role_file_location(request):
    return request.param


class TestGetRole:
    @pytest.mark.unit
    def test_getRole_from_default_role_file(
        self, default_role_file_location, stage_existing_default_role_files
    ):
        uid = os.getuid()
        group = os.environ.get("GROUP")
        filename = f"jobsub_default_role_{group}_{uid}"
        file_dir = pathlib.Path(default_role_file_location)
        file_dir.mkdir(exist_ok=True)
        filepath = file_dir / filename
        try:
            filepath.write_text("testrole")
            assert creds.getRole_from_default_role_file() == "testrole"
        finally:
            os.unlink(filepath)

    @pytest.mark.unit
    def test_getRole_from_default_role_file_none(
        self, stage_existing_default_role_files
    ):
        assert not creds.getRole_from_default_role_file()

    @pytest.mark.unit
    def test_getRole_from_valid_token(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE", "fake_ifdh_tokens/fermilab_production.token"
        )
        assert cred_token.getRole_from_valid_token() == "Production"

    @pytest.mark.unit
    def test_getRole_from_valid_token_invalid(self, monkeypatch):
        monkeypatch.setenv("BEARER_TOKEN_FILE", "fake_ifdh_tokens/malformed.token")
        with pytest.raises(TypeError, match="malformed.*list"):
            cred_token.getRole_from_valid_token()

    @pytest.mark.unit
    def test_getRole_from_valid_token_none(self, monkeypatch):
        monkeypatch.delenv("BEARER_TOKEN_FILE", raising=False)
        assert not cred_token.getRole_from_valid_token()

    @pytest.mark.unit
    def test_getRole(self, set_group_fermilab):
        res = creds.getRole()
        assert res == DEFAULT_ROLE

    @pytest.mark.unit
    def test_getRole_override(self):
        override_role = "Hamburgler"
        res = creds.getRole(override_role)
        assert res == override_role


class TestCredUnit:
    """
    Use with pytest... unit tests for ../lib/*.py
    """

    # lib/creds.py routines...

    @pytest.mark.unit
    def test_get_creds_file_exists(
        self,
        htgettoken_mock_good,
        fake_token,
        clear_x509_user_proxy,
        clear_bearer_token_file,
        monkeypatch,
    ):
        """get credentials, make sure the credentials file returned
        exist. Default is to get REQUIRED_AUTH_METHODS which is 'token'"""
        os.environ["BEARER_TOKEN_FILE"] = os.path.join(
            os.path.dirname(__file__), "fake_ifdh_tokens", "fermilab.token"
        )
        import importlib

        monkeypatch.setattr("cred_token.checkToken", lambda a, b: True)
        importlib.reload(cred_token)

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

    # TODO Make this work with managed proxy fixture
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
            cred_proxy.JobsubInvalidProxyError, match="not a valid VOMS proxy"
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

        with pytest.raises(cred_proxy.JobsubInvalidProxyError, match="does not exist"):
            creds.get_creds(proxy_test_hypot_pro_args)

    # TODO Make this work with managed proxy fixture
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
            cred_proxy.JobsubInvalidProxyError, match="not a valid VOMS proxy"
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
        with pytest.raises(cred_proxy.JobsubInvalidProxyError, match="does not exist"):
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


class TestGetRole:
    @pytest.mark.unit
    def test_getRole_from_default_role_file(
        self, default_role_file_location, stage_existing_default_role_files
    ):
        uid = os.getuid()
        group = os.environ.get("GROUP")
        filename = f"jobsub_default_role_{group}_{uid}"
        file_dir = pathlib.Path(default_role_file_location)
        file_dir.mkdir(exist_ok=True)
        filepath = file_dir / filename
        try:
            filepath.write_text("testrole")
            assert creds.getRole_from_default_role_file() == "testrole"
        finally:
            os.unlink(filepath)

    @pytest.mark.unit
    def test_getRole_from_default_role_file_none(
        self, stage_existing_default_role_files
    ):
        assert not creds.getRole_from_default_role_file()

    @pytest.mark.unit
    def test_getRole_from_valid_token(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab_production.token",
        )
        assert cred_token.getRole_from_valid_token() == "Production"

    @pytest.mark.unit
    def test_getRole_from_valid_token_invalid(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/malformed.token",
        )
        with pytest.raises(TypeError, match="malformed.*list"):
            cred_token.getRole_from_valid_token()

    @pytest.mark.unit
    def test_getRole_from_valid_token_none(self, monkeypatch):
        monkeypatch.delenv("BEARER_TOKEN_FILE", raising=False)
        assert not cred_token.getRole_from_valid_token()

    @pytest.mark.unit
    def test_getRole(self, set_group_fermilab):
        res = creds.getRole()
        assert res == DEFAULT_ROLE

    @pytest.mark.unit
    def test_getRole_override(self):
        override_role = "Hamburgler"
        res = creds.getRole(override_role)
        assert res == override_role
