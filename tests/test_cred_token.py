from collections import namedtuple
import os
import shutil
import sys

import jwt
import pytest
import scitokens

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
import cred_token


@pytest.fixture
def clear_token():
    if os.environ.get("BEARER_TOKEN_FILE", None):
        if os.path.exists(os.environ["BEARER_TOKEN_FILE"]):
            try:
                os.unlink(os.environ["BEARER_TOKEN_FILE"])
            except:
                pass
        del os.environ["BEARER_TOKEN_FILE"]


@pytest.fixture
def fermilab_token(clear_token, set_group_fermilab):
    # Get a standard fermilab token for tests
    return cred_token.getToken("fermilab", "Analysis")


# checkToken test fixtures
_TokenLocationAndReverser = namedtuple(
    "_TokenLocationAndReverser", ["token_location", "preserve_or_reverse_func"]
)
_token_locations_and_reversers = (
    _TokenLocationAndReverser(
        f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab.token", lambda x: x
    ),
    _TokenLocationAndReverser("thispathdoesntexist", lambda x: not x),
    _TokenLocationAndReverser(
        f"{os.path.dirname(__file__)}/fake_ifdh_tokens/expired.token", lambda x: not x
    ),
)


@pytest.fixture(params=_token_locations_and_reversers)
def token_locations_and_reverser(request):
    return request.param


class TestCheckToken:
    @pytest.mark.unit
    def test_checkToken_bool(
        self,
        token_locations_and_reverser,
        monkeypatch,
    ):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE", token_locations_and_reverser.token_location
        )
        group = "fermilab"
        # If we want to assert False in one of these cases, flip the result using preserve_or_reverse_func
        assert token_locations_and_reverser.preserve_or_reverse_func(
            cred_token.checkToken(group)
        )

    @pytest.mark.unit
    def test_checkToken_wrong_group_raises(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab.token",
        )
        group = "fakegroup"
        with pytest.raises(ValueError, match="wrong group"):
            cred_token.checkToken(group)


class TestCheckTokenNotExpired:
    @pytest.mark.unit
    def test_fail(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/expired.token",
        )
        try:
            token = scitokens.SciToken.discover(insecure=True)
            assert not cred_token.checkToken_not_expired(token)
        except jwt.ExpiredSignatureError:
            pass

    @pytest.mark.unit
    def test_success(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab.token",
        )
        token = scitokens.SciToken.discover(insecure=True)
        assert cred_token.checkToken_not_expired(token)


# checkToken_right_group_and_role test cases and fixtures
_BadCheckTokenTestCase = namedtuple(
    "_BadCheckTokenTestCase",
    ["token_location", "group", "raised_error", "match_expr", "role"],
)
_bad_checkToken_test_cases = (
    _BadCheckTokenTestCase(
        f"{os.path.dirname(__file__)}/fake_ifdh_tokens/no_groups.token",
        "fermilab",
        TypeError,
        r"wlcg\.groups",
        None,
    ),
    _BadCheckTokenTestCase(
        f"{os.path.dirname(__file__)}/fake_ifdh_tokens/malformed.token",
        "fermilab",
        TypeError,
        "malformed.*list",
        None,
    ),
    _BadCheckTokenTestCase(
        f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab.token",
        "badgroup",
        ValueError,
        "wrong group",
        None,
    ),
    _BadCheckTokenTestCase(
        f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab.token",
        "fermilab",
        ValueError,
        "wrong group or role",
        "badrole",
    ),
)


@pytest.fixture(params=_bad_checkToken_test_cases)
def bad_checkToken_test_case(request):
    return request.param


class TestCheckTokenRightGroupAndRole:
    @pytest.mark.unit
    def test_good(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab.token",
        )
        group = "fermilab"
        token = scitokens.SciToken.discover(insecure=True)
        cred_token.checkToken_right_group_and_role(token, group)

    @pytest.mark.unit
    def test_good_with_role(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab_production.token",
        )
        group = "fermilab"
        role = "production"
        token = scitokens.SciToken.discover(insecure=True)
        cred_token.checkToken_right_group_and_role(token, group, role)

    @pytest.mark.unit
    def test_good_with_role_different_case(self, monkeypatch):
        """Should still pass because we should be case-insensitive"""
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab_production.token",
        )
        group = "fermilab"
        role = "Production"
        token = scitokens.SciToken.discover(insecure=True)
        cred_token.checkToken_right_group_and_role(token, group, role)

    @pytest.mark.unit
    def test_bad(self, bad_checkToken_test_case, monkeypatch):
        monkeypatch.setenv("BEARER_TOKEN_FILE", bad_checkToken_test_case.token_location)
        group = bad_checkToken_test_case.group
        token = scitokens.SciToken.discover(insecure=True)
        with pytest.raises(
            bad_checkToken_test_case.raised_error,
            match=bad_checkToken_test_case.match_expr,
        ):
            args = (
                (token, group, bad_checkToken_test_case.role)
                if bad_checkToken_test_case.role
                else (token, group)
            )
            cred_token.checkToken_right_group_and_role(*args)


class TestGetToken:
    @pytest.mark.unit
    def test_good(self, clear_token, fermilab_token):
        assert os.path.exists(fermilab_token)

    @pytest.mark.unit
    def test_fail(self, monkeypatch, clear_token):
        monkeypatch.setenv("GROUP", "bozo")
        with pytest.raises(PermissionError):
            cred_token.getToken("Analysis")

    @pytest.mark.unit
    def test_bearer_token_file_good(self, monkeypatch, set_group_fermilab):
        monkeypatch.setenv("BEARER_TOKEN_FILE", "fake_ifdh_tokens/fermilab.token")
        assert (
            cred_token.getToken("fermilab", "Analysis")
            == os.environ["BEARER_TOKEN_FILE"]
        )

    @pytest.mark.unit
    def test_bearer_token_file_expired(self, monkeypatch, tmp_path):
        # Since the token is expired, a new, valid token should show up at BEARER_TOKEN_FILE
        token_path = tmp_path / "expired.token"
        shutil.copy(
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/expired.token", token_path
        )
        monkeypatch.setenv("BEARER_TOKEN_FILE", str(token_path))
        monkeypatch.setenv("GROUP", "fermilab")
        assert cred_token.getToken("fermilab", "Analysis")

    @pytest.mark.unit
    def test_bearer_token_file_wrong_group(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/fermilab.token",
        )
        monkeypatch.setenv("GROUP", "bogus")
        with pytest.raises(ValueError, match="wrong group"):
            cred_token.getToken()

    @pytest.mark.unit
    def test_bearer_token_file_malformed(self, monkeypatch):
        monkeypatch.setenv(
            "BEARER_TOKEN_FILE",
            f"{os.path.dirname(__file__)}/fake_ifdh_tokens/malformed.token",
        )
        monkeypatch.setenv("GROUP", "fermilab")
        with pytest.raises(TypeError, match="malformed"):
            cred_token.getToken()

    @pytest.mark.unit
    def test_bearer_token_file_not_exist(self, monkeypatch):
        monkeypatch.setenv("BEARER_TOKEN_FILE", "thisfiledoesnotexist")
        monkeypatch.setenv("GROUP", "fermilab")
        token_file = cred_token.getToken("fermilab", "Analysis")
        assert os.path.exists(token_file)


@pytest.mark.parametrize(
    "input, expected, raised_error, match_expr",
    [
        (["/fermilab"], ("fermilab", "Analysis"), None, None),
        (["/fermilab/production", "/fermilab"], ("fermilab", "production"), None, None),
        (["/hypot"], ("hypot", "Analysis"), None, None),
        (["hypot"], None, ValueError, r"wlcg\.groups.*token.*malformed"),
    ],
)
@pytest.mark.unit
def test_get_group_and_role_from_token_claim(input, expected, raised_error, match_expr):
    if not raised_error:
        assert cred_token.get_group_and_role_from_token_claim(input) == expected
    else:
        with pytest.raises(raised_error, match=match_expr):
            cred_token.get_group_and_role_from_token_claim(input)
