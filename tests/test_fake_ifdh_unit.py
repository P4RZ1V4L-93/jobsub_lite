from collections import namedtuple
import grp
import os
import pathlib
import pwd
import shutil
import sys
import tempfile

import pytest
import jwt
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

import fake_ifdh


@pytest.fixture
def fake_proxy_path(tmp_path):
    fake_path = tmp_path / "test_proxy"
    if os.path.exists(fake_path):
        try:
            os.unlink(fake_path)
        except:
            pass
    return fake_path


@pytest.fixture
def switch_to_invalid_kerb_cache(monkeypatch, tmp_path):
    # Set the environment variable to an invalid path
    fakefile = tmp_path / "invalid_kerb_cache"
    fakefile.touch()
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{fakefile}")
    yield


# class TestGetRole:
# @pytest.mark.unit
# def test_getRole_from_default_role_file(
#     self, default_role_file_location, stage_existing_default_role_files
# ):
#     uid = os.getuid()
#     group = os.environ.get("GROUP")
#     filename = f"jobsub_default_role_{group}_{uid}"
#     file_dir = pathlib.Path(default_role_file_location)
#     file_dir.mkdir(exist_ok=True)
#     filepath = file_dir / filename
#     try:
#         filepath.write_text("testrole")
#         assert fake_ifdh.getRole_from_default_role_file() == "testrole"
#     finally:
#         os.unlink(filepath)

# @pytest.mark.unit
# def test_getRole_from_default_role_file_none(
#     self, stage_existing_default_role_files
# ):
#     assert not fake_ifdh.getRole_from_default_role_file()

# @pytest.mark.unit
# def test_getRole_from_valid_token(self, monkeypatch):
#     monkeypatch.setenv(
#         "BEARER_TOKEN_FILE", "fake_ifdh_tokens/fermilab_production.token"
#     )
#     assert fake_ifdh.getRole_from_valid_token() == "Production"

# @pytest.mark.unit
# def test_getRole_from_valid_token_invalid(self, monkeypatch):
#     monkeypatch.setenv("BEARER_TOKEN_FILE", "fake_ifdh_tokens/malformed.token")
#     with pytest.raises(TypeError, match="malformed.*list"):
#         fake_ifdh.getRole_from_valid_token()

# @pytest.mark.unit
# def test_getRole_from_valid_token_none(self, monkeypatch):
#     monkeypatch.delenv("BEARER_TOKEN_FILE", raising=False)
#     assert not fake_ifdh.getRole_from_valid_token()

# @pytest.mark.unit
# def test_getRole(self, set_group_fermilab):
#     res = fake_ifdh.getRole()
#     assert res == fake_ifdh.DEFAULT_ROLE

# @pytest.mark.unit
# def test_getRole_override(self):
#     override_role = "Hamburgler"
#     res = fake_ifdh.getRole(override_role)
#     assert res == override_role


@pytest.mark.unit
def test_getProxy():
    with pytest.raises(
        NotImplementedError,
        match=(
            "fake_ifdh.getProxy is no longer implemented. "
            "Please obtain your proxy outside of jobsub, and "
            "then set X509_USER_PROXY to the path of your proxy."
        ),
    ):
        fake_ifdh.getProxy()


@pytest.mark.unit
def test_cp():
    dest = __file__ + ".copy"
    if os.path.exists(dest):
        os.unlink(dest)
    fake_ifdh.cp(__file__, dest)
    assert os.path.exists(dest)
    os.unlink(dest)
