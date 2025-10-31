from collections import namedtuple
import os
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


@pytest.mark.parametrize(
    "input_path,expected_output",
    [
        (
            "/nashome/user/file.txt",
            "/nashome/user/file.txt",
        ),  # NFS mount - return as is
        (
            "/pnfs/path/to/file.txt",
            "https://fndcadoor.fnal.gov:2880/path/to/file.txt",  # PNFS path - make webdav URL
        ),
        (
            "/some/other/path/file.txt",
            "/some/other/path/file.txt",
        ),  # Other path - return as is
    ],
)
@pytest.mark.unit
def test_fix_pnfs(input_path, expected_output):
    assert fake_ifdh.fix_pnfs(input_path) == expected_output


# only works with real files.
class TestChmod:
    @pytest.mark.unit
    def test_chmod_good(self, tmp_path):
        test_file = tmp_path / "testfile"
        test_file.write_text("test")
        fake_ifdh.chmod(str(test_file), 0o742)
        assert oct(test_file.stat().st_mode & 0o777) == "0o742"

    @pytest.mark.unit
    def test_chmod_no_file(self, tmp_path):
        test_file = tmp_path / "nonexistentfile"
        fake_ifdh.chmod(str(test_file), 0o742)

    @pytest.mark.unit
    def test_chmod_no_permissions(self, tmp_path):
        test_file = tmp_path / "testfile"
        test_file.write_text("test")
        # Remove all permissions
        test_file.chmod(0o000)
        fake_ifdh.chmod(str(test_file), 0o742)  # Should raise no error
        test_file.chmod(0o644)  # Reset permissions for cleanup


class TestMkdirP:
    @pytest.mark.unit
    def test_mkdir_p(self, tmp_path):
        dest = tmp_path / "a/b/c/d/e"
        fake_ifdh.mkdir_p(str(dest))
        assert os.path.exists(dest)

    @pytest.mark.unit
    def test_mkdir_p_bad(self):
        dest = os.path.join(os.devnull, "forbidden_directory")
        with pytest.raises(PermissionError, match=f"Unable to make directory {dest}"):
            fake_ifdh.mkdir_p(dest)  # Should not raise an error even if it fails


@pytest.mark.unit
def test_ls(tmp_path):
    test_dir = tmp_path / "test_ls_dir"
    test_dir.mkdir()
    (test_dir / "file1.txt").touch()
    (test_dir / "file2.txt").touch()
    (test_dir / "file3.txt").touch()

    result = fake_ifdh.ls(str(test_dir))
    expected_files = {"file1.txt", "file2.txt", "file3.txt"}
    assert set(result) == expected_files
