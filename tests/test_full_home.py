import os
import re
import glob
import inspect
import pytest
import sys
import time
import subprocess
import tempfile
import shutil

#
# we assume everwhere our current directory is in the package
# test area, so go ahead and cd there
#
os.chdir(os.path.dirname(__file__))

#
# add to path what we eed to test
# unless we're testing installed, then use /opt/jobsub_lite/...
#
if os.environ.get("JOBSUB_TEST_INSTALLED", "0") == "1":
    sys.path.append("/opt/jobsub_lite/lib")
else:
    sys.path.append("../lib")

if os.environ.get("JOBSUB_TEST_INSTALLED", "0") == "1":
    os.environ["PATH"] = "/opt/jobsub_lite/bin:" + os.environ["PATH"]
else:
    os.environ["PATH"] = (
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        + "/bin:"
        + os.environ["PATH"]
    )

if 0 != os.system("ksu -e /bin/true"):
    pytest.skip(
        "cannot ksu to make test filesystem here. You may need a kerberos ticket",
        allow_module_level=True,
    )


@pytest.fixture
def tiny_home():
    # setup a $HOME which has just a few MB in it...
    tinyfile = f"{os.environ.get('TMPDIR', '/tmp')}/fsfile{os.getpid()}"
    tinymount = f"/media/tiny_{os.getpid()}"
    print("Setting up {tinymount} as full 3M $HOME area")
    print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
    os.system(f"dd if=/dev/zero of={tinyfile} bs=1M count=3 ")
    os.system(f"echo y | mkfs -t ext3 {tinyfile}")
    os.system(f"ksu -e /bin/mkdir -p {tinymount}")
    os.system(f"ksu -e /bin/mount -o loop,nodev {tinyfile} {tinymount}")
    os.system(f"ksu -e /bin/chown $USER {tinymount}")
    os.system(f"mkdir -p {tinymount}/.config/htgettoken/")
    os.system(
        f"cp -r $HOME/.config/htgettoken/credkey-fermilab-default {tinymount}/.config/htgettoken/"
    )
    save_home = os.environ["HOME"]
    os.environ["HOME"] = tinymount
    os.system(f"dd if=/dev/zero of={tinymount}/f3k bs=1k count=3")
    os.system(f"dd if=/dev/zero of={tinymount}/f16k bs=1k count=16")
    os.system(f"dd if=/dev/zero of={tinymount}/fillit")
    yield tinymount
    os.system(f"ksu -e /bin/umount {tinymount}")
    os.system(f"ksu -e rm {tinyfile}")
    os.environ["HOME"] = save_home
    print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
    return ""


@pytest.fixture
def mock_tarfile_publisher_handler(monkeypatch):
    # Mock TarfilePublisherHandler to avoid actual publishing during tests
    if os.environ.get("JOBSUB_TEST_INSTALLED", "0") == "1":
        sys.path.append("/opt/jobsub_lite/lib")
    else:
        sys.path.append("../lib")
    import tarfiles
    import importlib

    monkeypatch.setattr(
        "tarfiles.TarfilePublisherHandler.cid_exists", lambda x: "PRESENT:12345"
    )
    importlib.reload(tarfiles)


@pytest.mark.parametrize(
    "submit_args,expected_error_msg",
    [
        ({"executable": "/bin/true", "group": "fermilab"}, "No space left on device"),
        (
            {
                "executable": "/bin/true",
                "group": "fermilab",
                "tar_file_name": [f"{os.path.dirname(__file__)}/data/tiny.tar"],
            },
            "No space left on device",
        ),
        (
            {
                "executable": "/bin/true",
                "group": "fermilab",
                "tar_file_name": [f"tardir://{os.path.dirname(__file__)}/dagnabbit"],
            },
            "Tarring up the directory",
        ),
    ],
)
@pytest.mark.integration
def test_full_disk(
    tiny_home, mock_tarfile_publisher_handler, submit_args, expected_error_msg
):
    import jobsub_api

    print("With disk totally full:")
    os.chdir(os.environ.get("HOME"))
    os.system(f"df -h $HOME")
    with pytest.raises(
        jobsub_api.JobsubAPIError, match="Exception in jobsub_call"
    ) as excinfo:
        jobsub_api.submit(**submit_args)
        assert expected_error_msg in excinfo.__cause__


@pytest.mark.parametrize(
    "submit_args,expected_error_msg",
    [
        ({"executable": "/bin/true", "group": "fermilab"}, "No space left on device"),
        (
            {
                "executable": "/bin/true",
                "group": "fermilab",
                "tar_file_name": [f"{os.path.dirname(__file__)}/data/tiny.tar"],
            },
            "No space left on device",
        ),
        (
            {
                "executable": "/bin/true",
                "group": "fermilab",
                "tar_file_name": [f"tardir://{os.path.dirname(__file__)}/dagnabbit"],
            },
            "Tarring up the directory",
        ),
    ],
)
@pytest.mark.integration
def test_3k_free(
    tiny_home, mock_tarfile_publisher_handler, submit_args, expected_error_msg
):
    import jobsub_api

    os.system(f"rm $HOME/f3k")
    os.chdir(os.environ.get("HOME"))
    print("With 3k free:")
    os.system(f"df -h $HOME")
    with pytest.raises(
        jobsub_api.JobsubAPIError, match="Exception in jobsub_call"
    ) as excinfo:
        jobsub_api.submit(**submit_args)
        assert expected_error_msg in excinfo.__cause__


@pytest.mark.integration
def test_19k_free(tiny_home, mock_tarfile_publisher_handler):
    import jobsub_api

    os.system(f"rm $HOME/f3k $HOME/f16k")
    print("===================")
    print("With 19k free:")
    print("===================")
    os.system(f"df -h $HOME")
    # Note:  Here, the tarball creation will work, but there won't be space to copy in the submit files
    with pytest.raises(
        jobsub_api.JobsubAPIError, match="Exception in jobsub_call"
    ) as excinfo:
        jobsub_api.submit(
            executable="/bin/true",
            group="fermilab",
            tar_file_name=[f"tardir://{os.path.dirname(__file__)}/dagnabbit"],
        )
        assert "No space left on device" in excinfo.__cause__
