import os
import sys
import pytest

os.chdir(os.path.dirname(__file__))


#
# import modules we need to test, since we chdir()ed, can use relative path
#
if os.environ.get("JOBSUB_TEST_INSTALLED", "0") == "1":
    sys.path.append("/opt/jobsub_lite/lib")
else:
    sys.path.append("../lib")

import token_mods

if os.environ.get("JOBSUB_TEST_INSTALLED", "0") == "1":
    os.environ["PATH"] = "/opt/jobsub_lite/bin:" + os.environ["PATH"]
else:
    os.environ["PATH"] = (
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        + "/bin:"
        + os.environ["PATH"]
    )


""" Note:  The test tokens in the decode_token_tests dir are set to expire at 2222-02-22 22:22 GMT.  Presumably there'll be a new auth
technology well before then"""


@pytest.fixture
def sample_sl():
    """scope that should be in decode_token_tests/da1"""
    return [
        "storage.create:/dune/scratch/users/username",
        "compute.create",
        "compute.read",
        "compute.cancel",
        "compute.modify",
        "storage.read:/dune",
    ]


def test_get_job_scopes():
    """layer jobsub_submit calls to get desired job scope..."""
    # sample mu2e token with modify generated from https://demo.scitokens.org/. The scopes in that token are:
    # storage.modify:/mu2e/scratch/users/username/out1/d1
    # storage.modify:/mu2e/scratch/users/username/out1/d2
    # foo
    # bar
    # storage.create:/mu2e/scratch/users/username
    # compute.modify
    # storage.modify:/mu2e/scratch/users/username
    # storage.stage:/mu2e/scratch/users/username
    tokenf = "decode_token_tests/mp1"

    need_modify = [
        "/mu2e/scratch/users/username/out1/d1",
        "/mu2e/scratch/users/username/out2/d2",
    ]
    need_stage = [
        "/mu2e/scratch/users/username/stage1",
        "/mu2e/scratch/users/username/stage2",
    ]
    need_scope = ["foo", "bar"]

    job_scopes = token_mods.get_job_scopes(tokenf, need_modify, need_stage, need_scope)
    print(f"got job scopes: {repr(job_scopes)}")

    # check things we added
    added_scopes = [
        "storage.modify:/mu2e/scratch/users/username/out1/d1",
        "storage.modify:/mu2e/scratch/users/username/out2/d2",
        "storage.stage:/mu2e/scratch/users/username/stage1",
        "storage.stage:/mu2e/scratch/users/username/stage2",
        "foo",
        "bar",
    ]
    for sc in added_scopes:
        assert sc in job_scopes

    # check things that should still be there from original
    orig_scopes = [
        "storage.create:/mu2e/scratch/users/username",
        "compute.modify",
    ]
    for sc in orig_scopes:
        assert sc in job_scopes

    # check things that should NOT still be there from original
    removed_scopes = [
        "storage.modify:/mu2e/scratch/users/username",
        "storage.stage:/mu2e/scratch/users/username",
    ]
    for sc in removed_scopes:
        assert sc not in job_scopes


def test_get_job_scopes_env(monkeypatch):
    """If we specify our list of scopes to clean out via JOBSUB_SCOPES_DROP env variable, make sure that works"""
    # sample mu2e token with modify generated from https://demo.scitokens.org/. The scopes in that token are:
    # storage.modify:/mu2e/scratch/users/username/out1/d1
    # storage.modify:/mu2e/scratch/users/username/out1/d2
    # foo
    # bar
    # storage.create:/mu2e/scratch/users/username
    # compute.modify
    # storage.modify:/mu2e/scratch/users/username
    # storage.stage:/mu2e/scratch/users/username
    tokenf = "decode_token_tests/mp1"

    # Set env variable to drop storage.create scopes
    monkeypatch.setenv("JOBSUB_SCOPES_DROP", "storage.create")
    job_scopes = token_mods.get_job_scopes(tokenf)
    print(f"got job scopes: {repr(job_scopes)}")

    # This is what should be left:
    should_exist = [
        "storage.modify:/mu2e/scratch/users/username/out1/d1",
        "storage.modify:/mu2e/scratch/users/username/out1/d2",
        "foo",
        "bar",
        "compute.modify",
        "storage.modify:/mu2e/scratch/users/username",
        "storage.stage:/mu2e/scratch/users/username",
    ]
    for sc in should_exist:
        assert sc in job_scopes

    assert "storage.create:/mu2e/scratch/users/username" not in job_scopes


def test_get_token_scope_1(sample_sl):
    """check that get_token_scope finds the scope"""
    sl = token_mods.get_token_scope("decode_token_tests/da1")
    assert sl == sample_sl


def test_scope_without_1(sample_sl):
    """make sure scope_without can clean out scope types"""
    cleanout = set(["storage.read", "compute.cancel"])
    sl = token_mods.scope_without(cleanout, sample_sl)
    assert "compute.create" in sl
    assert "compute.modify" in sl
    assert "compute.cancel" not in sl
    assert "storage.read:/dune" not in sl


def test_add_subpath_scope_1(sample_sl):
    """test adding allowed weaker storage scopes"""
    # sample_sl doesn't have a modify scope, so add it to the scopes list so we can test
    sctyp = "storage.modify"
    scpath = "/dune/scratch/users/username"
    scsubdir1 = scpath + "/sub/directory"
    scsubdir2 = scpath + "/other/directory"
    orig_scl = sample_sl + [f"{sctyp}:{scpath}"]

    nscl = token_mods.add_subpath_scope(sctyp, scsubdir1, sample_sl, orig_scl)
    nscl = token_mods.add_subpath_scope(sctyp, scsubdir2, nscl, orig_scl)

    assert f"{sctyp}:{scsubdir1}" in nscl
    assert f"{sctyp}:{scsubdir2}" in nscl


def test_add_subpath_scope_2(sample_sl):
    """test where adding a scope that is NOT a subpath of an original scope raises PermissionError"""
    # sample_sl doesn't have a modify scope, so add it to the scopes list so we can test
    sctyp = "storage.modify"
    scpath = "/dune/scratch/users/username"
    orig_scl = sample_sl + [f"{sctyp}:{scpath}"]

    scsubdir = "/other/path/not/allowed"

    with pytest.raises(PermissionError):
        nscl = token_mods.add_subpath_scope(sctyp, scsubdir, sample_sl, orig_scl)
