#!/usr/bin/python3 -I
#
# cred_token -- utility functions for obtaining, checking, and using tokens
#
# COPYRIGHT 2025 FERMI NATIONAL ACCELERATOR LABORATORY
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import sys
import time
from typing import Union, Optional, List, Tuple, Any

# pylint: disable=import-error
import jwt  # type: ignore
import htcondor  # type: ignore # pylint: disable=wrong-import-position
import scitokens  # type: ignore

from defaults import DEFAULT_ROLE  # pylint: disable=wrong-import-position
from tracing import as_span, add_event  # pylint: disable=wrong-import-position

VAULT_OPTS = htcondor.param.get("SEC_CREDENTIAL_GETTOKEN_OPTS", "")


# TODO Eventually, the next two funcs should move into utils.py, and be imported from there. But first, utils.py needs to be cleaned up #pylint: disable=fixme
def getTmp() -> str:
    """return temp directory path"""
    return os.environ.get("TMPDIR", "/tmp")


def getExp() -> str:
    """return current experiment name"""
    if os.environ.get("GROUP", None):
        return str(os.environ.get("GROUP"))
    # otherwise guess primary group...
    exp: str
    with os.popen("id -gn", "r") as f:
        exp = f.read().strip()
    return exp


def init_scitokens() -> None:
    """
    So the scitokens library by default puts a sqlite database
    in $HOME/.cache/scitokens; which is a problem when your
    home area is in NFS, as sqlite doesn't like sharing files
    over NFS.  So to tell it to use something different
    we have to make a config file which points the cache area
    somewhere local.
    So we make a subdirectory in /tmp (or $TMPDIR)
    and put the config file in there, which tells scitokens
    to put the cache file in there as well.
    """
    uid = os.getuid()
    jstmpdir = f"{getTmp()}/js_scitok_{uid}"
    cfgfile = f"{jstmpdir}/.scitokens.cfg"

    # make sure we have the directory
    if not os.access(jstmpdir, os.W_OK):
        os.makedirs(jstmpdir)

    # always update the config file, so /tmp scrubbers do not delete it
    # out from under us
    if os.access(cfgfile, os.W_OK):
        os.utime(cfgfile)
    else:
        with open(cfgfile, "w") as cff:  # pylint: disable=unspecified-encoding
            cff.write(f"[scitokens]\ncache_location: {jstmpdir}\n")

    # in case moving it to /tmp doesn't fix the bug, check for zero length cache file
    # and remove it if zero length
    cachefile = f"{jstmpdir}/scitokens/scitokens_keycache.sqllite"
    if os.access(cachefile, os.R_OK):
        si = os.stat(f"{jstmpdir}/scitokens/scitokens_keycache.sqllite")
        if si.st_size == 0:
            os.unlink(cachefile)

    scitokens.set_config(cfgfile)


init_scitokens()


@as_span("getToken")
def getToken(
    group: Optional[str] = None, role: str = DEFAULT_ROLE, verbose: int = 0
) -> str:
    """get path to token file from the following locations:
    1. Use $BEARER_TOKEN_FILE if set,
    2. Use a token file in /tmp/bt_token_<group>_<role>_<uid> if valid
    3. Make a new token file in /tmp/bt_token_<group>_<role>_<uid>
    """
    group = getExp() if group is None else group
    pid = os.getuid()

    issuer = group
    if group == "samdev":
        issuer = "fermilab"

    if os.environ.get("BEARER_TOKEN_FILE", None) and os.path.exists(
        os.environ["BEARER_TOKEN_FILE"]
    ):
        # if we have a bearer token file set already, keep that one
        tokenfile = os.environ["BEARER_TOKEN_FILE"]
    else:
        tokenfile = f"{getTmp()}/bt_token_{issuer}_{role}_{pid}"
        os.environ["BEARER_TOKEN_FILE"] = tokenfile

    try:
        token_ok = checkToken(issuer, role)
    except (ValueError, TypeError):
        # These are invalid token errors.  User asked to use this file specifically, so user should fix the token
        raise
    except Exception:  # pylint: disable=broad-except
        # Something else is wrong with the token or it doesn't exist.  We should make a fresh one
        token_ok = False

    if not token_ok:
        cmd = f"htgettoken {VAULT_OPTS} -i {issuer}"

        if role != DEFAULT_ROLE:
            cmd = f"{cmd} -r {role.lower()}"  # Token-world wants all-lower

        if verbose > 0:
            sys.stderr.write(f"Running: {cmd}")

        res = os.system(cmd)

        if res != 0:
            raise PermissionError(f"Failed attempting '{cmd}'")

        if not checkToken(issuer, role):
            raise PermissionError(f"Failed validating token from '{cmd}'")

    return tokenfile


# pylint: disable=anomalous-backslash-in-string
def get_group_and_role_from_token_claim(
    wlcg_groups: List[str],
) -> Tuple[Union[str, Any], ...]:
    """Get the group and role from a token's wlcg.groups claim"""
    group_role_pat = re.compile("\/(.+)\/(.+)")
    group_pat = re.compile("\/(.+)")

    # See if we have any claim values that have group and role
    for wlcg_group in wlcg_groups:
        group_role_match = group_role_pat.match(wlcg_group)
        if group_role_match:
            return group_role_match.group(1, 2)

    # We didn't find any, so look claims with just the group
    for wlcg_group in wlcg_groups:
        group_match = group_pat.match(wlcg_group)
        if group_match:
            return (group_match.group(1), DEFAULT_ROLE)

    raise ValueError(
        "wlcg.groups in token are malformed.  Please inspect token with httokendecode command"
    )


def getRole_from_valid_token() -> Optional[str]:
    # if there's a role in the wlcg.groups of the token, pick that
    if os.environ.get("BEARER_TOKEN_FILE", False) and os.path.exists(
        os.environ["BEARER_TOKEN_FILE"]
    ):
        try:
            token = scitokens.SciToken.discover(insecure=True)
        except scitokens.utils.errors.InvalidTokenFormat:
            raise scitokens.utils.errors.InvalidTokenFormat(
                "Token stored in $BEARER_TOKEN_FILE is not in a readable format. "
                "Please inspect the token with httokendecode or unset $BEARER_TOKEN_FILE and allow jobsub to create a new token."
            )
        token_groups_roles = get_and_verify_wlcg_groups_from_token(token)
        _, token_role = get_group_and_role_from_token_claim(token_groups_roles)
        return token_role.capitalize()
    return None


@as_span("get_and_verify_wlcg_groups_from_token", arg_attrs=["*"])
def get_and_verify_wlcg_groups_from_token(token: scitokens.SciToken) -> List[str]:
    """Inspect the wlcg.groups claim of a token, and check that it is of the correct format/type before returning the elements"""
    token_groups_roles = token.get("wlcg.groups")
    if not token_groups_roles:
        raise TypeError(
            "Token does not have a list of wlcg.groups, as is expected.  Please inspect bearer token with the httokendecode command"
        )
    if not isinstance(token_groups_roles, list):
        raise TypeError(
            "Token is malformed:  wlcg.groups should be a list.  Please rerun htgettoken or allow jobsub to fetch a token for you."
        )
    return list(token_groups_roles)


@as_span("checkToken", arg_attrs=["*"])
def checkToken(group: str, role: str = DEFAULT_ROLE) -> bool:
    """check if token in $BEARER_TOKEN_FILE is (almost) expired or is for the wrong group/role.
    If the file doesn't exist, or if the token is expired, checkToken will return false.
    If the file exists but the token is invalid somehow, this function will raise a ValueError or TypeError
    """
    if not os.path.exists(os.environ["BEARER_TOKEN_FILE"]):
        return False

    try:
        token = scitokens.SciToken.discover(insecure=True)
    except jwt.ExpiredSignatureError:
        # Token has already expired
        return False
    if not checkToken_not_expired(token):
        # Token is close enough to expiration or has expired
        return False
    checkToken_right_group_and_role(token, group, role)
    return True


@as_span("checkToken_right_group_and_role", arg_attrs=["*"])
def checkToken_right_group_and_role(
    token: scitokens.SciToken, group: str, role: str = DEFAULT_ROLE
) -> None:
    """Check if token in $BEARER_TOKEN_FILE is for right experiment"""
    token_groups_roles = get_and_verify_wlcg_groups_from_token(token)
    token_group, token_role = get_group_and_role_from_token_claim(token_groups_roles)
    if token_group.lower() != group.lower() or token_role.lower() != role.lower():
        raise ValueError(
            "BEARER_TOKEN_FILE contains a token with the wrong group or role. "
            f"jobsub expects a token with group {group} and role {role}. "
            f"Instead, BEARER_TOKEN_FILE contains a token with group {token_group} and role {token_role}."
        )


@as_span("checkToken_not_expired", arg_attrs=["*"])
def checkToken_not_expired(token: scitokens.SciToken) -> bool:
    """Make sure token in $BEARER_TOKEN_FILE is not (almost) expired"""
    exp_time = str(token.get("exp"))
    add_event(f"expiration: {exp_time}")
    return int(exp_time) - time.time() > 60
