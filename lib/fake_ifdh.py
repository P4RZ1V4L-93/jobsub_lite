#!/usr/bin/python3 -I

# fake_ifdh -- get rid of ifdhc dependency by providing a few
#              bits of ifdh behavior
#
# COPYRIGHT 2021 FERMI NATIONAL ACCELERATOR LABORATORY
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
"""ifdh replacemnents to remove dependency"""

import argparse
import os
import io
import re
import shlex
import subprocess
import sys
import time
from typing import Union, Optional, List, Dict, Tuple, Any

# pylint: disable=import-error
import jwt  # type: ignore
import scitokens  # type: ignore

# TODO: Do we need this anymore since we're IN lib?  # pylint: disable=fixme
PREFIX = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PREFIX, "lib"))

import htcondor  # type: ignore # pylint: disable=wrong-import-position
from tracing import as_span, add_event  # pylint: disable=wrong-import-position

VAULT_OPTS = htcondor.param.get("SEC_CREDENTIAL_GETTOKEN_OPTS", "")
DEFAULT_ROLE = "Analysis"


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
    tdir = os.environ.get("TMPDIR", "/tmp")
    jstmpdir = f"{tdir}/js_scitok_{uid}"
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


def getTmp() -> str:
    """return temp directory path"""
    return os.environ.get("TMPDIR", "/tmp")


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


@as_span("getExp")
def getExp() -> str:
    """return current experiment name"""
    if os.environ.get("GROUP", None):
        return str(os.environ.get("GROUP"))
    # otherwise guess primary group...
    exp: str
    with os.popen("id -gn", "r") as f:
        exp = f.read().strip()
    return exp


def getRole_from_default_role_file() -> Optional[str]:
    # if we have a default role pushed with a vault token, or $HOME/.jobsub_default... use that
    uid = os.getuid()
    environ_group = os.environ.get("GROUP")
    group = environ_group if environ_group else getExp()

    for prefix in ["/tmp/", f"{os.environ['HOME']}/.config/"]:
        fname = f"{prefix}jobsub_default_role_{group}_{uid}"

        if os.path.exists(fname) and os.stat(fname).st_uid == uid:
            with open(fname, "r") as f:  # pylint: disable=unspecified-encoding
                role = f.read().strip()
            return role
    return None


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


# pylint: disable=unused-argument
@as_span("getRole")
def getRole(role_override: Optional[str] = None, verbose: int = 0) -> str:
    """get current role.  Will check the following in order:
    1. role_override
    2. default role file
    3. Existing valid token
    4. Use default
    """
    if role_override:
        return role_override

    # Once we get to python 3.8, this can be changed to if (_role := getRole_from_default_role_file()): return _role,
    # and same for getRole_from_valid_token.  IMO, that's a bit clearer than this loop
    for role_location_try_func in (
        getRole_from_default_role_file,
        getRole_from_valid_token,
    ):
        _role = role_location_try_func()
        if _role:
            return _role

    return DEFAULT_ROLE


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


@as_span("checkToken_not_expired", arg_attrs=["*"])
def checkToken_not_expired(token: scitokens.SciToken) -> bool:
    """Make sure token in $BEARER_TOKEN_FILE is not (almost) expired"""
    exp_time = str(token.get("exp"))
    add_event(f"expiration: {exp_time}")
    return int(exp_time) - time.time() > 60


@as_span("getToken")
def getToken(role: str = DEFAULT_ROLE, verbose: int = 0) -> str:
    """get path to token file"""
    pid = os.getuid()
    tmp = getTmp()
    exp = getExp()
    if exp == "samdev":
        issuer: Optional[str] = "fermilab"
    else:
        issuer = exp

    if os.environ.get("BEARER_TOKEN_FILE", None) and os.path.exists(
        os.environ["BEARER_TOKEN_FILE"]
    ):
        # if we have a bearer token file set already, keep that one
        tokenfile = os.environ["BEARER_TOKEN_FILE"]
    else:
        tokenfile = f"{tmp}/bt_token_{issuer}_{role}_{pid}"
        os.environ["BEARER_TOKEN_FILE"] = tokenfile

    try:
        token_ok = checkToken(exp, role)
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

        if not checkToken(exp, role):
            raise PermissionError(f"Failed validating token from '{cmd}'")

    return tokenfile


# pylint: disable=too-many-locals
@as_span("getProxy")
def getProxy(
    role: str = DEFAULT_ROLE, verbose: int = 0, force_proxy: bool = False
) -> str:
    """get path to proxy certificate file and regenerate proxy if needed.
    Setting force_proxy=True will force regeneration of the proxy"""

    def generate_proxy_command_verbose_args(cmd_str: str) -> Dict[str, Any]:
        # Helper function to handle verbose and regular mode
        if verbose > 0:
            # Caller that sets up command will write stdout to stderr
            # Equivalent of >&2
            sys.stderr.write(f"Running: {cmd_str}\n")
            if isinstance(sys.stderr, io.StringIO):
                # being called from jobsub_api...
                return {}
            return {"stdout": sys.stderr}
        # Caller that sets up command will write stdout to /dev/null, stderr to stdout
        # Equivalent of >/dev/null 2>&1
        return {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.STDOUT,
        }

    pid = os.getuid()
    tmp = getTmp()
    exp = getExp()
    if exp == "samdev":
        issuer = "fermilab"
        igroup = "fermilab"
    elif exp in ("lsst", "dune", "fermilab", "des"):
        issuer = exp
        igroup = exp
    else:
        issuer = "fermilab"
        igroup = f"fermilab/{exp}"
    vomsfile = os.environ.get("X509_USER_PROXY", f"{tmp}/x509up_{exp}_{role}_{pid}")

    # If this is a read-only proxy, like managed proxies or POMS-uploaded proxy, don't touch it!
    if os.path.exists(vomsfile) and (not os.access(vomsfile, os.W_OK)):
        return vomsfile

    certfile = os.environ.get("X509_USER_PROXY", f"{tmp}/x509up_u{pid}")

    invalid_proxy = False
    if not force_proxy:
        chk_cmd_str = f"voms-proxy-info -exists -valid 0:10 -file {vomsfile}"
        extra_check_args = generate_proxy_command_verbose_args(chk_cmd_str)
        try:
            subprocess.run(shlex.split(chk_cmd_str), check=True, **extra_check_args)
        except subprocess.CalledProcessError:
            invalid_proxy = True

    if force_proxy or invalid_proxy:
        cigetcert_cmd_str = f"cigetcert -i 'Fermi National Accelerator Laboratory' -n --proxyhours 168 --minhours 167 -o {certfile}"
        cigetcert_cmd = subprocess.run(
            shlex.split(cigetcert_cmd_str),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            encoding="UTF-8",
            env=os.environ,
        )

        try:
            cigetcert_cmd.check_returncode()
        except subprocess.CalledProcessError:
            msg = f"Cigetcert failed to get a proxy due to an unspecified issue. Please inspect the output below.\n{cigetcert_cmd.stdout}"
            if "Kerberos initialization failed" in cigetcert_cmd.stdout:
                msg = (
                    "Cigetcert failed to get proxy due to kerberos issue.  Please ensure "
                    "you have valid kerberos credentials."
                )
            raise PermissionError(msg)

        voms_proxy_init_cmd_str = (
            f"voms-proxy-init -dont-verify-ac -valid 167:00 -rfc -noregen"
            f" -debug -cert {certfile} -key {certfile} -out {vomsfile} -vomslife 167:0"
            f" -voms {issuer}:/{igroup}/Role={role}"
        )
        extra_check_args = generate_proxy_command_verbose_args(voms_proxy_init_cmd_str)
        try:
            subprocess.run(
                shlex.split(voms_proxy_init_cmd_str),
                check=True,
                env=os.environ,
                **extra_check_args,
            )
        except subprocess.CalledProcessError:
            raise PermissionError(f"Failed attempting '{voms_proxy_init_cmd_str}'")
        else:
            return vomsfile

    return vomsfile


# pylint: disable=invalid-name
gfal_clean_env = "unset PYTHONHOME PYTHONPATH LD_LIBRARY_PATH GFAL_PLUGIN_DIR GFAL_CONFIG_DIR;  [ -s ${BEARER_TOKEN_FILE:-/dev/null} ] && export BEARER_TOKEN=`cat ${BEARER_TOKEN_FILE}`"


def fix_pnfs(path: str) -> str:
    if path[0] == "/":
        path = os.path.realpath(path)

    # use nfs4 mount if present
    mountpoint_end = path.find("/", 7)
    if os.path.isdir(path[:mountpoint_end]):
        return path

    # otherwise make an https/webdav path for it
    m = re.match(r"/pnfs/(.*)", path)
    if m:
        path = f"https://fndcadoor.fnal.gov:2880/{m.group(1)}"
    return path


def chmod(dest: str, mode: int) -> None:
    # can't really chmod over https, but can over nfs mount, so
    # just try with the raw path, and ignore it if it doesn't work
    try:
        os.chmod(dest, mode)
    except FileNotFoundError:
        pass
    except PermissionError:
        pass


def mkdir_p(dest: str) -> None:
    """make possibly multiple directories"""
    dest = fix_pnfs(dest)
    if 0 != os.system(f"{gfal_clean_env}; gfal-mkdir -p {dest}"):
        raise PermissionError(f"Error: Unable to make directory {dest}")


def ls(dest: str) -> List[str]:
    """make possibly multiple directories"""
    dest = fix_pnfs(dest)
    with os.popen(f"{gfal_clean_env}; gfal-ls {dest} 2>/dev/null") as f:
        files = [x.strip() for x in f.readlines()]
    return files


@as_span("cp", arg_attrs=["*"])
def cp(src: str, dest: str) -> None:
    """copy a (remote) file with gfal-copy"""
    src = fix_pnfs(src)
    dest = fix_pnfs(dest)
    if 0 != os.system(f"{gfal_clean_env}; gfal-copy {src} {dest}"):
        raise PermissionError(f"Error: Unable to copy {src} to {dest}")


if __name__ == "__main__":
    commands = {
        "getProxy": getProxy,
        "getToken": getToken,
        "checkToken": checkToken,
        "cp": cp,
        "ls": ls,
        "mkdir_p": mkdir_p,
        "getRole": getRole,
    }
    parser = argparse.ArgumentParser(description="ifdh subset replacement")
    parser.add_argument(
        "--experiment", help="experiment name", default=os.environ.get("GROUP", None)
    )
    parser.add_argument("--role", help="role name", default=None)
    parser.add_argument("command", action="store", nargs=1, help="command")
    parser.add_argument(
        "cpargs", default=None, action="append", nargs="*", help="copy arguments"
    )

    opts = parser.parse_args()
    myrole = getRole(opts.role)

    try:
        if opts.command[0] in ("cp", "ls", "mkdir_p", "checkToken"):
            print(commands[opts.command[0]](*opts.cpargs[0]))  # type: ignore
        else:
            result = commands[opts.command[0]](myrole, verbose=1)  # type: ignore
            if result is not None:
                print(result)
    except PermissionError as pe:
        sys.stderr.write(str(pe) + "\n")
        print("")
    except KeyError:
        print(
            "An invalid command to fake_ifdh was given.  Please select from "
            f'one of the following: {", ".join(commands.keys())}'
        )
