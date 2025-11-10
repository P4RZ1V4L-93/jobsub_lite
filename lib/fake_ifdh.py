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
import re
import sys
from typing import List


# TODO: Do we need this anymore since we're IN lib?  # pylint: disable=fixme
PREFIX = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PREFIX, "lib"))


import creds  # pylint: disable=wrong-import-position
import cred_token  # pylint: disable=wrong-import-position
from defaults import DEFAULT_ROLE  # pylint: disable=wrong-import-position
from tracing import as_span  # pylint: disable=wrong-import-position


@as_span("getProxy")
def getProxy(
    role: str = DEFAULT_ROLE, verbose: int = 0, force_proxy: bool = False
) -> str:
    """Deprecated as of version 1.13.  This will now raise a NotImplementedError.

    Old behavior: get path to proxy certificate file and regenerate proxy if needed.
    Setting force_proxy=True will force regeneration of the proxy
    """

    raise NotImplementedError(
        "fake_ifdh.getProxy is no longer implemented. "
        "Please obtain your proxy outside of jobsub, and "
        "then set X509_USER_PROXY to the path of your proxy."
    )


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
    except (FileNotFoundError, PermissionError):
        # We don't want to fail the submission over not being able to chmod a file
        pass


def mkdir_p(dest: str) -> None:
    """make possibly multiple directories with gfal-mkdir -p"""
    dest = fix_pnfs(dest)
    if 0 != os.system(f"{gfal_clean_env}; gfal-mkdir -p {dest}"):
        raise PermissionError(f"Error: Unable to make directory {dest}")


def ls(dest: str) -> List[str]:
    """list directory contents with gfal-ls"""
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
        "getToken": cred_token.getToken,
        "checkToken": cred_token.checkToken,
        "cp": cp,
        "ls": ls,
        "mkdir_p": mkdir_p,
        "getRole": creds.getRole,
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
    myrole = creds.getRole(opts.role)

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
