#!/usr/bin/python3 -I
#
# cred_proxy -- utility functions for checking and using proxies
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

import io
import os
import pathlib
import shlex
import subprocess
import sys
from typing import Any, Dict, Optional, Union

# TODO: Do we need this anymore since we're IN lib?  # pylint: disable=fixme
PREFIX = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PREFIX, "lib"))

from defaults import DEFAULT_ROLE  # pylint: disable=wrong-import-position


# TODO Eventually, the next two funcs should move into utils.py, and be imported from there. But first, utils.py needs to be cleaned up
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


def check_proxy(proxy_file: Union[str, pathlib.Path], verbose: int = 0) -> None:
    """
    Check that the provided proxy file is valid.
    Args:

        proxy_file (Union[str, pathlib.Path]): Path to the proxy file to be checked.
        verbose (int, optional): Verbosity level for command output. Defaults to 0.

    Raises:
        JobsubInvalidProxyError: If the proxy file does not exist, is not readable,
        or is not a valid VOMS proxy.
    """
    if isinstance(proxy_file, str):
        _proxy_file = pathlib.Path(proxy_file)
    else:
        _proxy_file = proxy_file

    check_proxy_file(_proxy_file)  # Does proxy file exist, and is it readable?
    check_valid_proxy(_proxy_file, verbose)


def check_proxy_file(proxy_file: pathlib.Path) -> None:
    """
    Checks whether the specified proxy file exists and is readable.

    Args:
        proxy_file (pathlib.Path): The path to the proxy file to check.

    Raises:
        JobsubInvalidProxyError: If the proxy file does not exist or is not readable by the current user.
    """
    if not proxy_file.exists():
        raise JobsubInvalidProxyError("The proxy file does not exist.", str(proxy_file))
    if not os.access(proxy_file, os.R_OK):
        raise JobsubInvalidProxyError(
            "The proxy file is not readable by the current user.", str(proxy_file)
        )


def check_valid_proxy(proxy_file: pathlib.Path, verbose: int = 0) -> None:
    """
    Checks if the provided proxy file is a valid and non-expired VOMS proxy.

    Args:
        proxy_file (pathlib.Path): Path to the proxy file to be validated.
        verbose (int, optional): Verbosity level for command output. Defaults to 0.

    Raises:
        JobsubInvalidProxyError: If the proxy is not a valid VOMS proxy or has expired.
    """

    def _generate_proxy_command_verbose_args(
        cmd_str: str, verbose: int = 0
    ) -> Dict[str, Any]:
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

    chk_cmd_str = f"voms-proxy-info -exists -valid 0:10 -file {str(proxy_file)}"
    extra_check_args = _generate_proxy_command_verbose_args(chk_cmd_str, verbose)
    try:
        subprocess.run(shlex.split(chk_cmd_str), check=True, **extra_check_args)
    except subprocess.CalledProcessError as e:
        raise JobsubInvalidProxyError(
            "The proxy is not a valid VOMS proxy or has expired", str(proxy_file)
        ) from e
    except Exception as e:
        raise JobsubInvalidProxyError(
            "An unexpected error occurred while validating the proxy", str(proxy_file)
        ) from e


def default_proxy_location(
    experiment: Optional[str] = None, role: str = DEFAULT_ROLE
) -> pathlib.Path:
    """Return the default proxy location based on group and role"""
    experiment = getExp() if experiment is None else experiment
    return pathlib.Path(
        os.path.join(getTmp(), f"x509up_{experiment}_{role}_{os.getuid()}")
    )


class JobsubInvalidProxyError(Exception):
    """Exception raised for invalid proxies"""

    def __init__(self, message: str, proxy_path: str) -> None:
        self.message = message
        self.proxy_path = proxy_path
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"The proxy file at {self.proxy_path} is invalid: {self.message}"
