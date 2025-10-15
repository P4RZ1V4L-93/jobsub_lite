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
"""credential related routines"""
import io
import os
import pathlib
import shlex
import subprocess
import sys
from typing import Any, Dict, Optional, List, Union

import fake_ifdh
import packages
from tracing import as_span


REQUIRED_AUTH_METHODS = [
    value.strip()
    for value in os.environ.get("JOBSUB_REQUIRED_AUTH_METHODS", "token").split(",")
]


class CredentialSet:
    """Class to hold credential paths for supported auth methods.  The __init__ method
    here defines what credentials we support"""

    # TODO Add __iter__ method so that we can explicitly return the credentials in an iterator # pylint: disable=fixme
    # rather than relying on the magic of vars()?

    # Environment Variables corresponding to each supported auth method
    TOKEN_ENV = "BEARER_TOKEN_FILE"
    PROXY_ENV = "X509_USER_PROXY"

    def __init__(self, token: Optional[str] = None, proxy: Optional[str] = None):
        self.token: Optional[str] = token
        self.proxy: Optional[str] = proxy
        self._set_environment_for_credentials()

    def _set_environment_for_credentials(self) -> None:
        """Set environment variables for credentials"""
        for cred_type, cred_path in vars(self).items():
            if not cred_path:
                continue
            self_key = f"{cred_type.upper()}_ENV"
            environ_key = getattr(self, self_key, None)
            if environ_key:
                os.environ[environ_key] = cred_path
                # This needs to be added so that any credential we set stays in both the environment
                # modified before get_creds() is called (such as the POMS pkg_find case) and the
                # environment in which this function is called.  So far, that seems to only be the case
                # for submissions that use the poms_client, so when that is moved to POMS, this can be removed.
                packages.add_to_SAVED_ENV_if_not_empty(environ_key, cred_path)


SUPPORTED_AUTH_METHODS = list(
    set(list(vars(CredentialSet())) + REQUIRED_AUTH_METHODS)
)  # Dynamically populate our SUPPORTED_AUTH_METHODS, and make sure it includes REQUIRED_AUTH_METHODS


# pylint: disable=dangerous-default-value
@as_span("get_creds")
def get_creds(args: Dict[str, Any] = {}) -> CredentialSet:
    """get credentials for job operations"""
    role = fake_ifdh.getRole(args.get("role", None))
    args["role"] = role

    # Set our auth_methods: Precedence:  --auth-methods, JOBSUB_AUTH_METHODS, REQUIRED_AUTH_METHODS
    auth_methods: List[str] = REQUIRED_AUTH_METHODS
    if args.get("auth_methods", None):
        auth_methods = str(args.get("auth_methods")).split(",")
    elif os.environ.get("JOBSUB_AUTH_METHODS", False):
        auth_methods = os.environ["JOBSUB_AUTH_METHODS"].split(",")

    # One last check to make sure we have the required auth methods
    if len(set(REQUIRED_AUTH_METHODS).intersection(set(auth_methods))) == 0:
        raise TypeError(
            f"Missing required authorization method(s) {list(set(REQUIRED_AUTH_METHODS).difference(set(auth_methods)))} "
            f"in requested authorization methods {auth_methods}"
        )

    if args.get("verbose", 0) > 0:
        print(f"Requested auth methods are: {auth_methods}")

    creds_to_return: Dict[str, Optional[str]] = {
        cred_type: None for cred_type in SUPPORTED_AUTH_METHODS
    }
    if "token" in auth_methods:
        t = fake_ifdh.getToken(role, args.get("verbose", 0))
        t = t.strip()
        creds_to_return["token"] = t
    if "proxy" in auth_methods:
        # User must provide proxy in one of two places:
        # 1) X509_USER_PROXY environment variable
        # 2) A proxy file in their default location (usually /tmp/x509up_experiment_role_uid
        experiment = fake_ifdh.getExp()
        uid = os.getuid()
        tmp = fake_ifdh.getTmp()
        proxy_file = pathlib.Path(
            os.environ.get(
                "X509_USER_PROXY",
                os.path.join(tmp, f"x509up_{experiment}_{role}_{uid}"),
            ).strip()
        )
        check_proxy(proxy_file, args.get("verbose", 0))
        p = str(proxy_file)
        creds_to_return["proxy"] = p
    obtained_creds = CredentialSet(**creds_to_return)
    return obtained_creds


def print_cred_paths_from_credset(cred_set: CredentialSet) -> None:
    """Print out the locations of the various credentials in the credential set"""
    for cred_type, cred_path in vars(cred_set).items():
        print(f"{cred_type} location: {cred_path}")


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
    chk_cmd_str = f"voms-proxy-info -exists -valid 0:10 -file {str(proxy_file)}"
    extra_check_args = _generate_proxy_command_verbose_args(chk_cmd_str, verbose)
    try:
        subprocess.run(shlex.split(chk_cmd_str), check=True, **extra_check_args)
    except subprocess.CalledProcessError as e:
        raise JobsubInvalidProxyError(
            "The proxy is not a valid VOMS proxy or has expired", str(proxy_file)
        ) from e


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


class JobsubInvalidProxyError(Exception):
    """Exception raised for invalid proxies"""

    def __init__(self, message: str, proxy_path: str) -> None:
        self.message = message
        self.proxy_path = proxy_path
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"The proxy file at {self.proxy_path} is invalid: {self.message}"
