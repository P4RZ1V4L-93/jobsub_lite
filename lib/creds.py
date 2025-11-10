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
import os
import pathlib
from typing import Any, Dict, Optional, List

from defaults import DEFAULT_ROLE
import packages
import cred_proxy
import cred_token
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
    group = args.get("group", cred_token.getExp())
    role = getRole(args.get("role", None))
    args["role"] = role

    # Set our auth_methods: Precedence:  --auth-methods, JOBSUB_AUTH_METHODS, REQUIRED_AUTH_METHODS
    auth_methods = resolve_auth_methods(args.get("auth_methods", None))

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
        t = cred_token.getToken(group, role, args.get("verbose", 0))
        t = t.strip()
        creds_to_return["token"] = t
    if "proxy" in auth_methods:
        # User must provide proxy in one of two places:
        # 1) X509_USER_PROXY environment variable
        # 2) A proxy file in their default location (usually /tmp/x509up_experiment_role_uid
        proxy_file = pathlib.Path(
            os.environ.get(
                "X509_USER_PROXY",
                str(cred_proxy.default_proxy_location(experiment=group, role=role)),
            ).strip()
        )
        cred_proxy.check_proxy(proxy_file, args.get("verbose", 0))
        p = str(proxy_file)
        creds_to_return["proxy"] = p
    obtained_creds = CredentialSet(**creds_to_return)
    return obtained_creds


def print_cred_paths_from_credset(cred_set: CredentialSet) -> None:
    """Print out the locations of the various credentials in the credential set"""
    for cred_type, cred_path in vars(cred_set).items():
        print(f"{cred_type} location: {cred_path}")


def resolve_auth_methods(arg_auth_method: Optional[str]) -> List[str]:
    """Resolve the list of auth methods to use based on the argument and environment variables"""
    # Set our auth_methods: Precedence:  --auth-methods, JOBSUB_AUTH_METHODS, REQUIRED_AUTH_METHODS
    if arg_auth_method is not None:
        return str(arg_auth_method).split(",")
    if os.environ.get("JOBSUB_AUTH_METHODS", False):
        return os.environ["JOBSUB_AUTH_METHODS"].split(",")
    return REQUIRED_AUTH_METHODS


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
    _role: Optional[str] = DEFAULT_ROLE
    for role_location_try_func in (
        getRole_from_default_role_file,
        cred_token.getRole_from_valid_token,
    ):
        _role = role_location_try_func()
        if _role:
            return _role

    return DEFAULT_ROLE


def getRole_from_default_role_file() -> Optional[str]:
    # if we have a default role pushed with a vault token, or $HOME/.jobsub_default... use that
    uid = os.getuid()

    for prefix in ["/tmp/", f"{os.environ['HOME']}/.config/"]:
        fname = f"{prefix}jobsub_default_role_{cred_token.getExp()}_{uid}"

        if os.path.exists(fname) and os.stat(fname).st_uid == uid:
            with open(fname, "r") as f:  # pylint: disable=unspecified-encoding
                role = f.read().strip()
            return role
    return None
