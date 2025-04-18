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
"""argument parser, used multiple places, so defined here"""
# pylint: disable=too-few-public-methods
import argparse
import difflib
import os
import re
from typing import Union, Any, Optional, List
from version import version_string

from condor import get_schedd_names
from creds import SUPPORTED_AUTH_METHODS, REQUIRED_AUTH_METHODS
import pool
from skip_checks import SupportedSkipChecks
from utils import DEFAULT_USAGE_MODELS, DEFAULT_SINGULARITY_IMAGE


def verify_executable_starts_with_file_colon(s: str) -> str:
    """routine to give argparse to verify the executable parameter,
    which is supposed to be given as a file:///path URL
    -- note we could check the file exists here, too.
    """
    if s.startswith("file://"):
        return s
    raise TypeError("executable must start with file://")


# Custom actions for parsers
class StoreGroupinEnvironment(argparse.Action):
    """Action to store the given group in the GROUP environment variable"""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Union[None, str] = None,
    ) -> None:
        os.environ["GROUP"] = values
        setattr(namespace, self.dest, values)


class ConvertDebugToVerbose(argparse.Action):
    """Action to convert the --debug flag to --verbose 1"""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Union[None, str] = None,
    ) -> None:
        setattr(namespace, self.dest, True)
        setattr(namespace, "verbose", 1)


class VerifyAndAddSkipCheck(argparse.Action):
    """Action to verify that the given skip-check argument is in the allowed
    list of checks to skip.  If it supported, the argument is added to the list
    of checks to skip, and the attribute skip_check_{argument} is set to True in
    the given namespace"""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Union[None, str] = None,
    ) -> None:
        _supported_checks = SupportedSkipChecks.get_all_checks()
        if values not in _supported_checks:
            raise TypeError(
                f'Invalid argument to flag --skip-check: "{values}". Value must '
                f"be one of the following: {_supported_checks}"
            )
        checks_to_skip = getattr(namespace, self.dest, [])
        if values not in checks_to_skip:
            checks_to_skip.append(values)
            setattr(namespace, self.dest, checks_to_skip)
            new_arg_to_set = f"skip_check_{values}"
            setattr(namespace, new_arg_to_set, True)


class CheckIfValidSchedd(argparse.Action):
    """Action to check if the tester has requested a valid schedd to submit to"""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Union[None, str] = None,
    ) -> None:
        group = os.environ.get("JOBSUB_GROUP", os.environ.get("GROUP", None))
        vargs = {"group": group} if group is not None else {}
        valid_schedds = get_schedd_names(vargs, available_only=False)
        if values not in valid_schedds:
            raise TypeError(
                f"Invalid schedd specified: {values}.  Valid choices are {valid_schedds}"
            )
        setattr(namespace, self.dest, values)


class CheckIfValidAuthMethod(argparse.Action):
    """Argparse Action to check if the caller has requested a valid auth method"""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Union[None, str] = None,
    ) -> None:
        check_values = [value.strip() for value in values.split(",")]
        check_values = list(
            filter(lambda val: val != "", check_values)
        )  # Clear out empty string
        if len(check_values) == 0:
            setattr(namespace, self.dest, ",".join(SUPPORTED_AUTH_METHODS))
            return

        # Check that the requested auth methods include the required auth methods
        if len(set(REQUIRED_AUTH_METHODS).intersection(set(check_values))) == 0:
            msg_add = ""
            for val in check_values:
                msg_add += self.__get_msg_from_close_val(val, REQUIRED_AUTH_METHODS)
            raise ValueError(
                "The jobsub_lite infrastructure requires that the following "
                f"authorization methods be present: {REQUIRED_AUTH_METHODS}.{msg_add}"
            )

        for value in check_values:
            if value not in SUPPORTED_AUTH_METHODS:
                msg_add = self.__get_msg_from_close_val(value, SUPPORTED_AUTH_METHODS)
                raise ValueError(
                    f"Invalid auth method {value}.  Supported auth methods are {SUPPORTED_AUTH_METHODS}.{msg_add}"
                )
        setattr(namespace, self.dest, ",".join(check_values))

    @staticmethod
    def __get_msg_from_close_val(value: str, valid_values: List[str]) -> str:
        """If our value is close to a valid value, return a message asking if the user meant
        the valid value.  Otherwise, return an empty string"""
        did_you_mean_str = " You provided '{value}' - did you mean '{close_match}'?"
        close_match = difflib.get_close_matches(value, valid_values, n=1)
        return (
            did_you_mean_str.format(value=value, close_match=close_match[0])
            if len(close_match) > 0
            else ""
        )


# Parsers


def get_base_parser(
    parser: Optional[argparse.ArgumentParser] = None,
) -> argparse.ArgumentParser:
    """Build the general jobsub command argument parser and return it

    If parser is given (not None), then this function will modify parser directly.
    Otherwise, it will use a new argparse.ArgumentParser.
    """

    if parser is None:
        parser = argparse.ArgumentParser()

    group = parser.add_argument_group("general arguments")

    # default to JOBSUB_GROUP rather than GROUP if set
    if os.environ.get("JOBSUB_GROUP", ""):
        os.environ["GROUP"] = os.environ["JOBSUB_GROUP"]

    group.add_argument(
        "--auth-methods",
        help=(
            "Authorization method to use for job management. "
            "Multiple values should be given in a comma-separated list, "
            'e.g. "token,proxy".'
            f"Currently supported methods are {SUPPORTED_AUTH_METHODS}. "
            f"The current infrastructure requires the following auth methods: {REQUIRED_AUTH_METHODS}"
        ),
        action=CheckIfValidAuthMethod,
        required=False,
        default=os.environ.get("JOBSUB_AUTH_METHODS", ",".join(SUPPORTED_AUTH_METHODS)),
    )
    group.add_argument(
        "-G",
        "--group",
        help="Group/Experiment/Subgroup for priorities and accounting",
        action=StoreGroupinEnvironment,
        default=os.environ.get("GROUP", None),
    )
    parser.add_argument(
        "--global-pool",
        default="",
        action=pool.SetPool,
        help="direct jobs/commands to a particular known global pool."
        f"Currently known pools are: {' '.join(pool.get_poolmap().keys())}",
    )
    group.add_argument(
        "--role",
        help="VOMS Role for priorities and accounting",
    )
    group.add_argument(
        "--subgroup",
        help=" Subgroup for priorities and accounting. See https://cdcvs.fnal.gov/redmine/projects/jobsub/wiki/ Jobsub_submit#Groups-Subgroups-Quotas-Priorities for more documentation on using --subgroup to set job quotas and priorities",
    )
    group.add_argument(
        "--verbose",
        type=int,
        default=0,
        help="Turn on more information on internal state of program. --verbose 1 is the same as --debug",
    )
    group.add_argument(
        "--debug",
        action=ConvertDebugToVerbose,
        nargs=0,
        help="dump internal state of program (useful for debugging)",
    )
    parser.add_argument(
        "--devserver",
        default=False,
        action="store_true",
        help="Use jobsubdevgpvm01 etc. to submit",
    )
    group.add_argument(
        "--version",
        action="version",
        version=version_string(),
    )
    group.add_argument(
        "--support-email",
        action="store_true",
        help="jobsub_lite support email",
        default=False,
    )
    parser.add_argument(
        "--schedd-for-testing",  # Non-advertised option for testers to direct jobs to certain schedds
        type=str,
        action=CheckIfValidSchedd,
        help=argparse.SUPPRESS,
    )
    return parser


def get_submit_parser(
    parser: Optional[argparse.ArgumentParser] = None,
) -> argparse.ArgumentParser:
    """Build the jobsub argument parser for the condor_submit/condor_submit_dag commands and return it.

    If parser is given (not None), then this function will modify parser directly.
    Otherwise, it will use a new argparse.ArgumentParser.
    """
    parser = get_base_parser(parser=parser)
    parser.add_argument(
        "--job-info",
        action="append",
        default=[],
        help="script to call with jobid and command line when job is submitted",
    )
    parser.add_argument(
        "--need-storage-modify",
        action="append",
        default=[],
        help="directories needing storage.modify scope in job tokens",
    )
    parser.add_argument(
        "--need-scope",
        action="append",
        default=[],
        help="scopes needed in job tokens",
    )
    return parser


def get_jobid_parser(
    parser: Optional[argparse.ArgumentParser] = None,
) -> argparse.ArgumentParser:
    """Build the jobsub_cmd (jobsub_q, etc.) argument parser and return it.

    If parser is given (not None), then this function will modify parser directly.
    Otherwise, it will use a new argparse.ArgumentParser.
    """
    parser = get_base_parser(parser=parser)
    parser.add_argument("-J", "--jobid", dest="jobid", help="job/submission ID")
    parser.add_argument(
        "--constraint",
        help="Condor constraint to filter jobs returned.  See https://htcondor.readthedocs.io/en/latest/classads/classad-mechanism.html for more details",
    )
    return parser


# pylint: disable=too-many-statements
def get_parser(
    parser: Optional[argparse.ArgumentParser] = None,
) -> argparse.ArgumentParser:
    """Build the jobsub_submit argument parser and return it.

    If parser is given (not None), then this function will modify parser directly.
    Otherwise, it will use a new argparse.ArgumentParser.
    """
    parser = get_submit_parser(parser)
    parser.add_argument(
        "-c",
        "--append_condor_requirements",
        "--append-condor-requirements",
        action="append",
        default=[],
        help="append condor requirements",
    )
    parser.add_argument(
        "--blocklist",
        "--blacklist",
        dest="blocklist",
        help="ensure that jobs do not land at these (comma-separated) sites",
        default="",
    )
    parser.add_argument("-r", help="Experiment release version")
    parser.add_argument("-i", help="Experiment release dir")
    parser.add_argument("-t", help="Experiment test release dir")
    parser.add_argument(
        "--cmtconfig",
        default=os.environ.get("CMTCONFIG", ""),
        help=" Set up minervasoft release built with cmt configuration. default is $CMTCONFIG",
    )
    parser.add_argument(
        "--cpu", metavar="NUMBER", help="Request worker nodes have at least NUMBER cpus"
    )
    parser.add_argument(
        "--dag",
        help="submit and run a dagNabbit input file",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--dataset-definition",
        "--dataset_definition",
        "--dataset",
        help="SAM dataset definition used in a Directed Acyclic Graph (DAG)",
    )
    parser.add_argument(
        "--dd-percentage",
        help="percentage to apply to SAM dataset size for --dataset-definition start job.",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--dd-extra-dataset",
        help="SAM dataset definition start script extra dataset to check as staged. You can add multiple of them.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--disk",
        help="Request worker nodes have at least NUMBER[UNITS] of disk space."
        " If UNITS is not specified default is 'KB' (a typo in earlier"
        " versions said that default was 'MB', this was wrong)."
        " Allowed values for UNITS are 'KB','MB','GB', and 'TB'",
        default="10GB",
    )
    parser.add_argument(
        "-d",
        nargs=2,
        action="append",
        default=[],
        metavar=("tag", "dir"),
        help="-d <tag> <dir> Writable directory $CONDOR_DIR_<tag> will exist"
        " on the execution node. After job completion, its contents will"
        " be moved to <dir> automatically."
        " Specify as many <tag>/<dir> pairs as you need.",
    )
    parser.add_argument(
        "--email-to",
        default=f"{os.environ['USER']}@fnal.gov",
        help="email address to send job reports/summaries"
        " (default is $USER@fnal.gov)",
    )
    parser.add_argument(
        "-e",
        "--environment",
        default=[],
        action="append",
        help=" -e ADDED_ENVIRONMENT exports this variable with its local value"
        " to worker node environment. For example export FOO='BAR';"
        " jobsub -e FOO <more stuff> guarantees that the value of $FOO"
        " on the worker node is 'BAR' . Alternate format which does not"
        " require setting the env var first is the -e VAR=VAL idiom,"
        " which sets the value of $VAR to 'VAL' in the worker environment."
        " The -e option can be used as many times in one jobsub_submit"
        " invocation as desired.",
    )
    parser.add_argument(
        "--expected-lifetime",
        help=" 'short'|'medium'|'long'|NUMBER[UNITS] Expected lifetime of the"
        " job. Used to match against resources advertising that they have"
        " REMAINING_LIFETIME seconds left. The shorter your EXPECTED_LIFTIME"
        " is, the more resources (aka slots, cpus) your job can potentially"
        " match against and the quicker it should start. If your job runs"
        " longer than EXPECTED_LIFETIME it *may* be killed by the batch"
        " system."
        " If your specified EXPECTED_LIFETIME is too long your job may"
        " take a long time to match against a resource a sufficiently long"
        " REMAINING_LIFETIME. Valid inputs for this parameter are:"
        " 'short', 'medium', 'long' IF [UNITS] is omitted, value is NUMBER"
        " seconds. Allowed values for UNITS are 's', 'm', 'h', 'd'"
        " representing seconds, minutes, etc.The values for"
        " 'short','medium',and 'long' are configurable by Grid Operations,"
        " they currently are '3h' , '8h' , and '85200s' but this may"
        " change in the future.",
        default="8h",
    )
    parser.add_argument(
        "-f",
        dest="input_file",
        default=[],
        action="append",
        help="INPUT_FILE at runtime, INPUT_FILE will be copied to directory"
        " $CONDOR_DIR_INPUT on the execution node. Example :"
        " -f /grid/data/minerva/my/input/file.xxx will be copied to"
        " $CONDOR_DIR_INPUT/file.xxx Specify as many"
        " -f INPUT_FILE_1 -f INPUT_FILE_2 args as you need. To copy file at"
        " submission time instead of run time, use -f dropbox://INPUT_FILE"
        " to copy the file.  If -f is used without the dropbox:// URI, for"
        " example -f /path/to/myfile, then the file (/path/to/myfile in this"
        " example) MUST be grid-accessible via ifdh."
        ""
        " For more information, please see https://github.com/fermitools/jobsub_lite/wiki/File-Transfers-in-jobsub-lite",
    )
    parser.add_argument(
        "--generate-email-summary",
        action="store_true",
        default=False,
        help="generate and mail a summary report of completed/failed/removed"
        " jobs in a DAG",
    )
    parser.add_argument(
        "--gpu", metavar="NUMBER", help="request worker nodes have at least NUMBER cpus"
    )
    parser.add_argument(
        "-L", "--log-file", "--log_file", help="Log file to hold log output from job."
    )
    parser.add_argument(
        "-l",
        "--lines",
        action="append",
        default=[""],
        help="Lines to append to the job file.",
    )
    parser.add_argument(
        "--project-name",
        "--project_name",
        default="",
        help="Project name for --dataset-definition DAGs to share",
    )
    parser.add_argument(
        "-Q",
        "--mail_never",
        "--mail-never",
        dest="mail",
        action="store_const",
        const="Never",
        default="Never",
        help="never send mail about job results (default)",
    )

    parser.add_argument(
        "--mail_on_error",
        "--mail-on-error",
        dest="mail",
        action="store_const",
        const="Error",
        help="send mail about job results if job fails",
    )
    parser.add_argument(
        "--mail_always",
        "--mail-always",
        dest="mail",
        action="store_const",
        const="Always",
        help="send mail about job results",
    )

    parser.add_argument(
        "--maxConcurrent",
        type=int,
        default=0,
        help="max number of jobs running concurrently at given time.  Use in"
        " conjunction with -N option to protect a shared resource. Example:"
        " jobsub -N 1000 -maxConcurrent 20 will only run 20 jobs at a time"
        " until all 1000 have completed. This is implemented by running the"
        " jobs in a DAG. Normally when jobs are run with the -N option, they"
        " all have the same $CLUSTER number and differing, sequential"
        " $PROCESS numbers, and many submission scripts take advantage of this."
        " When jobs are run with this option in a DAG each job has a different"
        " $CLUSTER number and a $PROCESS number of 0, which may break scripts"
        " that rely on the normal -N numbering scheme for $CLUSTER and $PROCESS."
        " Groups of jobs run with this option will have the same"
        " $JOBSUBPARENTJOBID, each individual job will have a unique and"
        " sequential $JOBSUBJOBSECTION. Scripts may need modification to take"
        " this into account",
    )
    parser.add_argument(
        "--managed-token",
        action="store_const",
        const=True,
        default=os.environ.get("JOBSUB_MANAGED_TOKEN", "").lower()
        not in ["0", "false", "", "no"],
        help="Will attempt to bypass calling condor_vault_storer during job submission. "
        "Assumes that vault token is managed externally, so condor_vault_storer will "
        "only be called once every six days.",
    )
    parser.add_argument(
        "--memory",
        default="2GB",
        help="Request worker nodes have at least NUMBER[UNITS] of memory."
        " If UNITS is not specified default is 'MB'.  Allowed values "
        " for UNITS are 'KB','MB','GB', and 'TB'",
    )
    parser.add_argument(
        "-N",
        default=1,
        type=int,
        help="submit N copies of this job. Each job will have access to the"
        " environment variable $PROCESS that provides the job number"
        " (0 to NUM-1), equivalent to the number following the decimal"
        " point in the job ID (the '2' in 134567.2).",
    )
    parser.add_argument(
        "-n",
        "--no_submit",
        "--no-submit",
        default=False,
        action="store_true",
        help="generate condor_command file but do not submit",
    )
    parser.add_argument(
        "--no-env-cleanup",
        default=False,
        action="store_true",
        help="do not clean environment in wrapper script",
    )
    parser.add_argument(
        "--OS",
        default=None,
        help="specify OS version of worker node. Example --OS=SL5 Comma"
        " separated list '--OS=SL4,SL5,SL6' works as well. Default is any"
        " available OS",
    )
    parser.add_argument(
        "--overwrite-condor-requirements",
        "--overwrite_condor_requirements",
        help="overwrite default condor requirements with supplied requirements",
    )
    parser.add_argument(
        "--resource-provides",
        action="append",
        default=[],
        help="request specific resources by changing condor jdf file. For"
        " example: --resource-provides=CVMFS=OSG will add"
        ' +DESIRED_CVMFS="OSG" to the job classad attributes and'
        " '&&(CVMFS==\"OSG\")' to the job requirements",
    )
    parser.add_argument(
        "--skip-check",
        type=str,
        action=VerifyAndAddSkipCheck,
        default=[],
        help="Skip checks that jobsub_lite does by default.  Add as many --skip-check "
        f"flags as desired.  Available checks are {SupportedSkipChecks.get_all_checks()}. "
        "Example:  --skip-check rcds",
    )
    parser.add_argument(
        "--tar_file_name",
        "--tar-file-name",
        default=[],
        action="append",
        help="    dropbox://PATH/TO/TAR_FILE\n     tardir://PATH/TO/DIRECTORY\n"
        "specify TAR_FILE or DIRECTORY to be transferred to worker node."
        " TAR_FILE will be copied with RCDS/cvmfs (or /pnfs),"
        " transferred to the job and unpacked there."
        " The unpacked contents of TAR_FILE will be available inside the"
        " directory $INPUT_TAR_DIR_LOCAL.  If using the PNFS dropbox (not default),"
        " TAR_FILE will be accessible to the user job on the worker node"
        " via the environment variable $INPUT_TAR_FILE.  The unpacked"
        " contents will be in the same directory as $INPUT_TAR_FILE."
        " For consistency, when using the default (RCDS/cvmfs) dropbox,"
        " $INPUT_TAR_FILE will be set in such a way that the parent directory"
        " of $INPUT_TAR_FILE will contain the unpacked contents of TAR_FILE."
        " Successive --tar_file_name options will be in"
        " $INPUT_TAR_DIR_LOCAL_1, $INPUT_TAR_DIR_LOCAL_2, etc. and"
        " $INPUT_TAR_FILE_1, $INPUT_TAR_FILE_2, etc."
        ""
        " We note here that with this flag, it is recommended to use the"
        " $INPUT_TAR_DIR_LOCAL environment variable, rather than $INPUT_TAR_FILE"
        ""
        " For more information, please see https://github.com/fermitools/jobsub_lite/wiki/File-Transfers-in-jobsub-lite",
    )

    parser.add_argument(
        "--tarball-exclusion-file",
        default=None,
        help="File with patterns to exclude from tarffile creation",
    )
    parser.add_argument(
        "--timeout",
        help="kill user job if still running after NUMBER[UNITS] of time."
        " UNITS may be `s' for seconds (the default), `m' for minutes,"
        " `h' for hours or `d' h for days.",
    )
    parser.add_argument(
        "--use-cvmfs-dropbox",
        dest="use_dropbox",
        action="store_const",
        const="cvmfs",
        help="use cvmfs for dropbox (default is cvmfs)",
        default=None,
    )
    parser.add_argument(
        "--use-pnfs-dropbox",
        dest="use_dropbox",
        action="store_const",
        const="pnfs",
        help="use pnfs resilient for dropbox (default is cvmfs)",
        default=None,
    )
    parser.add_argument(
        "executable",
        type=verify_executable_starts_with_file_colon,
        default=None,
        nargs="?",
        help="executable for job to run",
    )

    usage_model_group = parser.add_mutually_exclusive_group()
    usage_model_group.add_argument(
        "--site",
        type=str,
        default="",
        help="submit jobs to these (comma-separated) sites",
    )
    usage_model_group.add_argument(
        "--onsite",
        "--onsite-only",
        dest="usage_model",
        action="store_const",
        const="OPPORTUNISTIC,DEDICATED",
        default=",".join(DEFAULT_USAGE_MODELS),
        help="run jobs locally only; usage_model=OPPORTUNISTIC,DEDICATED",
    )
    usage_model_group.add_argument(
        "--offsite",
        "--offsite-only",
        dest="usage_model",
        action="store_const",
        const="OFFSITE",
        default=",".join(DEFAULT_USAGE_MODELS),
        help="run jobs offsite; usage_model=OFFSITE",
    )

    singularity_group = parser.add_mutually_exclusive_group()
    singularity_group.add_argument(
        "--singularity-image",
        "--apptainer-image",
        default=DEFAULT_SINGULARITY_IMAGE,
        help="Singularity image to run jobs in.  Default is "
        "/cvmfs/singularity.opensciencegrid.org/fermilab/fnal-wn-el9:latest",
    )
    singularity_group.add_argument(
        "--no-singularity",
        "--no-apptainer",
        action="store_true",
        help="Don't request a singularity container.  If the site your job "
        "lands on runs all jobs in singularity containers, your job will "
        "also run in one.  If the site does not run all jobs in "
        "singularity containers, your job will run outside a singularity "
        "container.",
    )

    parser.add_argument(
        "exe_arguments", nargs=argparse.REMAINDER, help="arguments to executable"
    )

    return parser


def get_condor_epilog(condor_cmd: str) -> str:
    epilog_l = []

    with os.popen(f"/usr/bin/{condor_cmd} -h 2>&1", "r") as fd:
        epilog_l = fd.readlines()

    epilog_l[0] = re.sub(
        f"Usage:.*{condor_cmd}", f"also {condor_cmd} arguments:", epilog_l[0]
    )
    epilog_l[0] += "(with single '-' or double '--' dashes)\n"

    if condor_cmd == "condor_q":
        # condor_q's help says that it defaults to jobs for the current user,
        # but jobsub_q's default is jobs for the current group, so we adjust it here
        for i in range(len(epilog_l)):  # pylint: disable=consider-using-enumerate
            epilog_l[i] = epilog_l[i].replace(
                "jobs owned by the current user",
                "jobs owned by the current jobsub group",
            )
    return "".join(epilog_l)
