import os
import re
from datetime import datetime
from typing import Optional, TypeVar

T = TypeVar("T")


def unpack_optional(opt: Optional[T]) -> T:
    if opt is None:
        raise ValueError("Optional value is None")
    return opt


def get_current_test_file_name() -> str | None:
    """
    Returns a string representing the filename of the currently running test.

    The result is derived from PYTEST_CURRENT_TEST env variable.

    For example:
    "tests/test_mesh_plus_vpn.py" -> "test_mesh_plus_vpn"
    """
    test_name = os.environ.get("PYTEST_CURRENT_TEST")
    if test_name is not None:
        try:
            # take the file path part of the pytest string, remove extension and parent directory
            file_part = test_name.split("::")[0].split(".")[0].split("/")[-1]
            return format_path_string(file_part)
        except IndexError:
            print(datetime.now(), "get_current_test_file_name() IndexError", test_name)
            return test_name
    print(datetime.now(), "PYTEST_CURRENT_TEST is None")
    return None


def get_current_test_case_name() -> str | None:
    """
    Returns a string representing the case name of the currently running test.

    The result is derived from PYTEST_CURRENT_TEST env variable.

    For example:
    "tests/test_mesh_plus_vpn.py::test_vpn_plus_mesh_over_direct" -> "test_vpn_plus_mesh_over_direct"
    """
    test_name = os.environ.get("PYTEST_CURRENT_TEST")
    if test_name is not None:
        try:
            test_part = test_name.split("::", 1)[-1].split(" ")[0].split("[", 1)[0]
            return format_path_string(test_part)
        except IndexError:
            print(datetime.now(), "get_current_test_case_name() IndexError", test_name)
            return test_name
    print(datetime.now(), "PYTEST_CURRENT_TEST is None")
    return None


def get_current_test_parameter_name() -> str | None:
    """
    Returns an optional string representing the parameters of the currently running test.

    The result is derived from PYTEST_CURRENT_TEST env variable.

    For example:
    "[CONE_CLIENT_2-Default-local-stun-CONE_CLIENT_1-LinuxNativeWg-local-stun]" -> "CONE_CLIENT_2_Default_local_stun_CONE_CLIENT_1_LinuxNativeWg_local_stun"
    """
    test_name = os.environ.get("PYTEST_CURRENT_TEST")
    if test_name is not None:
        try:
            parameter_part = test_name.split("::")[-1].split(" ")[0].split("[", 1)[1]
            return format_path_string(parameter_part)
        except IndexError:
            print(
                datetime.now(),
                "get_current_test_parameter_name() IndexError",
                test_name,
            )
            return None
    print(datetime.now(), "PYTEST_CURRENT_TEST is None")
    return None


def format_path_string(input_str: str) -> str:
    """
    Format the input string to be safely used as a system path or file name.
    """
    # truncate if it's longer than 64 characters to limit long absolute paths
    # replace any non-alphanumeric characters, and the last "_" if it is present
    return re.sub(r"\W+", "_", input_str[:64]).rstrip("_")


def get_current_test_log_path(base_dir: str) -> str:
    """
    Returns a path to the log files of the currently running test.
    """
    # format the base_dir
    if base_dir == "":
        base_dir = "logs"
    else:
        base_dir = format_path_string(base_dir)

    # get current test case, if we are in a test
    test_name = get_current_test_case_name()
    if test_name:
        logs_dir = os.path.join(base_dir, test_name)
        # add the test parameters suffx
        test_parameters = get_current_test_parameter_name()
        if test_parameters:
            return logs_dir + "_" + test_parameters
        # there were no parameters
        return logs_dir
    # we are not in a test
    return base_dir
