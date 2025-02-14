import os
import re
from datetime import datetime
from hashlib import md5
from typing import Optional, Tuple, TypeVar

MAX_PATH_LENGTH = 255

T = TypeVar("T")


def unpack_optional(opt: Optional[T]) -> T:
    if opt is None:
        raise ValueError("Optional value is None")
    return opt


def get_current_test_case_and_parameters() -> Tuple[Optional[str], Optional[str]]:
    """
    Returns a tuple of strings representing the case name and parameters of the currently running test.

    The result is derived from PYTEST_CURRENT_TEST env variable.
    """
    test_name = os.environ.get("PYTEST_CURRENT_TEST")
    if test_name:
        test_parts = test_name.split("::", 1)[-1].split(" ")[0].split("[", 1)
        if len(test_parts) > 1:
            return (
                _format_path_string(test_parts[0]),
                _format_path_string(test_parts[1]),
            )
        return (_format_path_string(test_parts[0]), None)
    print(datetime.now(), "PYTEST_CURRENT_TEST is None")
    return (None, None)


def _format_path_string(input_str: str) -> str:
    """
    Format the input string to be safely used as a system path or file name.
    """
    # replace any non-alphanumeric characters with "_"
    # remove any trailing "_"
    return re.sub(r"\W+", "_", input_str).rstrip("_")


def _shorten_path_if_needed(path: str) -> str:
    """
    Truncate the last segment and append a short hash to keep it unique.
    """
    if len(path) <= MAX_PATH_LENGTH:
        return path

    # make a short hash
    h = md5(path.encode("utf-8")).hexdigest()[:6]

    # truncate the last segment of the path
    head, tail = os.path.split(path)
    excess = len(path) - MAX_PATH_LENGTH
    keep_len = max(0, len(tail) - excess - len(h) - 2)
    truncated = tail[:keep_len]

    print(datetime.now(), "Test path:", tail, "truncated with hash:", h)
    return os.path.join(head, f"{truncated}_{h}")


def get_current_test_log_path(base_dir: str = "logs") -> str:
    """
    Returns a path to the log files of the currently running test.
    """
    base_dir = _format_path_string(base_dir)
    # get current test case, if we are in a test
    test_name, test_parameters = get_current_test_case_and_parameters()
    if test_name:
        logs_dir = os.path.join(base_dir, test_name)
        # add the test parameters suffx
        if test_parameters:
            result = logs_dir + "_" + test_parameters
        # there were no parameters
        else:
            result = logs_dir
    else:
        # we are not in a test
        result = base_dir

    return _shorten_path_if_needed(result)
