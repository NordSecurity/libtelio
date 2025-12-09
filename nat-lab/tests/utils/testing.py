import os
import re
import warnings
from tests.utils.logger import log
from typing import Optional, Tuple, TypeVar

MAX_PATH_LENGTH = 192
MAX_PARAMETER_LENGTH = 64

T = TypeVar("T")


def log_test_passed() -> None:
    """
    Logs that the test case has passed.

    It should be called at the end of a block with `async with AsyncExitStack()` in the tests.
    """
    # Use the full test ID from pytest (including file path) to ensure uniqueness
    # PYTEST_CURRENT_TEST format: "tests/path/test_file.py::test_name[params] (call)"
    full_test_id = os.environ.get("PYTEST_CURRENT_TEST", "unknown").split(" (")[0]
    log.info("TEST CASE PASSED: %s", full_test_id)


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
    return (None, None)


def _format_path_string(input_str: str) -> str:
    """
    Format the input string to be safely used as a system path or file name.
    """
    # replace any non-alphanumeric characters with "_"
    # remove any trailing "_"
    return re.sub(r"\W+", "_", input_str).rstrip("_")


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
            if len(test_parameters) > MAX_PARAMETER_LENGTH:
                warnings.warn(
                    f"""parameter path is too long: {len(test_parameters)} > {MAX_PARAMETER_LENGTH}.
                please consider anotating the parameters with 'id=' or 'ids='."""
                )
            result = logs_dir + "_" + test_parameters
        # there were no parameters
        else:
            result = logs_dir
    # we are not in a test
    else:
        result = base_dir

    # check if the total path name is too log
    # on windows absolute path to a file must not exceed 255 characters
    assert (
        len(result) < MAX_PATH_LENGTH
    ), f"""log path too long: {len(result)} >= {MAX_PATH_LENGTH}.
    please shorten the test name and anotate the parameters with 'id=' or 'ids='."""

    return result
