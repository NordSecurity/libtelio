import os
from typing import Optional, TypeVar

T = TypeVar("T")


def unpack_optional(opt: Optional[T]) -> T:
    if opt is None:
        raise ValueError("Optional value is None")
    return opt


def test_name_safe_for_file_name():
    test_name = os.environ.get("PYTEST_CURRENT_TEST")
    if test_name is not None:
        return "".join([x if x.isalnum() else "_" for x in test_name.split(" ")[0]])
    return test_name
