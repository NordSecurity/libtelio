import os
import pytest
from dataclasses import dataclass
from pathlib import PureWindowsPath
from tests.helpers import SetupParameters, Environment
from tests.libtelio_client import Client
from tests.uniffi.libtelio_proxy import BacktraceLocation, LibtelioError
from tests.utils.connection import ConnectionTag
from tests.utils.debug_symbols import libtelio_debug_files, resolve_return_addresses
from typing import Awaitable, Callable, List

STACK_PANIC_LOG = r"panicked at src.ffi\.rs"
BACKTRACE_LOG = r"telio_utils::backtrace:\d+ backtrace: "
LIBTELIO_MODULES = {"libtelio.so", "libtelio.dylib", "telio.dll"}
RELEASE_PROFILE = "release"
ERROR_SOURCE_FILE = "ffi.rs"


@dataclass(frozen=True)
class ErrorSource:
    trigger: Callable[[Client], Awaitable[None]]
    message: str
    allowed_errors: List[str]
    calls_innermost_first: List[str]


STACK_PANIC = ErrorSource(
    trigger=lambda client: client.generate_stack_panic(),
    message="runtime_panic_test_call_stack",
    allowed_errors=[STACK_PANIC_LOG, BACKTRACE_LOG],
    calls_innermost_first=["TelioError", "catch_ffi_panic", "generate_stack_panic"],
)

GENERATED_ERROR = ErrorSource(
    trigger=lambda client: client.generate_error(),
    message="generated_error_test_call_stack",
    allowed_errors=[],
    calls_innermost_first=[
        "TelioError",
        "quux",
        "baz",
        "bar",
        "foo",
        "catch_ffi_panic",
        "generate_error",
    ],
)

ERROR_SOURCES = [
    pytest.param(STACK_PANIC, id="stack_panic"),
    pytest.param(GENERATED_ERROR, id="generated_error"),
]

SETUP_PARAMS = [
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
            is_meshnet=False,
        ),
    ),
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.VM_WINDOWS_1,
            is_meshnet=False,
        ),
        marks=[pytest.mark.windows],
    ),
    pytest.param(
        SetupParameters(
            connection_tag=ConnectionTag.VM_MAC,
            is_meshnet=False,
        ),
        marks=[pytest.mark.mac],
    ),
]


async def trigger_error(client: Client, source: ErrorSource) -> LibtelioError:
    client.allow_errors(source.allowed_errors)
    with pytest.raises(LibtelioError, match=source.message) as error:
        await source.trigger(client)
    return error.value


def libtelio_frames(error: LibtelioError) -> List[BacktraceLocation]:
    return [
        location for location in error.backtrace if location.module in LIBTELIO_MODULES
    ]


def calls_in_order(expected: List[str], functions: List[str]) -> bool:
    remaining = iter(functions)
    return all(any(name in function for function in remaining) for name in expected)


@pytest.mark.skipif(
    os.getenv("TELIO_BIN_PROFILE") != RELEASE_PROFILE,
    reason="only release builds have debug files",
)
@pytest.mark.parametrize("error_source", ERROR_SOURCES)
@pytest.mark.parametrize("alpha_setup_params", SETUP_PARAMS)
async def test_error_backtrace_resolves(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    error_source: ErrorSource,
    env: Environment,
) -> None:
    client, *_ = env.clients
    error = await trigger_error(client, error_source)
    frames = libtelio_frames(error)
    assert frames, f"no libtelio frame in backtrace: {error.backtrace}"
    addresses = [frame.address for frame in frames if frame.address is not None]
    assert len(addresses) == len(frames), f"libtelio frames without address: {frames}"
    library, debug = libtelio_debug_files(client.get_connection().target_os)

    resolved = await resolve_return_addresses(library, debug, addresses)

    assert {frame.module_id for frame in frames} == {resolved.module_id}
    error_source_functions = [
        function.function
        for function in resolved.functions
        if PureWindowsPath(function.file).name == ERROR_SOURCE_FILE
    ]
    assert calls_in_order(
        error_source.calls_innermost_first, error_source_functions
    ), f"unexpected functions in backtrace: {resolved.functions}"
