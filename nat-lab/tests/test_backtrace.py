import os
import pytest
from dataclasses import dataclass
from pathlib import PureWindowsPath
from tests.helpers import SetupParameters, Environment
from tests.libtelio_client import Client
from tests.uniffi.libtelio_proxy import BacktraceLocation, LibtelioError
from tests.utils.connection import ConnectionTag
from tests.utils.debug_symbols import (
    ResolvedFunction,
    libtelio_debug_files,
    resolve_return_addresses,
)
from typing import Awaitable, Callable, List, Optional

LIBTELIO_MODULES = {"libtelio.so", "libtelio.dylib", "telio.dll"}
RELEASE_PROFILE = "release"


@dataclass(frozen=True)
class ExpectedFrame:
    function: str
    # Line the frame must resolve to, None = only function name and file are verified.
    line: Optional[int] = None


@dataclass(frozen=True)
class ErrorSource:
    trigger: Callable[[Client], Awaitable[None]]
    message: str
    allowed_errors: List[str]
    calls_innermost_first: List[ExpectedFrame]
    file_name: str


STACK_PANIC = ErrorSource(
    trigger=lambda client: client.generate_stack_panic(),
    message="runtime_panic_test_call_stack",
    allowed_errors=[r"panicked at src.ffi\.rs"],
    calls_innermost_first=[
        ExpectedFrame("TelioError"),
        ExpectedFrame("catch_ffi_panic", 109),
        ExpectedFrame("generate_stack_panic", 1116),
    ],
    file_name="ffi.rs",
)

GENERATED_ERROR = ErrorSource(
    trigger=lambda client: client.generate_error(False),
    message="generated_error_test_call_stack",
    allowed_errors=[],
    calls_innermost_first=[
        ExpectedFrame("TelioError"),
        ExpectedFrame("quux", 1173),
        ExpectedFrame("baz", 1169),
        ExpectedFrame("bar", 1165),
        ExpectedFrame("foo", 1161),
        ExpectedFrame("catch_ffi_panic", 95),
        ExpectedFrame("generate_error", 1155),
    ],
    file_name="ffi.rs",
)

GENERATED_ASYNC_ERROR = ErrorSource(
    trigger=lambda client: client.generate_error(True),
    message="UnknownError: PollingPeriodZero",
    allowed_errors=[],
    calls_innermost_first=[
        ExpectedFrame("quux", 1038),
        ExpectedFrame("baz", 1034),
        ExpectedFrame("bar", 1030),
        ExpectedFrame("foo", 1026),
    ],
    file_name="device.rs",
)

ERROR_SOURCES = [
    pytest.param(STACK_PANIC, id="stack_panic"),
    pytest.param(GENERATED_ERROR, id="generated_error"),
    pytest.param(GENERATED_ASYNC_ERROR, id="generated_async_error"),
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


def verify_calls_in_order(
    source: ErrorSource, functions: List[ResolvedFunction]
) -> None:
    remaining = iter(functions)
    for frame in source.calls_innermost_first:
        resolved = next(
            (
                function
                for function in remaining
                if frame.function in function.function
                and PureWindowsPath(function.file).name == source.file_name
            ),
            None,
        )

        assert (
            resolved is not None
        ), f"{frame.function} ({source.file_name}) not found in order in: {functions}"
        if frame.line is not None:
            assert resolved.line == frame.line, (
                f"{frame.function}: expected {source.file_name}:{frame.line}, "
                f"got {resolved.file}:{resolved.line}"
            )


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
    verify_calls_in_order(error_source, resolved.functions)
