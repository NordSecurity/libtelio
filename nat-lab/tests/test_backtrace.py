import pytest
from tests.helpers import SetupParameters, Environment
from tests.uniffi.libtelio_proxy import LibtelioError
from tests.utils.connection import ConnectionTag

STACK_PANIC_MESSAGE = "runtime_panic_test_call_stack"
STACK_PANIC_LOG = r"panicked at src.ffi\.rs"
BACKTRACE_LOG = r"telio_utils::backtrace:\d+ backtrace: "
LIBTELIO_MODULES = {"libtelio.so", "libtelio.dylib", "telio.dll"}


@pytest.mark.parametrize(
    "alpha_setup_params",
    [
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
    ],
)
async def test_panic_error_has_backtrace(
    alpha_setup_params: SetupParameters,  # pylint: disable=unused-argument
    env: Environment,
) -> None:
    client, *_ = env.clients
    client.allow_errors([STACK_PANIC_LOG, BACKTRACE_LOG])

    with pytest.raises(LibtelioError, match=STACK_PANIC_MESSAGE) as error:
        await client.generate_stack_panic()

    assert any(
        location.module in LIBTELIO_MODULES for location in error.value.backtrace
    ), f"no libtelio frame in backtrace: {error.value.backtrace}"
