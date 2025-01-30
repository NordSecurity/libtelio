import asyncio
from typing import List, Optional
from utils.connection import Connection
from utils.process import ProcessExecError


class CommandGrepper:
    _connection: Connection
    _check_cmd: List[str]
    _timeout: Optional[float]
    _last_stdout: Optional[str]

    def __init__(
        self,
        connection: Connection,
        check_cmd: List[str],
        timeout: Optional[float] = None,
    ):
        """
        A class that runs a command and checks if the expected strings are present or not present in the output.

        Args:
            connection: Connection object to container to run the command on.
            check_cmd: Command to run.
            timeout: Timeout for the check. If the check does not have expected results within the timeout, it will return False.
        """
        self._connection = connection
        self._check_cmd = check_cmd
        self._timeout = timeout
        self._last_stdout = None

    def get_stdout(self) -> Optional[str]:
        return self._last_stdout

    async def check_exists(
        self, exp_primary: str, exp_secondary: Optional[List[str]] = None
    ) -> bool:
        """
        Checks if the expected strings are present in the output of the command.
        If only the primary string is provided, check for its presence in whole stdout.
        If secondary strings are also provided, checks, if primary and all secondaries are in one line

        Returns True if string is found.
        Returns False if string is not found and TimeoutError is caught.
        Raises a `PorcessExecError` if command returns non zero value.
        Raises an `Exception` if something else wrong happens.
        """
        try:
            return await asyncio.wait_for(
                self._run_check(exp_primary, exp_secondary, True),
                self._timeout,
            )
        except ProcessExecError as e:
            print(f"Process exec error: {e}")
            raise
        except TimeoutError as e:
            print(f"Timeout error: {e}, last stdout: {self._last_stdout}")
            return False
        except Exception as e:
            print(f"Some other exception happened: {e}")
            raise

    async def check_not_exists(
        self, exp_primary: str, exp_secondary: Optional[List[str]] = None
    ) -> bool:
        """
        Check if the expected strings are not present in the output of the command.
        If only the primary string is provided, check for its absence in whole stdout.
        If secondary strings are also provided, checks, if primary and secondary are NOT in one line.

        Returns True if string is not found.
        Returns False if string is found and TimeoutError is caught.
        Raises a `PorcessExecError` if command returns non zero value.
        Raises an `Exception` if something else wrong happens.
        """
        try:
            return await asyncio.wait_for(
                self._run_check(exp_primary, exp_secondary, exists=False),
                self._timeout,
            )
        except ProcessExecError as e:
            print(f"Process exec error: {e}, last stdout: {self._last_stdout}")
            raise
        except TimeoutError as e:
            print(f"Timeout error: {e}, last stdout: {self._last_stdout}")
            return False
        except Exception as e:
            print(
                f"Some other exception happened: {e}, last stdout: {self._last_stdout}"
            )
            raise

    async def _run_check(
        self, exp_primary: str, exp_secondary: Optional[List[str]], exists: bool
    ) -> bool:
        while True:
            process = await self._connection.create_process(self._check_cmd).execute()
            self._last_stdout = process.get_stdout()

            if exists:
                if self._check_if_exists(self._last_stdout, exp_primary, exp_secondary):
                    return True
            else:
                if self._check_if_not_exists(
                    self._last_stdout, exp_primary, exp_secondary
                ):
                    return True

            await asyncio.sleep(1.0)

    def _check_if_exists(
        self, stdout: str, exp_primary: str, exp_secondary: Optional[List[str]]
    ) -> bool:
        # Both primary and secondary strings are expected to be in one line
        for line in stdout.split("\n"):
            if exp_primary in line:
                if exp_secondary is not None:
                    missing = False
                    for expected_str in exp_secondary:
                        if expected_str not in line:
                            missing = True
                            break
                    if not missing:
                        return True
                else:
                    return True
        return False

    def _check_if_not_exists(
        self, stdout: str, exp_primary: str, exp_secondary: Optional[List[str]]
    ) -> bool:
        if exp_secondary is not None:
            for line in stdout.split("\n"):
                missing = True
                if exp_primary in line:
                    for expected_str in exp_secondary:
                        if expected_str in line:
                            missing = False
                            break
                    if not missing:
                        return False
            return True
        if exp_primary not in stdout:
            return True

        return False
