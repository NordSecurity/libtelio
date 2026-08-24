import logging

from natlab.logger import configure_cli_logging, log

LOG_LEVEL = logging.INFO

# natlab's logger is library-style (no handlers); these tests expect console output
if all(isinstance(handler, logging.NullHandler) for handler in log.handlers):
    configure_cli_logging(LOG_LEVEL)


class SetupLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return f"[SETUP] {msg}", kwargs


setup_log = SetupLoggerAdapter(log, {})
