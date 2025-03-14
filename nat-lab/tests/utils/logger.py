import logging
import threading
from typing import Optional

LOG_LEVEL = logging.INFO


class Logger:
    def __init__(self, log_file: Optional[str] = None, level=logging.INFO):
        self._logger = logging.getLogger("natlab-logger")
        self._logger.setLevel(logging.DEBUG)
        self._lock = threading.Lock()

        if not self._logger.hasHandlers():
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(
                logging.Formatter("[%(asctime)s]: %(message)s")
            )
            self._logger.addHandler(console_handler)

            if log_file:
                file_handler = logging.FileHandler(log_file, mode="w")
                self.addFileHandler(file_handler)

    def log(self, level, message):
        assert self._logger, "Logger is not initialized"
        with self._lock:
            self._logger.log(level, message)

    def info(self, message):
        self.log(logging.INFO, message)

    def debug(self, message):
        self.log(logging.DEBUG, message)

    def warning(self, message):
        self.log(logging.WARNING, message)

    def error(self, message):
        self.log(logging.ERROR, message)

    def critical(self, message):
        self.log(logging.CRITICAL, message)

    def addFileHandler(self, handler: logging.FileHandler) -> None:
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
        )
        self._logger.addHandler(handler)

    def removeHandler(self, handler: logging.Handler) -> None:
        self._logger.removeHandler(handler)


log = Logger(level=LOG_LEVEL)
