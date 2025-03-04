import logging
import threading
from typing import Optional


class Logger:
    def __init__(self, log_file: Optional[str] = None, level=logging.INFO):
        self._logger = logging.getLogger("natlab-log")
        self._logger.setLevel(level)
        self._lock = threading.Lock()

        if not self._logger.hasHandlers():
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter("[%(asctime)s]: %(message)s")
            )
            self._logger.addHandler(console_handler)

            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(
                    logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
                )

                self._logger.addHandler(file_handler)

    def log(self, level, message):
        with self._lock:
            self._logger.log(level, message)

    def set_level(self, level):
        with self._lock:
            self._logger.setLevel(level)

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


log = Logger()
