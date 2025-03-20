import logging
from typing import Optional

LOG_LEVEL = logging.INFO


class Logger:
    def __init__(self, log_file: Optional[str] = None, level=logging.INFO):
        self.logger = logging.getLogger("natlab-logger")

        if not self.logger.hasHandlers():
            self.logger.setLevel(logging.DEBUG)

            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(
                logging.Formatter("[%(asctime)s]: %(message)s")
            )
            self.logger.addHandler(console_handler)

            if log_file:
                file_handler = logging.FileHandler(log_file, mode="w")
                self.logger.addHandler(file_handler)


log = Logger(level=LOG_LEVEL).logger
