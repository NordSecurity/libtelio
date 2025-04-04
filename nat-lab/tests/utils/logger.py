import logging

LOG_LEVEL = logging.INFO


class Logger:
    def __init__(self, level=logging.INFO):
        self.logger = logging.getLogger("natlab-logger")

        if not self.logger.hasHandlers():
            self.logger.setLevel(logging.DEBUG)

            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(
                logging.Formatter("%(asctime)s,%(msecs)03d | %(message)s")
            )
            self.logger.addHandler(console_handler)


log = Logger(level=LOG_LEVEL).logger
