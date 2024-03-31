import logging
from concurrent_log import ConcurrentTimedRotatingFileHandler as _handler

class ConcurrentLogger:

    def __init__(self, **kwargs):
        self._level = kwargs.pop("level", logging.INFO)
        self._filename = kwargs.pop("filename", "./logs/default.log")
        self._datefmt = kwargs.pop("datefmt", "%Y-%m-%d %H:%M:%S")
        self._format = kwargs.pop("format", "%(asctime)s [%(module)s] %(levelname)s [%(lineno)d] %(message)s")
        self._divide = kwargs.pop("divide", "midnight")
        self.log = logging.getLogger(self._filename)
        self.thread = _handler(filename=self._filename, when=self._divide, encoding="utf-8")
        self.thread.setFormatter(logging.Formatter(self._format, self._datefmt))
        self.thread.setLevel(self._level)

    def info(self, _text):
        self.log.addHandler(self.thread)
        self.log.setLevel(logging.INFO)
        self.log.info(_text)
        self.log.removeHandler(self.thread)

    def error(self, _text):
        self.log.addHandler(self.thread)
        self.log.setLevel(logging.ERROR)
        self.log.error(_text)
        self.log.removeHandler(self.thread)
