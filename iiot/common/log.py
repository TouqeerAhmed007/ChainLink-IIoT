import logging
import os
import sys
import time

_COL = {"DEBUG": "36", "INFO": "32", "WARNING": "33", "ERROR": "31", "CRITICAL": "35"}


class _Fmt(logging.Formatter):
    def format(self, record):
        t = time.strftime("%H:%M:%S", time.localtime(record.created)) + f".{int(record.msecs):03d}"
        comp = record.name.removeprefix("iiot.")
        msg = record.getMessage()
        if os.environ.get("IIOT_NOCOLOR") == "1":
            return f"[{t}] [{comp}] {msg}"
        c = _COL.get(record.levelname, "0")
        return f"\x1b[2m[{t}]\x1b[0m \x1b[{c}m[{comp}]\x1b[0m {msg}"


def get_logger(name: str) -> logging.Logger:
    lg = logging.getLogger(f"iiot.{name}")
    if not lg.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(_Fmt())
        lg.addHandler(h)
        lg.setLevel(os.environ.get("IIOT_LOGLEVEL", "INFO").upper())
        lg.propagate = False
    return lg
