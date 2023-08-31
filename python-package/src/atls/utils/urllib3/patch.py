from typing import List

import urllib3
from atls.utils._httpa_connection_shim import _HTTPAConnectionShim
from atls.validators import Validator

_orig_urllib3_connection_cls = None


def inject_into_urllib3(validators: List[Validator]) -> None:
    """
    Monkey-patch aTLS support into urllib3.

    This function overrides the class that urllib3 uses for HTTPS connections
    with a wrapper for the HTTPAConnection class. The wrapper is necessary
    because the interface that urllib3 expects is not quite the same as that
    provided by HTTPAConnection (and which it should not provide).

    Injecting aTLS into urllib3 also allows the requests library to use aTLS,
    too.

    Call extract_from_urllib3() to undo the changes made by this function.
    """

    global _orig_urllib3_connection_cls
    _orig_urllib3_connection_cls = (
        urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls
    )

    _HTTPAConnectionShim.Validators = validators
    urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls = (
        _HTTPAConnectionShim
    )


def extract_from_urllib3() -> None:
    """Undoes the changes made by inject_into_urllib3()."""

    global _orig_urllib3_connection_cls
    if _orig_urllib3_connection_cls is None:
        return

    urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls = (
        _orig_urllib3_connection_cls
    )

    _orig_urllib3_connection_cls = None
