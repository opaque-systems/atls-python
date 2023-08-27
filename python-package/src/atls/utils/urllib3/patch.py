import socket
from typing import Any, Dict, List, Optional, Tuple

from atls import ATLSContext, HTTPAConnection
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

    class _HTTPAConnectionShim(HTTPAConnection):
        """
        Provides impendance-matching at the interface between urllib3 and the
        HTTPAConnection class.
        """

        def __init__(
            self,
            host: str,
            port: Optional[int] = None,
            timeout: int = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore
            source_address: Optional[Tuple[str, int]] = None,
            blocksize: int = 8192,
            # We use kwargs to catch additional parameters that urllib3 passes
            # to its selected HTTPS connection that we do not use and which we
            # do not want to expose to developers at the level of the
            # underlying class (i.e., HTTPSAConnection) because they will have
            # no use for them either.
            **_kwargs: Dict[str, Any],
        ) -> None:
            context = ATLSContext(validators)

            super().__init__(
                host, context, port, timeout, source_address, blocksize
            )

        def is_verified(self) -> bool:
            # This function returns whether the connection is SSL-enabled,
            # which it always is.
            return True

    import urllib3

    global _orig_urllib3_connection_cls
    _orig_urllib3_connection_cls = (
        urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls
    )

    urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls = (
        _HTTPAConnectionShim
    )


def extract_from_urllib3() -> None:
    """Undoes the changes made by inject_into_urllib3()."""

    global _orig_urllib3_connection_cls
    if _orig_urllib3_connection_cls is None:
        return

    import urllib3

    urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls = (
        _orig_urllib3_connection_cls
    )

    _orig_urllib3_connection_cls = None
