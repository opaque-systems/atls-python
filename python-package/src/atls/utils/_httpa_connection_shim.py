from typing import Any, ClassVar, Dict, List, Optional, Tuple

from atls import ATLSContext
from atls.httpa_connection import HTTPAConnection
from atls.validators import Validator
from urllib3.util.connection import _TYPE_SOCKET_OPTIONS
from urllib3.util.timeout import _DEFAULT_TIMEOUT, _TYPE_TIMEOUT


class _HTTPAConnectionShim(HTTPAConnection):
    """
    Provides impendance-matching at the interface between urllib3 and the
    HTTPAConnection class.
    """

    Validators: ClassVar[List[Validator]]

    is_verified: bool = True

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        timeout: _TYPE_TIMEOUT = _DEFAULT_TIMEOUT,
        source_address: Optional[Tuple[str, int]] = None,
        blocksize: int = 8192,
        socket_options: Optional[_TYPE_SOCKET_OPTIONS] = None,
        **_kwargs: Dict[str, Any],
    ) -> None:
        context = ATLSContext(self.Validators)

        super().__init__(
            host,
            context,
            port,
            timeout,
            source_address,
            blocksize,
            socket_options,
        )
