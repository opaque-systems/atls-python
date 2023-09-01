from typing import ClassVar, Optional, Tuple

from atls import ATLSContext
from urllib3.connection import HTTPConnection, port_by_scheme
from urllib3.util.connection import _TYPE_SOCKET_OPTIONS
from urllib3.util.timeout import _DEFAULT_TIMEOUT, _TYPE_TIMEOUT


class HTTPAConnection(HTTPConnection):
    """
    Performs HTTP requests over an Attested TLS (aTLS) connection. It is
    equivalent to HTTPSConnection, but the underlying transport is aTLS instead
    of standard TLS.

    Parameters
    ----------
    host : str
        IP address or hostname to connect to.

    context : ATLSContext
        An aTLS context that performs the aTLS handshake.

    port : int, optional
        Port to connect to.

    timeout : _TYPE_TIMEOUT
        Maximum amount of time, in seconds, to await an attempt to connect to
        the host on the specified port before timing out.

    source_address : tuple of str and int, optional
        A pair of (host, port) for the client socket to bind to before
        connecting to the remote host.

    blocksize : int
        Size in bytes of blocks when sending and receiving data to and from the
        remote host, respectively.

    socket_options: _TYPE_SOCKET_OPTIONS, optional
        A sequence of socket options to apply to the socket.
    """

    default_port: ClassVar[int] = port_by_scheme["https"]

    def __init__(
        self,
        host: str,
        context: ATLSContext,
        port: Optional[int] = None,
        timeout: _TYPE_TIMEOUT = _DEFAULT_TIMEOUT,
        source_address: Optional[Tuple[str, int]] = None,
        blocksize: int = 8192,
        socket_options: Optional[_TYPE_SOCKET_OPTIONS] = None,
    ) -> None:
        super().__init__(
            host,
            port,
            timeout=timeout,
            source_address=source_address,
            blocksize=blocksize,
            socket_options=socket_options,
        )

        self._context = context

    def connect(self) -> None:
        super().connect()

        self.sock = self._context.wrap_socket(self.sock)  # type: ignore
