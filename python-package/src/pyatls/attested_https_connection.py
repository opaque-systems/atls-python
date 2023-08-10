import socket
from http.client import HTTPS_PORT, HTTPConnection

from .attested_tls_context import AttestedTLSContext  # noqa: E402


class AttestedHTTPSConnection(HTTPConnection):
    """
    Performs HTTP requests over an Attested TLS (aTLS) connection. It is
    equivalent to HTTPSConnection, but the underlying transport is aTLS instead
    of standard TLS.

    Parameters
    ----------
    host : str
        IP address or hostname to connect to.

    context : AtlsContext
        An aTLS context that performs the aTLS handshake.

    port : int
        Port to connect to.

    timeout : int
        Timeout for the attempt to connect to the host on the specified port.

    source_address : tuple[str, str]
        A pair of (host, port) for the client socket to bind to before
        connecting to the remote host.

    blocksize : int
        Size in bytes of blocks when sending and receiving data to and from the
        remote host, respectively.
    """

    default_port = HTTPS_PORT

    def __init__(
        self,
        host: str,
        context: AttestedTLSContext,
        port: int | None = None,
        timeout: int | None = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore
        source_address: tuple[str, int] | None = None,
        blocksize: int = 8192,
    ) -> None:
        super().__init__(host, port, timeout, source_address, blocksize)

        if not isinstance(context, AttestedTLSContext):
            raise ValueError("context must be an instance of AtlsContext")

        self._context = context

    def connect(self) -> None:
        super().connect()

        self.sock = self._context.wrap_socket(self.sock)
