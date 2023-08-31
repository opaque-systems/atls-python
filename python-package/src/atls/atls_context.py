import base64
import secrets
import socket
import ssl
import warnings
from typing import List, Optional

import OpenSSL.crypto
import OpenSSL.SSL
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.extensions import Extension, ExtensionType

# TODO/HEGATTA: Either take the code from urllib3 that wraps PyOpenSSL or ditch
# PyOpenSSL altogether in favor of either modifying Python's SSL module to
# support custom certificate validation or switching to mbedTLS (and
# contributing support for custom certificate validation there).
warnings.filterwarnings("ignore", category=DeprecationWarning)
from atls.validators import Validator  # noqa: E402
from urllib3.contrib.pyopenssl import PyOpenSSLContext  # noqa: E402
from urllib3.contrib.pyopenssl import WrappedSocket  # noqa: E402


class ATLSContext(PyOpenSSLContext):
    """
    An SSL context that supports validation of aTLS certificates.

    Attention: Because this class manages the aTLS handshake's nonce, you must
    use different instances for different connections.

    Parameters
    ----------
    validators : list of Validator
        A list of one or more evidence or attestation result validators. During
        the TLS handshake, each validator in this list is queried for the
        certificate extension OID that contains the attestation document that
        the validator understands and if a corresponding extension is found in
        the peer's certificate, the validator is invoked.

    nonce : bytes, optional
        A random string of bytes to use as a nonce to ascertain the freshness
        of attestation evidence and mitigate replay attacks. If None, a random
        nonce is automatically generated.
    """

    def __init__(
        self, validators: List[Validator], nonce: Optional[bytes] = None
    ) -> None:
        super().__init__(ssl.PROTOCOL_TLSv1_2)

        if len(validators) == 0:
            raise ValueError("At least one validator is necessary")

        if nonce is None:
            nonce = secrets.token_bytes(32)

        self._validators = validators
        self._nonce = nonce

        self._ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, self._verify_certificate)

    def _verify_certificate(
        self,
        _conn: OpenSSL.SSL.Connection,
        x509: OpenSSL.crypto.X509,
        _err_no: int,
        _err_depth: int,
        _return_code: int,
    ) -> bool:
        """OpenSSL certificate validation callback"""

        peer_cert = x509.to_cryptography()

        for validator in self._validators:
            extension: Extension[ExtensionType]
            for extension in peer_cert.extensions:
                if validator.accepts(extension.oid):
                    if not hasattr(extension.value, "value"):
                        continue

                    document = extension.value.value
                    pub = peer_cert.public_key()
                    spki = pub.public_bytes(
                        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                    )

                    if validator.validate(document, spki, self._nonce):
                        return True

        return False

    def wrap_socket(self, sock: socket.socket) -> WrappedSocket:
        # To perform aTLS over regular TLS, we use the Server Name Indication
        # extension to carry the nonce.
        sni = base64.encodebytes(self._nonce)

        return super().wrap_socket(sock, False, True, True, sni)

    @property
    def validators(self) -> List[Validator]:
        return self._validators

    @validators.setter
    def validators(self, validators: List[Validator]) -> None:
        self._validators = validators

    @property
    def nonce(self) -> bytes:
        return self._nonce
