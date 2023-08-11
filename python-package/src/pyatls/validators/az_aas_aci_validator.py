import base64
import hashlib
import json
import warnings
from typing import Any, Dict, List, Optional

import jwt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)
from cryptography.x509 import oid
from cryptography.x509.oid import ObjectIdentifier

from .validator import SecurityWarning, Validator


class AzAasAciValidator(Validator):
    """
    Validates an attestation document issued for a confidential Azure ACI
    container running on AMD SEV-SNP using the Azure Attestation Service (AAS).

    Parameters
    ----------
    policies : list of str, optional
        A list of one or more allowed plaintext Azure Confidential Computing
        Enforcement (CCE) policies. If no policies are provided, all policies
        are allowed, but a warning is issued.

    jkus : list of str, optional
        A list of one or more allowed JKU claim values. The JKU claim contains
        the URL of the JWKS server that contains the public key to use to
        verify the signature of the JWT token issued by AAS. If no JKU claim
        values are provided, all values are allowed, but a warning is issued.
    """

    def __init__(
        self,
        policies: Optional[List[str]] = None,
        jkus: Optional[List[str]] = None,
    ) -> None:
        super().__init__()

        self._inspect_policies(policies)
        self._policies = policies

        self._inspect_jkus(jkus)
        self._jkus = jkus

    @staticmethod
    def get_identifier() -> ObjectIdentifier:
        # 1.3.9999.2.1.2 = iso.identified-organization.reserved.azure.aas.aci
        return oid.ObjectIdentifier("1.3.9999.2.1.2")

    def validate(
        self, document: bytes, public_key: bytes, nonce: bytes
    ) -> bool:
        # This verifies the signature of the JWT, too.
        jwt = _verify_and_decode_token(document.decode(), self._jkus)

        # The runtime data structure must match exactly the structure generated
        # by the Go ACI attestation issuer.
        runtime_data = {
            "publicKey": base64.b64encode(public_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }

        # The JSON representation of the runtime data structure must match
        # exactly that generated by the Go ACI attestation issuer. In this
        # case, Go's JSON marshaller generates the most compact representation
        # possible (i.e., no whitespace), unlike Python's, so configure the
        # latter accordingly.
        runtime_data_json = json.dumps(runtime_data, separators=(",", ":"))
        runtime_data_json_hash = hashlib.sha256(runtime_data_json.encode())
        runtime_data_json_hash_hex = runtime_data_json_hash.hexdigest()

        # TODO/HEGATTA: The AAS SEV-SNP attestation endpoint expects the
        # runtime data hash to be SHA256 while SEV-SNP hardware itself expects
        # a 512-byte block. As such, the last 64 hex bytes in AAS' claim is
        # just zeroes. Ideally, AAS should accept a SHA512 hash of the runtime
        # data.
        aas_runtime_data_hash: str = jwt["x-ms-sevsnpvm-reportdata"]
        aas_runtime_data_hash = aas_runtime_data_hash[:64]

        if runtime_data_json_hash_hex != aas_runtime_data_hash:
            return False

        if jwt["x-ms-attestation-type"] != "sevsnpvm":
            return False

        if jwt["x-ms-compliance-status"] != "azure-compliant-uvm":
            return False

        if jwt["x-ms-sevsnpvm-is-debuggable"]:
            return False

        jwt_runtime: Dict[str, Any] = jwt["x-ms-runtime"]
        if base64.b64decode(jwt_runtime["nonce"]) != nonce:
            return False

        if base64.b64decode(jwt_runtime["publicKey"]) != public_key:
            return False

        if self._policies is not None:
            for policy in self._policies:
                policy_hash_hex = hashlib.sha256(policy.encode()).hexdigest()

                if jwt["x-ms-sevsnpvm-hostdata"] == policy_hash_hex:
                    return True

            return False

        return True

    @property
    def jkus(self) -> Optional[List[str]]:
        """List of allowed JKU claim values."""
        return self._jkus

    @jkus.setter
    def jkus(self, jkus: List[str]) -> None:
        self._inspect_jkus(jkus)
        self._jkus = jkus

    @staticmethod
    def _inspect_jkus(jkus: Optional[List[str]]) -> None:
        if jkus is None or len(jkus) == 0:
            warnings.warn(
                "No JKU whitelist provided, you should provide one to ensure "
                "that only trusted JWKS servers are used to retrieve JWT "
                "signature validation keys.",
                SecurityWarning,
            )

    @property
    def policies(self) -> Optional[List[str]]:
        """
        List of allowed Confidential Computing Enforcement (CCE) policies.
        """
        return self._policies

    @policies.setter
    def policies(self, policies: Optional[List[str]]) -> None:
        self._inspect_policies(policies)
        self._policies = policies

    @staticmethod
    def _inspect_policies(policies: Optional[List[str]]) -> None:
        if policies is None or len(policies) == 0:
            warnings.warn(
                "No CCE policies specified for validation, you should provide "
                "at least one to ensure that the ACI container instance you "
                "are attesting is running with the expected security "
                "properties",
                SecurityWarning,
            )


def _get_key_by_header(
    header: Dict[str, Any], jkus: Optional[List[str]]
) -> CertificatePublicKeyTypes:
    """
    Given an AAS-issued JWT header, this function contacts the JWKS server
    indicated by its JKU claim and attempts to find there the public key that
    corresponds to the JWT's signature.

    Parameters
    ----------
    header : dict of str to any
        An unverified JWT header issued by AAS containing a JKU claim.

    jkus : list of str, optional
        A list of trusted JWKS URLs (i.e., known-good values of the JKU claim).
        If the JKU claim in the provided header is not in this list, this
        function raises an exception.

    Returns
    -------
    public_key : CertificatePublicKeyTypes
        A decoded public key for use with Python's cryptography module that can
        be used to verify the signature of the JWT token whose unverified
        header was passed to this function.
    """
    jku: str = header["jku"]

    if jkus is not None and jku not in jkus:
        raise ValueError("Untrusted JKU found in token")

    kid: str = header["kid"]

    jwks_client = jwt.PyJWKClient(jku)
    for key in jwks_client.fetch_data().get("keys", []):
        if key["kid"] == kid:
            cert_der = jwt.utils.base64url_decode(key["x5c"][0])
            return x509.load_der_x509_certificate(cert_der).public_key()

    raise LookupError("No matching key was found in JWKS")


def _verify_and_decode_token(
    token: str, jkus: Optional[List[str]]
) -> Dict[str, Any]:
    """
    Given an AAS-issued JWT header, this function verifies its signature and
    decodes its claims.

    Parameters
    ----------
    token : str
        A JWT token issued by AAS.

    jkus : list of str, optional
        A list of trusted JWKS URLs (i.e., known-good values of the JKU claim).

    Returns
    -------
    claims : dict of str to any
        A dictionary containing the decoded claims from the provided JWT token.
    """
    hdr = jwt.get_unverified_header(token)

    return jwt.decode(token, _get_key_by_header(hdr, jkus), [hdr["alg"]])
