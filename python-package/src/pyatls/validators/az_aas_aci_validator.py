import base64
import hashlib
import json
from typing import Any, Dict, List, Optional

import jwt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)
from cryptography.x509.oid import ObjectIdentifier
from pyatls.validators.validator import Validator


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

        self._policies = policies
        self._jkus = jkus

    @staticmethod
    def accepts(oid: ObjectIdentifier) -> bool:
        # 1.3.9999.2.1.2 = iso.identified-organization.reserved.azure.aas.aci
        return oid == ObjectIdentifier("1.3.9999.2.1.2")

    def validate(
        self, document: bytes, public_key: bytes, nonce: bytes
    ) -> bool:
        # This verifies the signature of the JWT, too.
        try:
            token = _verify_and_decode_token(document.decode(), self._jkus)
        except jwt.PyJWTError:
            return False

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

        # A JWT token is valid if both of the following conditions are true:
        #
        # 1. It contains the keys we expect it to contain, and;
        # 2. The keys have the values we expect them to have.
        #
        # The first condition is the reason why we forgo .get() and explicitly
        # check for the presence of the keys.

        # TODO/HEGATTA: The AAS SEV-SNP attestation endpoint expects the
        # runtime data hash to be SHA256 while SEV-SNP hardware itself expects
        # a 512-byte block. As such, the last 64 hex bytes in AAS' claim is
        # just zeroes. Ideally, AAS should accept a SHA512 hash of the runtime
        # data.
        if "x-ms-sevsnpvm-reportdata" not in token:
            return False

        aas_runtime_data_hash: str = token["x-ms-sevsnpvm-reportdata"]
        aas_runtime_data_hash = aas_runtime_data_hash[:64]

        if runtime_data_json_hash_hex != aas_runtime_data_hash:
            return False

        if (
            "x-ms-attestation-type" not in token
            or token["x-ms-attestation-type"] != "sevsnpvm"
        ):
            return False

        if (
            "x-ms-compliance-status" not in token
            or token["x-ms-compliance-status"] != "azure-compliant-uvm"
        ):
            return False

        if (
            "x-ms-sevsnpvm-is-debuggable" not in token
            or token["x-ms-sevsnpvm-is-debuggable"]
        ):
            return False

        if "x-ms-runtime" not in token:
            return False

        token_runtime: Dict[str, Any] = token["x-ms-runtime"]

        if (
            "nonce" not in token_runtime
            or base64.b64decode(token_runtime["nonce"]) != nonce
        ):
            return False

        if (
            "publicKey" not in token_runtime
            or base64.b64decode(token_runtime["publicKey"]) != public_key
        ):
            return False

        if self._policies is not None:
            if "x-ms-sevsnpvm-hostdata" not in token:
                return False

            token_host_data = token["x-ms-sevsnpvm-hostdata"]
            for policy in self._policies:
                policy_hash_hex = hashlib.sha256(policy.encode()).hexdigest()

                if token_host_data == policy_hash_hex:
                    return True

            return False

        return True

    @property
    def jkus(self) -> Optional[List[str]]:
        """List of allowed JKU claim values."""
        return self._jkus

    @jkus.setter
    def jkus(self, jkus: List[str]) -> None:
        self._jkus = jkus

    @property
    def policies(self) -> Optional[List[str]]:
        """
        List of allowed Confidential Computing Enforcement (CCE) policies.
        """
        return self._policies

    @policies.setter
    def policies(self, policies: Optional[List[str]]) -> None:
        self._policies = policies


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
