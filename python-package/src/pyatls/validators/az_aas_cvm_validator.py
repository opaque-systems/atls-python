from cryptography.x509 import oid
from cryptography.x509.oid import ObjectIdentifier
from pyatls.validators.validator import Validator


class AzAasCvmValidator(Validator):
    """
    Validates an attestation document issued for an Azure Confidential Virtual
    Machine (CVM) running on AMD SEV-SNP using the Azure Attestation Service
    (AAS)
    """

    @staticmethod
    def get_identifier() -> ObjectIdentifier:
        # 1.3.9999.2.1.1 = iso.identified-organization.reserved.azure.aas.cvm
        return oid.ObjectIdentifier("1.3.9999.2.1.1")

    def validate(
        self, document: bytes, public_key: bytes, nonce: bytes
    ) -> bool:
        raise NotImplementedError()
