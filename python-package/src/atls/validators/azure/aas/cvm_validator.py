from atls.validators import Validator
from cryptography.x509.oid import ObjectIdentifier


class CvmValidator(Validator):
    """
    Validates an attestation document issued for an Azure Confidential Virtual
    Machine (CVM) running on AMD SEV-SNP using the Azure Attestation Service
    (AAS)
    """

    @staticmethod
    def accepts(oid: ObjectIdentifier) -> bool:
        # 1.3.9999.2.1.1 = iso.identified-organization.reserved.azure.aas.cvm
        return oid == ObjectIdentifier("1.3.9999.2.1.1")

    def validate(
        self, document: bytes, public_key: bytes, nonce: bytes
    ) -> bool:
        raise NotImplementedError()
