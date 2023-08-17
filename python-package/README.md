# Python aTLS Package

An implementation of Attested TLS (aTLS) for Python.

Supports the client-side handshake against a custom attester that issues JWT
tokens via the Azure Attestation Service (AAS) running on Azure Container
Instance (ACI) instances.

For the moment, this package exists to support [`promptguard`](PyPi), a
confidential information redaction service that runs in a Trusted Execution
Environment (TEE).

**Note:** The server-side counterpart to this package is not yet public. If you
are interested in using the aTLS functionality in this package, please reach out
by filing an issue on [GitHub](https://github.com/opaque-systems/atls-python/).

## Overview

The main workhorse of this package is the `AttestedTLSContext` class. Instances
of this class are parameterized with one or more `Validator`s. A `Validator` can
understand and appraise evidence or attestation results issued by an attester or
verifier, respectively, contained in an attestation document created by an
issuer, itself embedded in a TLS certificate.

The appraisal of an attestation document takes the place of the typical
PKI-based certificate validation performed during regular TLS. By appraising an
attestation document via `Validator`s, the `AttestedTLSContext` class binds the
TLS handshake not to a PKI-backed entity but to a genuine TEE.

## Sample Usage

The following snippet demonstrates how to use this package, assuming a service
running on a confidential ACI instnace with the corresponding attestation
document issuer, and submit an HTTP request:

```python
from pyatls import AttestedHTTPSConnection, AttestedTLSContext
from pyatls.validators import AzAasAciValidator

validator = AzAasAciValidator()
ctx = AttestedTLSContext([validator])
conn = AttestedHTTPConnection("my.confidential.service.net", ctx)

conn.request("GET", "/index")
print(conn.getresponse().read().decode())
```
