# Python aTLS Package

An implementation of Attested TLS (aTLS) for Python.

Supports the client-side handshake against a custom attester that issues JWT
tokens via the Azure Attestation Service (AAS) running on Azure Container
Instance (ACI) instances.

For the moment, this package exists to support
[`promptguard`](https://pypi.org/project/promptguard/), a confidential
information redaction service that runs in a Trusted Execution Environment
(TEE).

**API Stability:** This package is still in development. As such, its API may
change until it is sufficiently mature.

**Note:** The server-side counterpart to this package is not yet public. If you
are interested in using the aTLS functionality in this package, please reach out
by filing an issue on [GitHub](https://github.com/opaque-systems/atls-python/).

## Overview

Confidential computing is an emerging field focused on protecting data not only
at rest and in transit, but also during use.

Typically, the security of a service running in the cloud depends on the
security and trustworthiness of the cloud fabric it is hosted on and of the
entity that provides the service. Additionally, there is no way for a user of
such a service to ascertain, with cryptographic proof, that the service they are
using really is the service they expect in terms of the very code that the
service runs.

In contrast to traditional service deployments, with confidential computing one
relies on Trusted Execution Environments, or TEEs. A TEE provides guarantees of
confidentiality and integrity of code and data as well as a mechanism for remote
entities to appraise its trustworthiness known as remote attestation, all rooted
in hardware.

During remote attestation, the user of a service running inside a TEE challenges
the service to produce evidence of its trustworthiness. This evidence includes
measurements of the hosting environment, including hardware, firmware, and
software stack that the service is running on, as well as measurements of the
service itself. In turn, these measurements are produced in such a way that they
are as trustworthy as the manufacturer of the TEE itself (e.g., Intel or AMD).

Perhaps most crucially, TEEs and remote attestation can be used to create
services that run in such a way that neither the cloud fabric nor the service
owner can neither access nor tamper with the service. That is, users of the
service may convince themselves through remote attestation that any data that
they share with the service will be shielded from the cloud fabric and also from
the service provider.

This package aims to implement remote attestation for various TEEs in Python.

## Design

The main workhorse of this package is the `ATLSContext` class. Instances of this
class are parameterized with one or more `Validator`s. A `Validator` can
understand and appraise evidence or attestation results issued by an attester or
verifier, respectively, contained in an attestation document created by an
issuer, itself embedded in a TLS certificate.

The appraisal of an attestation document takes the place of the typical
PKI-based certificate validation performed during regular TLS. By appraising an
attestation document via `Validator`s, the `ATLSContext` class binds the TLS
handshake not to a PKI-backed entity but to a genuine TEE.

## Sample Usage

The following snippet demonstrates how to use this package, assuming a service
running on a confidential ACI instance with the corresponding attestation
document issuer, and submit an HTTP request:

```python
from atls import ATLSContext, HTTPAConnection
from atls.validators.azure.aas import AciValidator

validator = AciValidator()
ctx = ATLSContext([validator])
conn = HTTPAConnection("my.confidential.service.net", ctx)

conn.request("GET", "/index")

response = conn.getresponse()

print(f"Status: {response.status}")
print(f"Response: {response.data.decode()}")

conn.close()
```

Alternatively, this package integrates into the
[`requests`](https://requests.readthedocs.io/) library by using the `httpa://`
scheme in lieu of `https://`, like so:

```python
import requests

from atls.utils.requests import HTTPAAdapter
from atls.validators.azure.aas import AciValidator

validator = AciValidator()
session = requests.Session()
session.mount("httpa://", HTTPAAdapter([validator]))

response = session.request("GET", "httpa://my.confidential.service.net/index")

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
```

**Note**: The `requests` library is not marked as a dependency of this package
because it is not required for its operation. As such, if you wish to use
`requests`, install it via `pip install requests` prior to importing
`HTTPAAdapter`.

## Further Reading

If you are unfamiliar with the terms used in this README and would like to learn
more, consider the following resources:

- [Confidential Computing at
  Wikipedia](https://en.wikipedia.org/wiki/Confidential_computing)
- [White Papers & Resources at the Confidential Computing
  Consortium](https://confidentialcomputing.io/resources/white-papers-reports/)
- [Remote Attestation Procedures RFC 9334 at the
  IETF](https://datatracker.ietf.org/doc/rfc9334/)
