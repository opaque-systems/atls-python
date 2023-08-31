#!/usr/bin/python3

# Sample usage of the atls package
#
# Suppose a simple HTTP server with a single GET endpoint /index is running
# over aTLS in an AMD SEV-SNP-backed Azure ACI container instance on HOST:PORT.
# Suppose further that this service is issuing attestation documents via the
# Azure Attestation Service (AAS), particularly using the publicly available
# endpoint in the East US 2 region, and is running with the debug Confidential
# Computing Enforcement (CCE) policy. Then, you can run this program as
# follows from the directory where this file is located:
#
# python3 connect_aci.py                                  \
#   --host HOST                                           \
#   --port PORT                                           \
#   --policy aci_debug_policy.rego                        \
#   --jku https://sharedeus2.eus2.attest.azure.net/certs  \
#   --method GET                                          \
#   --url /index

import argparse
import ast
import warnings
from typing import List, Mapping, Optional

import urllib3
from atls import ATLSContext, HTTPAConnection
from atls.utils.requests import HTTPAAdapter
from atls.utils.urllib3 import extract_from_urllib3, inject_into_urllib3
from atls.validators import Validator
from atls.validators.azure.aas import AciValidator
from cryptography.x509.oid import ObjectIdentifier

# Parse arguments
parser = argparse.ArgumentParser()

parser.add_argument(
    "--server", required=True, help="IP or hostname to connect to"
)

parser.add_argument(
    "--port", default=443, help="port to connect to (default: 443)"
)

parser.add_argument(
    "--method",
    default="GET",
    help="HTTP method to use in the request (default: GET)",
)

parser.add_argument(
    "--url",
    default="/index",
    help="URL to perform the HTTP request against (default: /index)",
)

parser.add_argument(
    "--policy",
    nargs="*",
    help="path to a CCE policy in Rego format, may be specified multiple "
    "times, once for each allowed policy (default: ignore)",
)

parser.add_argument(
    "--jku",
    nargs="*",
    action="extend",
    help="allowed JWKS URL to verify the JKU claim in the AAS JWT token "
    "against, may be specified multiple times, one for each allowed value "
    "(default: ignore)",
)

parser.add_argument(
    "--body",
    type=argparse.FileType("r"),
    help="path to a file containing the content to include in the request "
    "(default: nothing)",
)

parser.add_argument(
    "--headers",
    type=argparse.FileType("r"),
    help="path to a file containing the string representation of a Python "
    "dictionary containing the headers to be sent along with the request "
    "(default: none)",
)

parser.add_argument(
    "--loops",
    default=1,
    help="number of times to perform the request to evaluate the impact of "
    "connection pooling (default: 1)",
)

parser.add_argument(
    "--use-injection",
    action="store_true",
    help="inject aTLS support under the urllib3 library to automatically "
    "upgade all HTTPS connections into HTTP/aTLS (default: false)",
)

parser.add_argument(
    "--use-requests",
    action="store_true",
    help="use the requests library with the HTTPS/aTLS adapater (default: "
    "false)",
)

parser.add_argument(
    "--insecure",
    action="store_true",
    help="disable attestation (testing only) (default false)",
)

args = parser.parse_args()

if args.insecure and (args.policy or args.jku):
    raise Exception(
        "Cannot specify --policy and/or --jku alongside --insecure"
    )

loops: int = int(args.loops)
if loops == 0 or loops < 0:
    raise ValueError(f"Invalid loop count: {loops}")

policy_files: Optional[List[str]] = args.policy
jkus: Optional[List[str]] = args.jku

# Read in the specified Rego policies, if any.
policies: Optional[List[str]] = None
if policy_files is not None:
    policies = []
    for filepath in policy_files:
        with open(filepath) as f:
            policies.append(f.read())


class NullValidator(Validator):
    """
    A validator that accepts any evidence, effectively bypassing attestation.

    This can be useful to evaluate the overhead of the attestation process. For
    example, when using AAS, the endpoint may be too far away from where this
    script is running and therefore incur significant latency. To test that
    hypothesis, it may be valuable to momentarily disable attestation for the
    sake of debugging.

    Do not use in production.
    """

    @staticmethod
    def accepts(_oid: ObjectIdentifier) -> bool:
        return True

    def validate(
        self, _document: bytes, _public_key: bytes, _nonce: bytes
    ) -> bool:
        warnings.warn("Skipping attestation...")
        return True


# Set up the Azure AAS ACI validator, unless it has been explicitly disabled:
# - The policies array carries all allowed CCE policies, or none if the policy
#   should be ignored.
#
# - The JKUs array carries all allowed JWKS URLs, or none if the JKU claim in
#   the AAS JWT token sent by the server during the aTLS handshake should not
#   be checked.
validator: Validator
if args.insecure:
    validator = NullValidator()
else:
    validator = AciValidator(policies=policies, jkus=jkus)

# Parse provided headers, if any.
headers: Mapping[str, str] = {}
if args.headers is not None:
    raw = args.headers.read()
    headers = ast.literal_eval(raw)

# Read in the provided body, if any.
body: Optional[str] = None
if args.body is not None:
    body = args.body.read()


def use_direct() -> None:
    # Set up the aTLS context, including at least one attestation document
    # validator (only one need succeed).
    ctx = ATLSContext([validator])

    # Purposefully create a new connection per loop to incur the cost of
    # attestation to highlight the added value of connection pooling as
    # provided by the urllib3 and requests libraries.
    for _ in range(loops):
        # Set up the HTTP request machinery using the aTLS context.
        conn = HTTPAConnection(args.server, ctx, args.port)

        # Send the HTTP request, and read and print the response in the usual
        # way.
        conn.request(args.method, args.url, body, headers)

        response = conn.getresponse()

        print(f"Status: {response.status}")
        print(f"Response: {response.data.decode()}")

        conn.close()


def use_injection() -> None:
    # Replace urllib3's default HTTPSConnection class with HTTPAConnection.
    inject_into_urllib3([validator])

    for _ in range(loops):
        # The rest of urllib3's usage is as usual.
        response = urllib3.request(
            "POST",
            f"https://{args.server}:{args.port}{args.url}",
            body=body,
            headers=headers,
        )

        print(f"Status: {response.status}")
        print(f"Response: {response.data.decode()}")

    # Restore the default HTTPSConnection class.
    extract_from_urllib3()


def use_requests() -> None:
    # Note that this is an optional dependency of PyAtls since it is not
    # strictly required for its operation.
    import requests

    session = requests.Session()

    # Mount the HTTP/aTLS adapter such that any URL whose scheme is httpa://
    # results in an HTTPAConnection object that in turn establishes an aTLS
    # connection with the server.
    session.mount("httpa://", HTTPAAdapter([validator]))

    for _ in range(loops):
        # The rest of the usage of the requests library is as usual. Do
        # remember to use session.request from the session object that has the
        # mounted adapter, not requests.request, since that's the global
        # request function and has therefore no knowledge of the adapter.
        response = session.request(
            args.method,
            f"httpa://{args.server}:{args.port}{args.url}",
            data=body,
            headers=headers,
        )

        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")


if args.use_requests:
    use_requests()
elif args.use_injection:
    use_injection()
else:
    use_direct()
