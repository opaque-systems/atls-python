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
from typing import List, Mapping, Optional

import requests
from atls import (
    AttestedHTTPSConnection,
    AttestedTLSContext,
    extract_from_urllib3,
    inject_into_urllib3,
)
from atls.validators import AzAasAciValidator

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
    help="string representation of a Python dictionary containing the headers "
    "to be sent along with the request (default: none)",
)

parser.add_argument(
    "--use-requests",
    action="store_true",
    help="use the requests package (default: false)",
)

args = parser.parse_args()

policy_files: Optional[List[str]] = args.policy
jkus: Optional[List[str]] = args.jku

# Read in the specified Rego policies, if any.
policies: Optional[List[str]] = None
if policy_files is not None:
    policies = []
    for filepath in policy_files:
        with open(filepath) as f:
            policies.append(f.read())

# Set up the Azure AAS ACI validator:
# - The policies array carries all allowed CCE policies, or none if the policy
#   should be ignored.
#
# - The JKUs array carries all allowed JWKS URLs, or none if the JKU claim in
#   the AAS JWT token sent by the server during the aTLS handshake should not
#   be checked.
validator = AzAasAciValidator(policies=policies, jkus=jkus)

# Parse provided headers, if any.
headers: Mapping[str, str] = {}
if args.headers is not None:
    headers = ast.literal_eval(args.headers)

# Read in the provided body, if any.
body: Optional[str] = None
if args.body is not None:
    body = args.body.read()


def use_direct() -> None:
    # Set up the aTLS context, including at least one attestation document
    # validator (only one need succeed).
    ctx = AttestedTLSContext([validator])

    # Set up the HTTP request machinery using the aTLS context.
    conn = AttestedHTTPSConnection(args.server, ctx, args.port)

    # Send the HTTP request, and read and print the response in the usual way.
    conn.request(
        args.method,
        args.url,
        args.body,
        headers,
    )

    response = conn.getresponse()
    code = response.getcode()

    print(f"Status: {code}")
    print(f"Response: {response.read().decode()}")

    conn.close()


def use_requests() -> None:
    inject_into_urllib3([validator])

    response = requests.request(
        args.method,
        f"https://{args.server}:{args.port}{args.url}",
        data=body,
        headers=headers,
    )

    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")

    extract_from_urllib3()


if args.use_requests:
    use_requests()
else:
    use_direct()
