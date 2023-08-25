import socket
import threading
from typing import Any, Dict, List, Optional, Tuple

import requests
from atls.attested_https_connection import AttestedHTTPSConnection
from atls.attested_tls_context import AttestedTLSContext
from atls.validators.az_aas_aci_validator import AzAasAciValidator
from atls.validators.validator import Validator
from requests.adapters import HTTPAdapter
from urllib3 import HTTPSConnectionPool
from urllib3.poolmanager import PoolManager
from urllib3.util.retry import Retry as Retry


class _AttestedShimHTTPSConnection(AttestedHTTPSConnection):
    """
    Provides impendance-matching at the interface between urllib3 and the
    AttestedHTTPSConnection class.
    """

    Validators: List[Validator]

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        timeout: int = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore
        source_address: Optional[Tuple[str, int]] = None,
        blocksize: int = 8192,
        # We use kwargs to catch additional parameters that urllib3 passes
        # to its selected HTTPS connection that we do not use and which we
        # do not want to expose to developers at the level of the
        # underlying class (i.e., AttestedHTTPSConnection) because they
        # will have no use for them either.
        **_kwargs: Dict[str, Any],
    ) -> None:
        context = AttestedTLSContext(self.Validators)

        super().__init__(host, context, port, timeout, source_address, blocksize)

    def is_verified(self) -> bool:
        # This function returns whether the connection is SSL-enabled which it
        # always is.
        return True


class _AttestedPoolManager(PoolManager):
    TypeCounter: int = 0
    TypeCounterLock: threading.Lock = threading.Lock()

    def __init__(
        self,
        validators: List[Validator],
        num_pools=10,
        headers=None,
        **connection_pool_kw,
    ) -> None:
        # This must be called first because it initializes
        # pool_classes_by_scheme, which we modify below.
        super().__init__(num_pools, headers, **connection_pool_kw)

        counter: int = 0
        with _AttestedPoolManager.TypeCounterLock:
            counter = _AttestedPoolManager.TypeCounter
            _AttestedPoolManager.TypeCounter += 1

        dyn_connection_type = type(
            f"_AttestedShimHTTPSConnection{counter}",
            (_AttestedShimHTTPSConnection,),
            {"Validators": validators},
        )

        dyn_pool_manager_type = type(
            f"MyConnectionPool{counter}",
            (HTTPSConnectionPool,),
            {"ConnectionCls": dyn_connection_type},
        )

        self.pool_classes_by_scheme = self.pool_classes_by_scheme.copy()
        self.pool_classes_by_scheme["ahttps"] = dyn_pool_manager_type
        self.key_fn_by_scheme["ahttps"] = self.key_fn_by_scheme["https"]


class AttestedHTTPAdapter(HTTPAdapter):
    def __init__(
        self,
        validators: List[Validator],
        pool_connections: int = 10,
        pool_maxsize: int = 10,
        max_retries: Retry | int | None = 0,
        pool_block: bool = False,
    ) -> None:
        self.validators = validators

        super().__init__(pool_connections, pool_maxsize, max_retries, pool_block)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = _AttestedPoolManager(
            validators=self.validators,
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )
