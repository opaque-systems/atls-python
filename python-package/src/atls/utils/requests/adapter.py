import socket
from typing import Any, Dict, List, Optional, Tuple

from atls import ATLSContext, HTTPAConnection
from atls.validators import Validator
from requests.adapters import (
    DEFAULT_POOLBLOCK,
    DEFAULT_POOLSIZE,
    DEFAULT_RETRIES,
    HTTPAdapter,
)
from urllib3 import HTTPSConnectionPool
from urllib3.poolmanager import PoolManager
from urllib3.util.retry import Retry as Retry


class _HTTPAConnectionShim(HTTPAConnection):
    """
    Provides impendance-matching at the interface between urllib3 and the
    HTTPAConnection class.
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
        # underlying class (i.e., HTTPAConnection) because they will have no
        # use for them either.
        **_kwargs: Dict[str, Any],
    ) -> None:
        context = ATLSContext(self.Validators)

        super().__init__(
            host, context, port, timeout, source_address, blocksize
        )

    def is_verified(self) -> bool:
        # This function returns whether the connection is SSL-enabled which it
        # always is.
        return True


class _HTTPAPoolManager(PoolManager):
    def __init__(
        self,
        validators: List[Validator],
        num_pools: int = DEFAULT_POOLSIZE,
        headers: Optional[Dict[Any, Any]] = None,
        **connection_pool_kw: Dict[str, Any],
    ) -> None:
        # This must be called first because it initializes
        # pool_classes_by_scheme, which we modify below.
        super().__init__(num_pools, headers, **connection_pool_kw)

        dyn_connection_type = type(
            "_HTTPAConnectionShim",
            (_HTTPAConnectionShim,),
            {"Validators": validators},
        )

        dyn_pool_manager_type = type(
            "_HTTPAConnectionPool",
            (HTTPSConnectionPool,),
            {"ConnectionCls": dyn_connection_type},
        )

        pools_by_scheme = self.pool_classes_by_scheme.copy()  # type: ignore
        pools_by_scheme["httpa"] = dyn_pool_manager_type

        self.pool_classes_by_scheme = pools_by_scheme
        self.key_fn_by_scheme["httpa"] = self.key_fn_by_scheme["https"]


class HTTPAAdapter(HTTPAdapter):
    def __init__(
        self,
        validators: List[Validator],
        pool_connections: int = DEFAULT_POOLSIZE,
        pool_maxsize: int = DEFAULT_POOLSIZE,
        max_retries: Retry | int = DEFAULT_RETRIES,
        pool_block: bool = DEFAULT_POOLBLOCK,
    ) -> None:
        self.validators = validators

        super().__init__(
            pool_connections, pool_maxsize, max_retries, pool_block
        )

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = DEFAULT_POOLBLOCK,
        **pool_kwargs: Dict[str, Any],
    ) -> None:
        self.poolmanager = _HTTPAPoolManager(
            validators=self.validators,
            num_pools=connections,
            maxsize=maxsize,  # type: ignore
            block=block,  # type: ignore
            **pool_kwargs,
        )
