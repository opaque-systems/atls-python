from typing import Any, Dict, List, Optional, Union

from atls.utils._httpa_connection_shim import _HTTPAConnectionShim
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
        max_retries: Union[Retry, int] = DEFAULT_RETRIES,
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
