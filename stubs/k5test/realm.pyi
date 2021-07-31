from typing import Any, Dict, List

class K5Realm:
    def __new__(cls, *args: Any, **kwargs: Any) -> K5Realm: ...
    tmpdir: str
    is_existing: bool
    realm: str
    portbase: int
    user_princ: str
    admin_princ: str
    host_princ: str
    nfs_princ: str
    krbtgt_princ: str
    keytab: str
    client_keytab: str
    ccache: str
    kadmin_ccache: str
    env: Dict[str, str]
    def __init__(
        self,
        realm: str = ...,
        portbase: int = ...,
        krb5_conf: Dict[str, str] | None = ...,
        kdc_conf: Dict[str, str] | None = ...,
        create_kdb: bool = ...,
        krbtgt_keysalt: str | None = ...,
        create_user: bool = ...,
        get_creds: bool = ...,
        create_host: bool = ...,
        start_kdc: bool = ...,
        start_kadmind: bool = ...,
        existing: str | None = ...,
        **paths: str,
    ) -> None: ...
    @property
    def provider(self) -> str: ...
    def create_kdb(self) -> None: ...
    def addprinc(
        self,
        princname: str,
        password: str | None = ...,
    ) -> None: ...
    def change_password(
        self,
        principal: str,
        password: str | None = ...,
        keysalt: str | None = ...,
    ) -> None: ...
    def extract_keytab(
        self,
        princname: str,
        keytab: str,
    ) -> None: ...
    def kinit(
        self,
        princname: str,
        password: str | None = ...,
        flags: List[str] | None = ...,
        verbose: bool = ...,
        **keywords: Any,
    ) -> str: ...
    def klist(
        self,
        ccache: str | None = ...,
        **keywords: Any,
    ) -> str: ...
    def klist_keytab(
        self,
        keytab: str | None = ...,
        **keywords: Any,
    ) -> str: ...
    def prep_kadmin(
        self,
        princname: str | None = ...,
        pw: str | None = ...,
        flags: List[str] | None = ...,
    ) -> str: ...
    def run_kadmin(
        self,
        query: str | List[str],
        **keywords: Any,
    ) -> str: ...
    def run_kadminl(
        self,
        query: str | List[str],
        **keywords: Any,
    ) -> Any: ...
    def start_kdc(
        self,
        args: List[str] | None = ...,
        env: Dict[str, str] | None = ...,
    ) -> None: ...
    def start_kadmind(
        self,
        env: Dict[str, str] | None = ...,
    ) -> None: ...
    @property
    def hostname(self) -> str: ...
    def run(
        self,
        args: List[str],
        env: Dict[str, str] | None = ...,
        input: str | None = ...,
        expected_code: int = ...,
    ) -> str: ...
    def __del__(self) -> None: ...
    def kprop_port(self) -> int: ...
    def server_port(self) -> int: ...
    def stop_kdc(self) -> None: ...
    def stop_kadmind(self) -> None: ...
    def stop(self) -> None: ...
    def password(
        self,
        name: str,
    ) -> str: ...
    def special_env(
        self,
        name: str,
        has_kdc_conf: bool,
        krb5_conf: Dict[str, str] | None = ...,
        kdc_conf: Dict[str, str] | None = ...,
    ) -> Dict[str, str]: ...
    def kill_daemons(self) -> None: ...
