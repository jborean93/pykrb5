# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._ccache import (
    CCache,
    cc_default,
    cc_default_name,
    cc_destroy,
    cc_get_name,
    cc_get_principal,
    cc_get_type,
    cc_initialize,
    cc_new_unique,
    cc_resolve,
    cc_store_cred,
)
from krb5._context import Context, get_default_realm, init_context, set_default_realm
from krb5._creds import (
    Creds,
    InitCredsContext,
    Krb5Prompt,
    get_init_creds_keytab,
    get_init_creds_password,
    init_creds_get,
    init_creds_get_creds,
    init_creds_init,
    init_creds_set_keytab,
    init_creds_set_password,
)
from krb5._creds_opt import (
    GetInitCredsOpt,
    get_init_creds_opt_alloc,
    get_init_creds_opt_set_canonicalize,
    get_init_creds_opt_set_forwardable,
)
from krb5._exceptions import Krb5Error
from krb5._kt import (
    KeyTab,
    kt_default,
    kt_default_name,
    kt_get_name,
    kt_get_type,
    kt_resolve,
)
from krb5._principal import (
    Principal,
    PrincipalParseFlags,
    PrincipalUnparseFlags,
    parse_name_flags,
    unparse_name_flags,
)

__all__ = [
    "CCache",
    "Context",
    "Creds",
    "GetInitCredsOpt",
    "InitCredsContext",
    "KeyTab",
    "Krb5Error",
    "Krb5Prompt",
    "Principal",
    "PrincipalParseFlags",
    "PrincipalUnparseFlags",
    "cc_default",
    "cc_default_name",
    "cc_destroy",
    "cc_get_name",
    "cc_get_principal",
    "cc_get_type",
    "cc_initialize",
    "cc_new_unique",
    "cc_resolve",
    "cc_store_cred",
    "get_default_realm",
    "get_init_creds_keytab",
    "get_init_creds_opt_alloc",
    "get_init_creds_opt_set_canonicalize",
    "get_init_creds_opt_set_forwardable",
    "get_init_creds_password",
    "init_context",
    "init_creds_get",
    "init_creds_get_creds",
    "init_creds_init",
    "init_creds_set_keytab",
    "init_creds_set_password",
    "kt_default",
    "kt_default_name",
    "kt_get_name",
    "kt_get_type",
    "kt_resolve",
    "parse_name_flags",
    "set_default_realm",
    "unparse_name_flags",
]

# Provider specific APIs
try:
    from krb5._ccache_mit import cc_dup
except ImportError:
    pass
else:
    __all__.append("cc_dup")


try:
    from krb5._context_mit import init_secure_context
except ImportError:
    pass
else:
    __all__.append("init_secure_context")


try:
    from krb5._creds_opt_heimdal import get_init_creds_opt_set_default_flags
except ImportError:
    pass
else:
    __all__.append("get_init_creds_opt_set_default_flags")


try:
    from krb5._creds_opt_mit import get_init_creds_opt_set_out_ccache
except ImportError:
    pass
else:
    __all__.append("get_init_creds_opt_set_out_ccache")


try:
    from krb5._kt_mit import kt_client_default, kt_dup
except ImportError:
    pass
else:

    def kt_get_full_name(
        context: Context,
        keytab: KeyTab,
    ) -> bytes:
        # This isn't implemented in MIT so mock the same behaviour
        return (keytab.kt_type or b"") + b":" + (keytab.name or b"")

    __all__.extend(["kt_client_default", "kt_dup", "kt_get_full_name", "kt_get_type"])


try:
    from krb5._kt_heimdal import kt_get_full_name
except ImportError:
    pass
else:
    __all__.extend(["kt_get_full_name", "kt_get_type"])


try:
    from krb5._principal_heimdal import principal_get_realm
except ImportError:
    pass
else:
    __all__.extend(["principal_get_realm"])
