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
    cc_set_default_name,
    cc_store_cred,
    cc_switch,
)
from krb5._cccol import cccol_iter
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
    get_init_creds_opt_set_anonymous,
    get_init_creds_opt_set_canonicalize,
    get_init_creds_opt_set_etype_list,
    get_init_creds_opt_set_forwardable,
    get_init_creds_opt_set_proxiable,
    get_init_creds_opt_set_renew_life,
    get_init_creds_opt_set_salt,
    get_init_creds_opt_set_tkt_life,
)
from krb5._exceptions import Krb5Error
from krb5._keyblock import KeyBlock, init_keyblock
from krb5._kt import (
    KeyTab,
    KeyTabEntry,
    kt_add_entry,
    kt_default,
    kt_default_name,
    kt_get_entry,
    kt_get_name,
    kt_get_type,
    kt_read_service_key,
    kt_remove_entry,
    kt_resolve,
)
from krb5._principal import (
    Principal,
    PrincipalParseFlags,
    PrincipalUnparseFlags,
    copy_principal,
    parse_name_flags,
    unparse_name_flags,
)
from krb5._string import enctype_to_string, string_to_enctype

__all__ = [
    "CCache",
    "Context",
    "Creds",
    "GetInitCredsOpt",
    "InitCredsContext",
    "KeyBlock",
    "KeyTab",
    "KeyTabEntry",
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
    "cc_set_default_name",
    "cc_store_cred",
    "cc_switch",
    "cccol_iter",
    "copy_principal",
    "enctype_to_string",
    "get_default_realm",
    "get_init_creds_keytab",
    "get_init_creds_opt_alloc",
    "get_init_creds_opt_set_anonymous",
    "get_init_creds_opt_set_canonicalize",
    "get_init_creds_opt_set_etype_list",
    "get_init_creds_opt_set_forwardable",
    "get_init_creds_opt_set_proxiable",
    "get_init_creds_opt_set_renew_life",
    "get_init_creds_opt_set_salt",
    "get_init_creds_opt_set_tkt_life",
    "get_init_creds_password",
    "init_context",
    "init_creds_get",
    "init_creds_get_creds",
    "init_creds_init",
    "init_creds_set_keytab",
    "init_creds_set_password",
    "init_keyblock",
    "kt_add_entry",
    "kt_default",
    "kt_default_name",
    "kt_get_entry",
    "kt_get_name",
    "kt_get_type",
    "kt_read_service_key",
    "kt_remove_entry",
    "kt_resolve",
    "parse_name_flags",
    "set_default_realm",
    "string_to_enctype",
    "unparse_name_flags",
]

# Provider or version specific APIs
try:
    from krb5._ccache_mit import cc_dup
except ImportError:
    pass
else:
    __all__.append("cc_dup")


try:
    from krb5._ccache_match import cc_cache_match
except ImportError:
    pass
else:
    __all__.append("cc_cache_match")

try:
    from krb5._ccache_support_switch import cc_support_switch
except ImportError:
    pass
else:
    __all__.append("cc_support_switch")

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
    from krb5._creds_opt_mit import (
        FastFlags,
        get_init_creds_opt_set_fast_ccache,
        get_init_creds_opt_set_fast_ccache_name,
        get_init_creds_opt_set_fast_flags,
        get_init_creds_opt_set_out_ccache,
        get_init_creds_opt_set_pa,
    )
except ImportError:
    pass
else:
    __all__.extend(
        [
            "FastFlags",
            "get_init_creds_opt_set_fast_ccache",
            "get_init_creds_opt_set_fast_ccache_name",
            "get_init_creds_opt_set_fast_flags",
            "get_init_creds_opt_set_out_ccache",
            "get_init_creds_opt_set_pa",
        ]
    )


try:
    from krb5._creds_opt_set_in_ccache import get_init_creds_opt_set_in_ccache
except ImportError:
    pass
else:
    __all__.append("get_init_creds_opt_set_in_ccache")


try:
    from krb5._creds_opt_set_pac_request import get_init_creds_opt_set_pac_request
except ImportError:
    pass
else:
    __all__.append("get_init_creds_opt_set_pac_request")


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
    from krb5._kt_have_content import kt_have_content
except ImportError:
    pass
else:
    __all__.append("kt_have_content")


try:
    from krb5._principal_heimdal import principal_get_realm
except ImportError:
    pass
else:
    __all__.extend(["principal_get_realm"])


try:
    from krb5._string_mit import enctype_to_name
except ImportError:
    pass
else:
    __all__.append("enctype_to_name")
