# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import krb5


def test_cccol_iter() -> None:
    ctx = krb5.init_context()
    ccache = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, ccache, krb5.parse_name_flags(ctx, b"username@DOMAIN.COM"))
    assert ccache.principal is not None
    krb5.cc_set_default_name(ctx, (ccache.cache_type or b"") + b":" + (ccache.name or b""))

    # MIT and Heimdal differ in the amounts returns, just make sure at least the MEMORY one is there
    actual = list(krb5.cccol_iter(ctx))
    assert len(actual) > 0
    for cache in actual:
        assert isinstance(cache, krb5.CCache)

    mem_ccache = next(iter([c for c in actual if c.cache_type == b"MEMORY"]))
    assert isinstance(mem_ccache, krb5.CCache)
    assert mem_ccache.cache_type == b"MEMORY"
    assert mem_ccache.name == ccache.name
    assert mem_ccache.principal is not None
    assert mem_ccache.principal.name == ccache.principal.name
