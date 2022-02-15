# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

import k5test
import pytest

import krb5


def test_get_init_creds_opt_alloc() -> None:
    ctx = krb5.init_context()

    opt = krb5.get_init_creds_opt_alloc(ctx)
    assert isinstance(opt, krb5.GetInitCredsOpt)
    assert str(opt) == "GetInitCredsOpt"


def test_get_init_creds_opt_set_anonymous() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_anonymous(opt, True)
    krb5.get_init_creds_opt_set_anonymous(opt, False)


def test_get_init_creds_opt_set_canonicalize() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_canonicalize(opt, True)
    krb5.get_init_creds_opt_set_canonicalize(opt, False)


def test_get_init_creds_opt_set_etype_list() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_etype_list(opt, [17, 18])
    krb5.get_init_creds_opt_set_etype_list(opt, [])


def test_get_init_creds_opt_set_forwardable() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_forwardable(opt, True)
    krb5.get_init_creds_opt_set_forwardable(opt, False)


def test_get_init_creds_opt_set_proxiable() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_proxiable(opt, True)
    krb5.get_init_creds_opt_set_proxiable(opt, False)


def test_get_init_creds_opt_set_renew_life() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_renew_life(opt, 0)
    krb5.get_init_creds_opt_set_renew_life(opt, 1)
    krb5.get_init_creds_opt_set_renew_life(opt, 1024)


def test_get_init_creds_opt_set_salt() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_salt(opt, b"\x00")


def test_get_init_creds_opt_set_salt_invalid_empty_string() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    with pytest.raises(ValueError, match="salt cannot be an empty byte string"):
        krb5.get_init_creds_opt_set_salt(opt, b"")


def test_get_init_creds_opt_set_tkt_life() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_tkt_life(opt, 0)
    krb5.get_init_creds_opt_set_tkt_life(opt, 1)
    krb5.get_init_creds_opt_set_tkt_life(opt, 1024)


@pytest.mark.requires_api("get_init_creds_opt_set_fast_flags")
def test_get_init_creds_opt_set_fast_flags() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_fast_flags(ctx, opt, krb5.FastFlags.required)
    krb5.get_init_creds_opt_set_fast_flags(ctx, opt, krb5.FastFlags.none)


@pytest.mark.requires_api("get_init_creds_opt_set_fast_ccache")
def test_get_init_creds_opt_set_fast_ccache() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.get_init_creds_opt_set_fast_ccache(ctx, opt, cc)


@pytest.mark.requires_api("get_init_creds_opt_set_fast_ccache_name")
def test_get_init_creds_opt_set_fast_ccache_name() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.get_init_creds_opt_set_fast_ccache_name(ctx, opt, (cc.cache_type or b"") + b":" + (cc.name or b""))


@pytest.mark.requires_api("get_init_creds_opt_set_in_ccache")
def test_get_init_creds_opt_set_in_ccache() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.get_init_creds_opt_set_in_ccache(ctx, opt, cc)


@pytest.mark.requires_api("get_init_creds_opt_set_out_ccache")
def test_get_init_creds_opt_set_out_ccache() -> None:
    ctx = krb5.init_context()
    ccache = krb5.cc_new_unique(ctx, b"MEMORY")

    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_out_ccache(ctx, opt, ccache)


@pytest.mark.requires_api("get_init_creds_opt_set_pac_request")
def test_get_init_creds_opt_set_pac_request() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_pac_request(ctx, opt, True)
    krb5.get_init_creds_opt_set_pac_request(ctx, opt, False)


@pytest.mark.requires_api("get_init_creds_opt_set_default_flags")
def test_get_init_creds_opt_set_default_flags() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)

    krb5.get_init_creds_opt_set_default_flags(ctx, opt)
    krb5.get_init_creds_opt_set_default_flags(ctx, opt, b"appname", b"realm")


@pytest.mark.requires_api("get_init_creds_opt_set_pa")
def test_get_init_creds_opt_set_pa() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)

    krb5.get_init_creds_opt_set_pa(ctx, opt, b"attr", b"value")


@pytest.mark.requires_api("get_init_creds_opt_set_pa")
def test_get_init_creds_opt_set_pa_invalid_empty_value() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)

    with pytest.raises(ValueError, match="attr must be set"):
        krb5.get_init_creds_opt_set_pa(ctx, opt, b"", b"value")

    with pytest.raises(ValueError, match="value must be set"):
        krb5.get_init_creds_opt_set_pa(ctx, opt, b"attr", b"")
