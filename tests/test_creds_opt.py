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


def test_get_init_creds_opt_set_canonicalize() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_canonicalize(opt, True)
    krb5.get_init_creds_opt_set_canonicalize(opt, False)
    krb5.get_init_creds_opt_set_canonicalize(opt, None)


def test_get_init_creds_opt_set_forwardable() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_forwardable(opt, True)
    krb5.get_init_creds_opt_set_forwardable(opt, False)
    krb5.get_init_creds_opt_set_forwardable(opt, None)


@pytest.mark.requires_api("get_init_creds_opt_set_out_ccache")
def test_get_init_creds_opt_set_out_ccache() -> None:
    ctx = krb5.init_context()
    ccache = krb5.cc_new_unique(ctx, b"MEMORY")

    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_out_ccache(ctx, opt, ccache)


@pytest.mark.requires_api("get_init_creds_opt_set_default_flags")
def test_get_init_creds_opt_set_default_flags() -> None:
    ctx = krb5.init_context()
    opt = krb5.get_init_creds_opt_alloc(ctx)

    krb5.get_init_creds_opt_set_default_flags(ctx, opt)
    krb5.get_init_creds_opt_set_default_flags(ctx, opt, b"appname", b"realm")
