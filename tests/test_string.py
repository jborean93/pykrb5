# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import k5test
import pytest

import krb5


def test_enctype_to_string(realm: k5test.K5Realm) -> None:
    expected = "AES-256 CTS mode with 96-bit SHA-1 HMAC" if realm.provider == "mit" else "aes256-cts-hmac-sha1-96"
    ctx = krb5.init_context()
    name = krb5.enctype_to_string(ctx, 18)
    assert name == expected


def test_enctype_to_string_invalid(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    expected_msg = "Invalid argument" if realm.provider == "mit" else "encryption type \\d+ not supported"
    with pytest.raises(krb5.Krb5Error, match=expected_msg):
        krb5.enctype_to_string(ctx, 1024)


def test_string_to_enctype() -> None:
    ctx = krb5.init_context()
    enctype = krb5.string_to_enctype(ctx, "aes256-cts-hmac-sha1-96")
    assert enctype == 18


def test_string_to_enctype_invalid(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    expected_msg = "Invalid argument" if realm.provider == "mit" else "encryption type invalid not supported"
    with pytest.raises(krb5.Krb5Error, match=expected_msg):
        krb5.string_to_enctype(ctx, "invalid")


@pytest.mark.requires_api("enctype_to_name")
def test_string_to_name() -> None:
    name = krb5.enctype_to_name(18)
    assert name == "aes256-cts-hmac-sha1-96"


@pytest.mark.requires_api("enctype_to_name")
def test_string_to_name_shortest() -> None:
    name = krb5.enctype_to_name(18, shortest=True)
    assert name == "aes256-cts"
