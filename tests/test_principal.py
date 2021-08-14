# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import k5test
import pytest

import krb5


def test_parse_principal(realm: k5test.K5Realm) -> None:
    name = f"role/abc\\/def\\@test@{realm.realm}"
    ctx = krb5.init_context()

    principal = krb5.parse_name_flags(ctx, name.encode())
    assert isinstance(principal, krb5.Principal)
    assert str(principal) == name
    assert repr(principal) == f"Principal({name})"
    assert principal.name == name.encode()
    assert isinstance(principal.addr, int)

    no_flags = krb5.parse_name_flags(ctx, name.encode(), flags=krb5.PrincipalParseFlags.none)
    assert isinstance(principal, krb5.Principal)
    assert str(principal) == str(no_flags)

    no_realm = krb5.parse_name_flags(ctx, b"role/abc\\/def\\@test", flags=krb5.PrincipalParseFlags.no_realm)
    assert isinstance(no_realm, krb5.Principal)
    if realm.provider == "mit":
        # MIT seems to have a bug here
        assert str(no_realm) == "role/abc\\/def@test"
    else:
        assert str(no_realm) == "role/abc\\/def\\@test"

    require_realm = krb5.parse_name_flags(ctx, name.encode(), flags=krb5.PrincipalParseFlags.require_realm)
    assert isinstance(require_realm, krb5.Principal)
    assert str(require_realm) == name

    enterprise = krb5.parse_name_flags(ctx, name.encode(), flags=krb5.PrincipalParseFlags.enterprise)
    assert isinstance(enterprise, krb5.Principal)
    assert str(enterprise) == f"role\\/abc\\/def\\@test\\@{realm.realm}@{realm.realm}"

    ignore_realm = krb5.parse_name_flags(ctx, name.encode(), flags=krb5.PrincipalParseFlags.ignore_realm)
    assert isinstance(ignore_realm, krb5.Principal)
    if realm.provider == "mit":
        assert str(ignore_realm) == "role/abc\\/def@test"
    else:
        assert str(ignore_realm) == "role/abc\\/def\\@test"


def test_parse_principal_no_realm_failure(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()

    expected = "has realm present" if realm.provider == "mit" else "realm found in"
    with pytest.raises(krb5.Krb5Error, match=expected):
        krb5.parse_name_flags(ctx, realm.user_princ.encode(), flags=krb5.PrincipalParseFlags.no_realm)


def test_unparse_principal(realm: k5test.K5Realm) -> None:
    name = f"role/abc\\/def\\@test@{realm.realm}"
    ctx = krb5.init_context()
    principal = krb5.parse_name_flags(ctx, name.encode())

    normal = krb5.unparse_name_flags(ctx, principal)
    assert normal == b"role/abc\\/def\\@test@" + realm.realm.encode()

    no_flags = krb5.unparse_name_flags(ctx, principal, flags=krb5.PrincipalUnparseFlags.none)
    assert no_flags == normal

    no_realm = krb5.unparse_name_flags(ctx, principal, flags=krb5.PrincipalUnparseFlags.no_realm)
    if realm.provider == "mit":
        # MIT seems to have a bug here
        assert no_realm == b"role/abc\\/def@test"
    else:
        assert no_realm == b"role/abc\\/def\\@test"

    display = krb5.unparse_name_flags(ctx, principal, flags=krb5.PrincipalUnparseFlags.display)
    assert display == b"role/abc/def@test@" + realm.realm.encode()

    short = krb5.unparse_name_flags(ctx, principal, flags=krb5.PrincipalUnparseFlags.short)
    assert short == b"role/abc\\/def\\@test"

    krb5.set_default_realm(ctx, b"NEW.REALM")
    short = krb5.unparse_name_flags(ctx, principal, flags=krb5.PrincipalUnparseFlags.short)
    assert short == b"role/abc\\/def\\@test@" + realm.realm.encode()


@pytest.mark.requires_api("principal_get_realm")
def test_principal_get_realm() -> None:
    ctx = krb5.init_context()
    principal = krb5.parse_name_flags(ctx, b"username@REALM.COM")

    realm = krb5.principal_get_realm(ctx, principal)
    assert realm == b"REALM.COM"
