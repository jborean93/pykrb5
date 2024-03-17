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


def test_principal_accessors() -> None:
    ctx = krb5.init_context()
    principal = krb5.parse_name_flags(ctx, b"someservice//name\\/with\\/slashes@REALM.COM")

    realm_name = principal.realm
    assert realm_name == b"REALM.COM"

    components = principal.components
    assert len(components) == 3
    assert components[0] == b"someservice"
    assert components[1] == b""
    assert components[2] == b"name/with/slashes"

    ty = principal.type
    assert ty == krb5.NameType.unknown or ty == krb5.NameType.principal


def test_name_type() -> None:
    unknown_name_type = krb5.NameType(200)
    assert unknown_name_type.name == "Unknown_NameType_200"
    assert unknown_name_type.value == 200

    unknown_neg_name_type = krb5.NameType(-300)
    assert unknown_neg_name_type.name == "Unknown_NameType_m300"
    assert unknown_neg_name_type.value == -300

    assert krb5.NameType(4) is krb5.NameType.srv_xhst

    ctx = krb5.init_context()
    principal = krb5.build_principal(ctx, b"REALM.COM", [b"component"])
    principal.type = krb5.NameType(-300)
    assert principal.type is unknown_neg_name_type


def test_build_principal() -> None:
    ctx = krb5.init_context()
    principal = krb5.build_principal(ctx, b"REALM.COM", [b"someservice", b"", b"name/with/slashes"])

    name = principal.name
    assert name == b"someservice//name\\/with\\/slashes@REALM.COM"

    realm_name = principal.realm
    assert realm_name == b"REALM.COM"

    components = principal.components
    assert len(components) == 3
    assert components[0] == b"someservice"
    assert components[1] == b""
    assert components[2] == b"name/with/slashes"

    ty = principal.type
    assert ty == krb5.NameType.principal

    principal = krb5.build_principal(ctx, b"REALM.COM", [b"krbtgt", b"REALM.COM"])

    name = principal.name
    assert name == b"krbtgt/REALM.COM@REALM.COM"

    ty = principal.type
    assert ty == krb5.NameType.srv_inst

    principal = krb5.build_principal(ctx, b"WELLKNOWN:ANONYMOUS", [b"WELLKNOWN", b"ANONYMOUS"])

    name = principal.name
    assert name == b"WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"

    ty = principal.type
    assert ty == krb5.NameType.wellknown


def test_principal_nul(realm: k5test.K5Realm) -> None:
    if realm.provider.lower() == "heimdal":
        pytest.skip("Heimdal does not support NUL bytes in realm or principal component strigns")

    ctx = krb5.init_context()
    principal = krb5.build_principal(ctx, b"REALM\0.COM", [b"some\0service", b"", b"name/with/slashes"])

    name = principal.name
    assert name == b"some\\0service//name\\/with\\/slashes@REALM\\0.COM"

    realm_name = principal.realm
    assert realm_name == b"REALM\0.COM"

    components = principal.components
    assert len(components) == 3
    assert components[0] == b"some\0service"
    assert components[1] == b""
    assert components[2] == b"name/with/slashes"

    principal = krb5.parse_name_flags(ctx, b"some\\0service//name\\/with\\/slashes@REALM\\0.COM")

    realm_name = principal.realm
    assert realm_name == b"REALM\0.COM"

    components = principal.components
    assert len(components) == 3
    assert components[0] == b"some\0service"
    assert components[1] == b""
    assert components[2] == b"name/with/slashes"
