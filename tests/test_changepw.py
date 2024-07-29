import typing

import k5test
import pytest

import krb5


@pytest.mark.requires_api("set_password")
def test_set_password(realm: k5test.K5Realm) -> None:
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, realm.user_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)
    creds = krb5.get_init_creds_password(ctx, princ, opt, realm.password("user").encode())
    assert isinstance(creds, krb5.Creds)

    newpw = realm.password("user").encode()
    result = krb5.set_password(ctx, creds, newpw, princ)
    raise ValueError(result)

    creds = krb5.get_init_creds_password(ctx, princ, opt, newpw)
    assert isinstance(creds, krb5.Creds)
