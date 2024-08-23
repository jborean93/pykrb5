import os

import k5test
import pytest

import krb5


@pytest.mark.requires_api("set_password")
def test_set_password(realm: k5test.K5Realm) -> None:
    if realm.provider == "heimdal" and os.path.isfile("/etc/redhat-release"):
        realm.kadmind = "/usr/libexec/heimdal-kadmind"
    realm.start_kadmind()

    princ_name = "exp@" + realm.realm
    old_password = realm.password("userexp")
    weak_password = "sh0rt"
    empty_password = ""
    new_password = realm.password("user")

    if realm.provider == "mit":
        realm.run_kadminl(["addpol", "-minlength", "6", "-minclasses", "2", "pwpol"])
        realm.run_kadminl(["addprinc", "-pw", old_password, "-policy", "pwpol", "+needchange", princ_name])
    else:
        realm.run_kadmin(["-l", "add", "-p", old_password, princ_name])
        realm.run_kadmin(["-l", "modify", "-a", "requires-pw-change", princ_name])

    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, princ_name.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)

    with pytest.raises(krb5.Krb5Error) as exc:
        krb5.get_init_creds_password(ctx, princ, opt, password=old_password.encode())
    assert exc.value.err_code == -1765328361  # KRB5KDC_ERR_KEY_EXP

    creds = krb5.get_init_creds_password(ctx, princ, opt, old_password.encode(), in_tkt_service=b"kadmin/changepw")
    assert isinstance(creds, krb5.Creds)

    (result_code, result_code_string, result_string) = krb5.set_password(ctx, creds, empty_password.encode(), princ)
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find(b"too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password(ctx, creds, weak_password.encode(), princ)
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find(b"too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password(ctx, creds, new_password.encode(), princ)
    assert result_code == 0

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password.encode())
    assert isinstance(creds, krb5.Creds)

    realm.run_kadminl(["modprinc", "-pw", old_password, "-policy", "pwpol", "+needchange", princ_name])

    with pytest.raises(krb5.Krb5Error) as exc:
        krb5.get_init_creds_password(ctx, princ, opt, password=old_password.encode())
    assert exc.value.err_code == -1765328361  # KRB5KDC_ERR_KEY_EXP

    creds = krb5.get_init_creds_password(ctx, princ, opt, old_password.encode(), in_tkt_service=b"kadmin/changepw")
    assert isinstance(creds, krb5.Creds)

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, cc, princ)
    krb5.cc_store_cred(ctx, cc, creds)

    (result_code, result_code_string, result_string) = krb5.set_password_using_ccache(
        ctx, cc, empty_password.encode(), princ
    )
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find(b"too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password_using_ccache(
        ctx, cc, weak_password.encode(), princ
    )
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find(b"too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password_using_ccache(
        ctx, cc, new_password.encode(), princ
    )
    assert result_code == 0

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password.encode())
    assert isinstance(creds, krb5.Creds)

    realm.run_kadminl(["delprinc", "-force", princ_name])
    realm.run_kadminl(["delpol", "-force", "pwpol"])

    realm.stop_kadmind()
