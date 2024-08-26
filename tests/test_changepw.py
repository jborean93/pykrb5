import k5test
import pytest

import krb5


def test_set_password(realm: k5test.K5Realm) -> None:

    if realm.provider != "mit":
        # Heimdal testing requires complicated kadmind and kpasswdd setup
        return

    realm.start_kadmind()

    princ_name = "exp@" + realm.realm
    old_password = realm.password("userexp")
    weak_password = "sh0rt"
    empty_password = ""
    new_password = realm.password("user")
    new_password2 = realm.password("user~")

    # setup
    realm.run_kadminl(["addpol", "-minlength", "6", "-minclasses", "2", "pwpol"])
    realm.run_kadminl(["addprinc", "-pw", old_password, "-policy", "pwpol", "+needchange", princ_name])

    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, princ_name.encode())
    admin_princ = krb5.parse_name_flags(ctx, realm.admin_princ.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)

    # admin creds; will be reused with ccache as well
    admin_creds = krb5.get_init_creds_password(
        ctx, admin_princ, opt, realm.password("admin").encode(), in_tkt_service=b"kadmin/changepw"
    )
    assert isinstance(admin_creds, krb5.Creds)

    # set_password for creds owner (self)
    with pytest.raises(krb5.Krb5Error) as exc:
        krb5.get_init_creds_password(ctx, princ, opt, password=old_password.encode())
    assert exc.value.err_code == -1765328361  # KRB5KDC_ERR_KEY_EXP

    creds = krb5.get_init_creds_password(ctx, princ, opt, old_password.encode(), in_tkt_service=b"kadmin/changepw")
    assert isinstance(creds, krb5.Creds)

    (result_code, result_code_string, result_string) = krb5.set_password(ctx, creds, empty_password.encode())
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find("too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password(ctx, creds, weak_password.encode())
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find("too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password(ctx, creds, new_password.encode())
    assert result_code == 0

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password.encode())
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    # set_password for other principal using admin creds
    (result_code, result_code_string, result_string) = krb5.set_password(
        ctx, admin_creds, new_password2.encode(), change_password_for=princ
    )
    assert result_code == 0

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password2.encode())
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    # reset password locally for next test
    realm.run_kadminl(["cpw", "-pw", old_password, princ_name])
    realm.run_kadminl(["modprinc", "+needchange", princ_name])

    # set_password_using_ccache
    with pytest.raises(krb5.Krb5Error) as exc:
        krb5.get_init_creds_password(ctx, princ, opt, password=old_password.encode())
    assert exc.value.err_code == -1765328361  # KRB5KDC_ERR_KEY_EXP

    creds = krb5.get_init_creds_password(ctx, princ, opt, old_password.encode(), in_tkt_service=b"kadmin/changepw")
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, cc, princ)
    krb5.cc_store_cred(ctx, cc, creds)

    (result_code, result_code_string, result_string) = krb5.set_password_using_ccache(
        ctx, cc, empty_password.encode(), princ
    )
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find("too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password_using_ccache(
        ctx, cc, weak_password.encode(), princ
    )
    assert result_code != 0
    assert result_code_string.find(b"rejected") > 0
    assert result_string.find("too short") > 0

    (result_code, result_code_string, result_string) = krb5.set_password_using_ccache(
        ctx, cc, new_password.encode(), princ
    )
    assert result_code == 0

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password.encode())
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    krb5.cc_destroy(ctx, cc)

    admin_cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, admin_cc, admin_princ)
    krb5.cc_store_cred(ctx, admin_cc, admin_creds)

    # set_password for other principal using admin ccache
    (result_code, result_code_string, result_string) = krb5.set_password_using_ccache(
        ctx, admin_cc, new_password2.encode(), change_password_for=princ
    )
    assert result_code == 0

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password2.encode())
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    realm.run_kadminl(["delprinc", "-force", princ_name])
    realm.run_kadminl(["delpol", "-force", "pwpol"])

    krb5.cc_destroy(ctx, admin_cc)

    realm.stop_kadmind()
