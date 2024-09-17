import locale

import k5test
import pytest

import krb5


@pytest.mark.requires_api("chpw_message")
def test_chpw_message() -> None:

    # MIT Kerberos test samples, https://github.com/krb5/krb5, human readable
    adpi_tests = {
        "complex": [
            (
                b"\0\0",
                b"\0\0\0\0",
                b"\0\0\0\0",
                b"\0\0\0\1",
                b"\0\0\0\0\0\0\0\0",
                b"\0\0\0\0\0\0\0\0",
            ),
            (
                "The password must include numbers or symbols.",
                "Don't include any part of your name in the password.",
            ),
        ],
        "length": [
            (
                b"\0\0",
                b"\0\0\0\x0d",
                b"\0\0\0\0",
                b"\0\0\0\0",
                b"\0\0\0\0\0\0\0\0",
                b"\0\0\0\0\0\0\0\0",
            ),
            ("The password must contain at least 13 characters.",),
        ],
        "history": [
            (
                b"\0\0",
                b"\0\0\0\0",
                b"\0\0\0\x09",
                b"\0\0\0\0",
                b"\0\0\0\0\0\0\0\0",
                b"\0\0\0\0\0\0\0\0",
            ),
            ("The password must be different from the previous 9 passwords."),
        ],
        "age": [
            (
                b"\0\0",
                b"\0\0\0\0",
                b"\0\0\0\0",
                b"\0\0\0\0",
                b"\0\0\0\0\0\0\0\0",
                b"\0\0\x01\x92\x54\xd3\x80\0",
            ),
            ("The password can only be changed every 2 days."),
        ],
        "combined": [
            (
                b"\0\0",
                b"\0\0\0\x05",
                b"\0\0\0\x0d",
                b"\0\0\0\x01",
                b"\0\0\0\0\0\0\0\0",
                b"\0\0\0\xc9\x2a\x69\xc0\0",
            ),
            (
                "The password can only be changed once a day.",
                "The password must be different from the previous 13 passwords.",
                "The password must contain at least 5 characters.",
                "The password must include numbers or symbols.",
                "Don't include any part of your name in the password.",
            ),
        ],
        "unknown": [
            (
                b"\0\0",
                b"\0\0\0\0",
                b"\0\0\0\0",
                b"\x80\0\0\1",
                b"\0\0\0\0\0\0\0\0",
                b"\0\0\0\0\0\0\0\0",
            )
        ],
    }

    locale.setlocale(locale.LC_ALL, "C")

    ctx = krb5.init_context()

    samples = {k: b"".join(v[0]) if isinstance(v, list) else b"" for k, v in adpi_tests.items()}

    for k, test in adpi_tests.items():
        if isinstance(test, list) and len(test) > 1:
            phrases = test[1]
            for phrase in phrases:
                message = krb5.chpw_message(ctx, samples[k])
                assert message.decode().find(phrase) >= 0

    assert krb5.ADPolicyInfoProp.COMPLEX in krb5.ADPolicyInfo.from_bytes(samples["complex"]).properties
    assert krb5.ADPolicyInfo.from_bytes(samples["length"]).min_length == 13
    assert krb5.ADPolicyInfo.from_bytes(samples["history"]).history == 9
    assert krb5.ADPolicyInfo.from_bytes(samples["age"]).min_age == 2 * 86400 * 10_000_000
    assert krb5.ADPolicyInfo.from_bytes(samples["combined"]).min_length == 5
    assert krb5.ADPolicyInfo.from_bytes(samples["combined"]).history == 13
    assert krb5.ADPolicyInfo.from_bytes(samples["combined"]).min_age == 1 * 86400 * 10_000_000
    assert krb5.ADPolicyInfoProp.COMPLEX in krb5.ADPolicyInfo.from_bytes(samples["combined"]).properties
    assert 0x80000000 & krb5.ADPolicyInfo.from_bytes(samples["unknown"]).properties != 0


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

    (result_code, result_code_string, server_response) = krb5.set_password(ctx, creds, empty_password.encode())
    assert result_code == krb5.SetPasswordResultCode.SOFTERROR
    assert result_code_string.find(b"rejected") > 0
    assert server_response.find(b"too short") > 0

    (result_code, result_code_string, server_response) = krb5.set_password(ctx, creds, weak_password.encode())
    assert result_code == krb5.SetPasswordResultCode.SOFTERROR
    assert result_code_string.find(b"rejected") > 0
    assert server_response.find(b"too short") > 0

    (result_code, result_code_string, server_response) = krb5.set_password(ctx, creds, new_password.encode())
    assert result_code == krb5.SetPasswordResultCode.SUCCESS

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password.encode())
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    # set_password for other principal using admin creds
    (result_code, result_code_string, server_response) = krb5.set_password(
        ctx, admin_creds, new_password2.encode(), change_password_for=princ
    )
    assert result_code == krb5.SetPasswordResultCode.SUCCESS

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

    (result_code, result_code_string, server_response) = krb5.set_password_using_ccache(
        ctx, cc, empty_password.encode(), princ
    )
    assert result_code == krb5.SetPasswordResultCode.SOFTERROR
    assert result_code_string.find(b"rejected") > 0
    assert server_response.find(b"too short") > 0

    (result_code, result_code_string, server_response) = krb5.set_password_using_ccache(
        ctx, cc, weak_password.encode(), princ
    )
    assert result_code == krb5.SetPasswordResultCode.SOFTERROR
    assert result_code_string.find(b"rejected") > 0
    assert server_response.find(b"too short") > 0

    (result_code, result_code_string, server_response) = krb5.set_password_using_ccache(
        ctx, cc, new_password.encode(), princ
    )
    assert result_code == krb5.SetPasswordResultCode.SUCCESS

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password.encode())
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    krb5.cc_destroy(ctx, cc)

    admin_cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, admin_cc, admin_princ)
    krb5.cc_store_cred(ctx, admin_cc, admin_creds)

    # set_password for other principal using admin ccache
    (result_code, result_code_string, server_response) = krb5.set_password_using_ccache(
        ctx, admin_cc, new_password2.encode(), change_password_for=princ
    )
    assert result_code == krb5.SetPasswordResultCode.SUCCESS

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password2.encode())
    assert isinstance(creds, krb5.Creds)
    assert creds.client.name == princ.name

    realm.run_kadminl(["delprinc", "-force", princ_name])
    realm.run_kadminl(["delpol", "-force", "pwpol"])

    krb5.cc_destroy(ctx, admin_cc)

    realm.stop_kadmind()
