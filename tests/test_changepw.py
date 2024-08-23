import os

import k5test
import pytest

import krb5


@pytest.mark.requires_api("set_password")
def test_set_password(realm: k5test.K5Realm) -> None:
    if realm.provider == "mit":
        realm.start_kadmind()
    elif realm.provider == "heimdal" and os.path.isfile("/etc/redhat-release"):
        # This is a RHEL start/stop demonstration for Heimdal
        realm.kadmind = "/usr/libexec/heimdal-kadmind"
        kadmind_args = [
            realm.kadmind,
            "--config-file=%s" % (realm.env["KRB5_CONFIG"]),
            # "--keytab=%s" % (realm.keytab),
            "--ports=%s" % (realm.portbase + 1),
        ]

        realm._kadmind_proc = realm._start_daemon(kadmind_args)

        changepw_keytab = os.path.join(realm.tmpdir, "changepw.keytab")
        realm.run_kadminl(
            [
                "ext_keytab",
                "-k",
                changepw_keytab,
                "kadmin/changepw",
            ]
        )

        kpasswdd_args = [
            "/usr/libexec/kpasswdd",
            "--config-file=%s" % (realm.env["KRB5_CONFIG"]),
            "--keytab=%s" % (changepw_keytab),
            "--port=%s" % (realm.portbase + 2),
        ]
        kpasswdd_proc = realm._start_daemon(kpasswdd_args, realm.env)

    princ_name = "exp@" + realm.realm
    old_password = realm.password("userexp")
    weak_password = "sh0rt"
    empty_password = ""
    new_password = realm.password("user")

    if realm.provider == "mit":
        realm.run_kadminl(["addpol", "-minlength", "6", "-minclasses", "2", "pwpol"])
        realm.run_kadminl(["addprinc", "-pw", old_password, "-policy", "pwpol", "+needchange", princ_name])
    else:
        # This demonstrates how to create user with expired password on Heimdal
        realm.run_kadminl(
            [
                "add",
                "-p",
                old_password,
                "--max-ticket-life=1 day",
                "--max-renewable-life=1 week",
                "--expiration-time=never",
                "--pw-expiration-time=never",
                "--policy=default",
                "--attributes=requires-pw-change",
                princ_name,
            ]
        )

    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, princ_name.encode())
    opt = krb5.get_init_creds_opt_alloc(ctx)

    with pytest.raises(krb5.Krb5Error) as exc:
        krb5.get_init_creds_password(ctx, princ, opt, password=old_password.encode())
    assert exc.value.err_code == -1765328361  # KRB5KDC_ERR_KEY_EXP

    creds = krb5.get_init_creds_password(ctx, princ, opt, old_password.encode(), in_tkt_service=b"kadmin/changepw")
    assert isinstance(creds, krb5.Creds)

    (result_code, result_code_string, result_string) = krb5.change_password(ctx, creds, new_password.encode())
    assert result_code == 0

    assert result_code != 0
    if realm.provider == "mit":
        assert result_code_string.find(b"rejected") > 0
        assert result_string.find(b"too short") > 0

    (result_code, result_code_string, result_string) = krb5.change_password(ctx, creds, weak_password.encode())

    assert result_code != 0
    if realm.provider == "mit":
        assert result_code_string.find(b"rejected") > 0
        assert result_string.find(b"too short") > 0

    (result_code, result_code_string, result_string) = krb5.change_password(ctx, creds, new_password.encode())
    assert result_code == 0

    creds = krb5.get_init_creds_password(ctx, princ, opt, new_password.encode())
    assert isinstance(creds, krb5.Creds)

    if realm.provider == "mit":
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

    if kpasswdd_proc:
        realm._stop_daemon(kpasswdd_proc)

    realm.stop_kadmind()
