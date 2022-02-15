# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pathlib

import krb5


def test_kinit_keytab(tmp_path: pathlib.Path) -> None:
    ctx = krb5.init_context()
    kt = krb5.kt_resolve(ctx, f"FILE:{tmp_path / 'keytab'}".encode())
    princ = krb5.parse_name_flags(ctx, b"user@DOMAIN.COM")
    key_block = krb5.init_keyblock(ctx, 17, b"\x00" * 16)
    krb5.kt_add_entry(ctx, kt, princ, 1, 0, key_block)

    # krb5.kinit()
