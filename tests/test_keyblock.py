# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import krb5


def test_init_keyblock_empty() -> None:
    ctx = krb5.init_context()
    kb = krb5.init_keyblock(ctx, 0, None)

    assert len(kb) == 0
    assert kb.enctype == 0
    assert kb.data == b""
    assert str(kb) == "KeyBlock 0"
    assert repr(kb) == "KeyBlock(enctype=0, length=0)"


def test_init_keyblock_data() -> None:
    ctx = krb5.init_context()
    kb = krb5.init_keyblock(ctx, 17, b"\xff" * 16)

    assert len(kb) == 16
    assert kb.enctype == 17
    assert kb.data == b"\xff" * 16
    assert str(kb) == "KeyBlock 17"
    assert repr(kb) == "KeyBlock(enctype=17, length=16)"
