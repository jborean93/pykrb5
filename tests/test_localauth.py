# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import tempfile
from typing import Optional

import k5test
import pytest

import krb5


def test_aname_to_localname(realm: k5test.K5Realm) -> None:

    # require: translation(p) == t
    def test(ctx: krb5.Context, p: str, t: Optional[str]) -> None:
        assert t == krb5.aname_to_localname(ctx, krb5.parse_name_flags(ctx, p.encode()))

    # To test, apply our own krb5.conf with a single translation
    # rule. The file is read by krb5_init_context(), so set the
    # environment variable before calling that. This overrides the
    # default rule, so only matching principals will have a
    # translation. Require a 2-instance name in the realm TEST.
    #
    # ... that's for MIT. Heimdal doesn't appear to have RULE
    # translations built in, so use auth_to_local_names instead.
    #
    # Since environment variables are process-wide, this could mess up
    # other tests in a multi-threaded test framework -- but that
    # probably won't be an issue here.

    with tempfile.NamedTemporaryFile() as config:
        saved_conf = os.environ.get("KRB5_CONFIG")
        try:
            config.write(
                b"""
[libdefaults]
default_realm = TEST

[realms]
TEST = {
  auth_to_local = RULE:[2:$1:$2@$0](^.*@TEST$)s/@TEST$//
  auth_to_local_names = {
     heimdal = mapped
  }
}
            """
            )
            config.flush()
            os.environ["KRB5_CONFIG"] = config.name
            ctx = krb5.init_context()
            if realm.provider == "mit":
                test(ctx, "foo/bar@TEST", "foo:bar")
                test(ctx, "foo@TEST", None)
                test(ctx, "foo/bar@WRONG", None)
            if realm.provider == "heimdal":
                test(ctx, "heimdal", "mapped")
        finally:
            if saved_conf:
                os.environ["KRB5_CONFIG"] = saved_conf
            else:
                del os.environ["KRB5_CONFIG"]
