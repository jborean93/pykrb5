#!/usr/bin/env python
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import argparse
import typing

try:
    import argcomplete
except ImportError:  # pragma: nocover
    argcomplete = None

from kinit._krb5 import (
    Krb5Prompt,
    PrincipalParseFlags,
    cc_default,
    cc_new_unique,
    get_init_creds_opt_alloc,
    get_init_creds_opt_set_forwardable,
    get_init_creds_opt_set_out_ccache,
    get_init_creds_password,
    init_context,
    parse_name_flags,
)


def prompt(
    name: typing.Optional[bytes],
    banner: typing.Optional[bytes],
    prompts: typing.List[Krb5Prompt],
) -> typing.List[bytes]:
    return [b"VagrantPass1"]


def main() -> None:
    ctx = init_context()
    princ = parse_name_flags(ctx, b"vagrant-domain@DOMAIN.TEST")
    # ccache = cc_new_unique(ctx, b"MEMORY")
    default_cc = cc_default(ctx)
    opts = get_init_creds_opt_alloc(ctx)
    get_init_creds_opt_set_forwardable(opts, True)
    get_init_creds_opt_set_out_ccache(ctx, opts, default_cc)

    use_prompter = False
    if use_prompter:
        password = None
    else:
        password = b"VagrantPass1"

    get_init_creds_password(ctx, princ, password, opts, prompter=prompt)

    print(default_cc.name)
    print("done")


if __name__ == "__main__":
    main()
