# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context
from krb5._creds_opt import GetInitCredsOpt

def get_init_creds_opt_set_default_flags(
    context: Context,
    opt: GetInitCredsOpt,
    appname: typing.Optional[bytes] = None,
    realm: typing.Optional[bytes] = None,
) -> None:
    """Set default configuration file flags.

    Set all the values in the options to the default values for the app and
    realm.

    Args:
        context: Krb5 context.
        ccache: The credential cache to set as the output.
        appname: The application name to get the default values for.
        realm: The realm as a fallback from appname.
    """
