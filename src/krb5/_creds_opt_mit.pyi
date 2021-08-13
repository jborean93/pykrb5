# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds_opt import GetInitCredsOpt

def get_init_creds_opt_set_out_ccache(
    context: Context,
    opt: GetInitCredsOpt,
    ccache: CCache,
) -> None:
    """Set output credential cache in options.

    Sets the output credential cache in the credential option structure.

    Args:
        context: Krb5 context.
        opt: The initial credential options.
        ccache: The credential cache to set as the output.
    """
