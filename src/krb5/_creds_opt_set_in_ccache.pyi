# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds_opt import GetInitCredsOpt

def get_init_creds_opt_set_in_ccache(
    context: Context,
    opt: GetInitCredsOpt,
    ccache: CCache,
) -> None:
    """Set an input credential cache in initial credential options.

    If an input credential cache is set, then the krb5_get_init_creds family of
    APIs will read settings from it. Setting an input ccache is desirable when
    the application wishes to perform authentication in the same way (using the
    same preauthentication mechanisms, and making the same non-security
    sensitive choices) as the previous authentication attempt, which stored
    information in the passed-in cache.

    Args:
        context: Krb5 context.
        opt: The initial credential options.
        ccache: The credential cache to set.
    """
