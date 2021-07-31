# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._ccache import CCache
from krb5._context import Context

def cc_dup(
    context: Context,
    cache: CCache,
) -> CCache:
    """Duplicate ccache handle.

    Create a new handle referring to the same cache referenced. The new cache
    can be closed independently.

    Args:
        context: Krb5 context.
        cache: The credential cache to duplicate.

    Returns:
        CCache: The duplicated ccache.
    """
