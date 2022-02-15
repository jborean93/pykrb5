# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._ccache import CCache
from krb5._context import Context
from krb5._principal import Principal

def cc_cache_match(
    context: Context,
    principal: Principal,
) -> CCache:
    """Find a credential cache for the specified principal.

    Find a cache within the collection whose default principal is the same as
    the one specified.

    Args:
        context: Krb5 context.
        principal: The principal to find in the collection cache.

    Returns:
        CCache: The opened credential cache for the principal specified.
    """
