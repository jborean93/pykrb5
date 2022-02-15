# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context

def cc_support_switch(
    context: Context,
    cache_type: bytes,
) -> bool:
    """Check whether the cache type supports switching.

    Checks whether the credential cache type specified supports switching the
    primary cache in its colleciton using :meth:`cc_switch`.

    Args:
        context: Krb5 context.
        cache_type: The credential cache type, like ``FILE``, ``DIR``, etc to
            check whether it supports switching or not.

    Returns:
        bool: The cache type supports switching.
    """
