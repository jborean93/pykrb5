# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._ccache import CCache
from krb5._context import Context

def cccol_iter(
    context: Context,
) -> typing.Iterator[CCache]:
    """Iterate over credential caches.

    Iterates over all known credential caches independent of type.

    Args:
        context: Krb5 context.

    Returns:
        Iterator[CCache]: An iterator of credential caches.
    """
