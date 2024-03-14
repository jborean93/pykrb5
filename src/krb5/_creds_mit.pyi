# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

def get_validated_creds(
    context: Context,
    client: Principal,
    ccache: CCache,
    in_tkt_service: typing.Optional[bytes] = None,
) -> Creds:
    """Get validated credentials from the KDC for a postdated ticket.

    Args:
        context: Krb5 context.
        client: Client principal name.
        ccache: The cache to get the existing credentials from.
        in_tkt_service: Server principal string or None.
    """
