# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds import Creds
from krb5._creds_opt import GetInitCredsOpt
from krb5._principal import Principal

class EtypeInfo(typing.NamedTuple):
    etype: int
    salt: typing.Optional[bytes]
    s2kparams: typing.Optional[bytes]

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

def get_etype_info(
    context: Context,
    principal: Principal,
    opt: typing.Optional[GetInitCredsOpt] = None,
) -> EtypeInfo:
    """Retrieve the enctype, salt and s2kparams for a principal from the KDC.

    Args:
        context: Krb5 context.
        principal: Principal to fetch the information for.
        opt: Options to use (e.g. for FAST armoring).

    Returns:
        A named tuple containing the enctype, the salt and the s2kparams.

        If the KDC provides no etype-info, the returned salt is None.

        If there are no s2kparams in the provided etype-info, s2kparams is None.
    """
