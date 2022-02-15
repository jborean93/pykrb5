# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing

from krb5._ccache import CCache
from krb5._context import Context
from krb5._creds_opt import GetInitCredsOpt

class FastFlags(enum.IntEnum):
    """Flags used to control :meth:`get_init_creds_opt_set_fast_flags`."""

    none: FastFlags = ...  #: No flags set.
    required: FastFlags = ...  #: Require KDC to support FAST.

def get_init_creds_opt_set_fast_ccache(
    context: Context,
    opt: GetInitCredsOpt,
    ccache: CCache,
) -> None:
    """Set FAST armor cache in options using an explicit CCache.

    Sets the location of the FAST armor ccache in the initial credential
    options. This is like :meth:`get_init_creds_opt_set_fast_ccache_name`
    except the ccache is provided as a CCache object rather than by name.

    Args:
        context: Krb5 context.
        opt: The initial credential options.
        ccache: The credential cache to set.
    """

def get_init_creds_opt_set_fast_ccache_name(
    context: Context,
    opt: GetInitCredsOpt,
    name: bytes,
) -> None:
    """Set FAST armor ccache in options using a name.

    Sets the location of the FAST armor ccache in initial credential options,
    This cache should contain the armor ticket to protect an initial credential
    exchange using the FAST protocol extension.

    Setting this option causes FAST to be used if the KDC supports it. Use
    :meth:`get_init_creds_opt_set_fast_flags` to mandate that FAST be used.

    Args:
        context: Krb5 context.
        opt: The initial credential options.
        name: The name of the credential cache.
    """

def get_init_creds_opt_set_fast_flags(
    context: Context,
    opt: GetInitCredsOpt,
    flags: typing.Union[int, FastFlags],
) -> None:
    """Set FAST flags in initial credential options.

    Sets the FAST flags in the initial credential options.

    Args:
        context: Krb5 context.
        opt: The initial credential options.
        flags: The flags to set.
    """

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

def get_init_creds_opt_set_pa(
    context: Context,
    opt: GetInitCredsOpt,
    attr: bytes,
    value: bytes,
) -> None:
    """Supply options for preauth in initial credential options.

    This function allows the caller to supply options for preauthentication.
    The values of attr and value are supplied to each preauthentication module
    available within context.

    Args:
        context: Krb5 ontext.
        opt: The initial credential options.
        attr: The preauthentication option name.
        value: The preauthentication option value.
    """
