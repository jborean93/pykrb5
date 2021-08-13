# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context

class GetInitCredsOpt:
    """Kerberos Initial Credential Options object.

    This class represents an initial credential options object.

    Args:
        context: Krb5 context.
    """

def get_init_creds_opt_alloc(
    context: Context,
) -> GetInitCredsOpt:
    """Allocate a new initial credential options object.

    Creates a new options structure that control how credential are gotten.

    Args:
        context: Krb5 context.

    Returns:
        GetInitCredsOpt: The initial credential options object.
    """

def get_init_creds_opt_set_canonicalize(
    opt: GetInitCredsOpt,
    canonicalize: typing.Optional[bool],
) -> None:
    """Set canonicalization details in the initial credential options.

    Sets whether the credential client principal should be canonicalized by
    the KDC.

    Args:
        opt: The initial credential options.
        canonicalize: Whether to set or unset the canonicalize option.
    """

def get_init_creds_opt_set_forwardable(
    opt: GetInitCredsOpt,
    forwardable: typing.Optional[bool],
) -> None:
    """Set forwardable details in the initial credential options.

    Sets whether the credentials are to be forwardable or not.

    Args:
        opt: The initial credential options.
        forwardable: Whether to set or unset the forwardable option.
    """
