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

def get_init_creds_opt_set_anonymous(
    opt: GetInitCredsOpt,
    anonymous: bool,
) -> None:
    """Set anonymous details in the initial credential options.

    This function may be used to request anonymous credentials from the KDC.

    Note:
        Anonymous credentials are only a request; clients must verify that
        credentials are anonymous if that is a requirement.

    Args:
        opt: The initial credential options.
        anonymous: Whether to set or unset the anonymous option.
    """

def get_init_creds_opt_set_canonicalize(
    opt: GetInitCredsOpt,
    canonicalize: bool,
) -> None:
    """Set canonicalization details in the initial credential options.

    Sets whether the credential client principal should be canonicalized by
    the KDC.

    Args:
        opt: The initial credential options.
        canonicalize: Whether to set or unset the canonicalize option.
    """

def get_init_creds_opt_set_etype_list(
    opt: GetInitCredsOpt,
    etypes: typing.Iterable[int],
) -> None:
    """Set allowable encryptions types in the initial credential options.

    Sets the allowable encryption types in the initial credential options. Use
    :meth:`string_to_enctype` to convert an encryption type string to the int
    identifier.

    Args:
        opt: The initial credential options.
        etypes: The list of allowable encryption types.
    """

def get_init_creds_opt_set_forwardable(
    opt: GetInitCredsOpt,
    forwardable: bool,
) -> None:
    """Set forwardable details in the initial credential options.

    Sets whether the credentials are to be forwardable or not.

    Args:
        opt: The initial credential options.
        forwardable: Whether to set or unset the forwardable option.
    """

def get_init_creds_opt_set_proxiable(
    opt: GetInitCredsOpt,
    proxiable: bool,
) -> None:
    """Set proxiable details in the initial credential options.

    Sets whether the credentials are to be proxiable or not.

    Args:
        opt: The initial credential options.
        proxiable: Whether to set or unset the proxiable option.
    """

def get_init_creds_opt_set_renew_life(
    opt: GetInitCredsOpt,
    renew_life: int,
) -> None:
    """Set the ticket renewal lifetime.

    Sets the ticket renewal lifetime in seconds in the initial credential
    options.

    Args:
        opt: The initial credential options.
        renew_life: The ticket renewal lifetime in seconds.
    """

def get_init_creds_opt_set_salt(
    opt: GetInitCredsOpt,
    salt: bytes,
) -> None:
    """Set salt for optimistic preauth in initial credential options.

    When getting initial credentials with a password, a salt string it used to
    convert the password to a key. Normally this salt is obtained from the
    first KDC reply, but when performing optimistic preauthentication, the
    client may need to supply the salt string with this function.

    Args:
        opt: The initial credential options.
        salt: The salt to set.
    """

def get_init_creds_opt_set_tkt_life(
    opt: GetInitCredsOpt,
    tkt_life: int,
) -> None:
    """Set the ticket lifetime.

    Sets the ticket lifetime in seconds in the initial credential options.

    Args:
        opt: The initial credential options.
        tkt_life: The ticket lifetime in seconds.
    """
