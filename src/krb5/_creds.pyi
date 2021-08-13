# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context
from krb5._creds_opt import GetInitCredsOpt
from krb5._kt import KeyTab
from krb5._principal import Principal

class Creds:
    """Kerberos Credentials object.

    This class represents Kerberos credentials.

    Args:
        context: Krb5 context.
    """

class InitCredsContext:
    """Kerberos Initial Credentials object.

    This class represents Kerberos context for acquiring initial credentials.

    Args:
        context: Krb5 context.
    """

class Krb5Prompt:
    """Base class used to prompt the user for input.

    This is the base class the caller should use to create a prompter class
    that is passed into :meth:`get_init_creds_password` and
    :meth:`init_creds_init`. It is used to handle prompts from the Kerberos
    API, such as changing a password or password input.

    At a minimum the `prompt` function should be implemented to return the
    bytes for the prompt.
    """

    def init(
        self,
        name: typing.Optional[bytes],
        banner: typing.Optional[bytes],
        num_prompts: int,
    ) -> None:
        """Initialise the prompt.

        Initialises the prompt by passing in the optional name, banner, and the
        number of prompts expected.

        Args:
            name: Optional name for the prompt session which should be
                displayed to the user.
            banner: Optional message that indicates what sort of input is
                expected from the user which should be displayed to the user.
            num_prompts: Number of times :meth:`prompt` is to be called for
                this prompt session.
        """
    def prompt(
        self,
        msg: bytes,
        hidden: bool,
    ) -> bytes:
        """Prompt user for a response.

        Prompt the user for a response.

        Args:
            msg: The message to display for this prompt.
            hidden: Set to ``True`` to indicate the response should not be
                printed back to the user.

        Returns:
            bytes: The response for the prompt.
        """

def get_init_creds_keytab(
    context: Context,
    client: Principal,
    k5_gic_options: GetInitCredsOpt,
    keytab: KeyTab,
    start_time: int = 0,
    in_tkt_service: typing.Optional[bytes] = None,
) -> Creds:
    """Get initial credentials using a key table.

    Requests the KDC for credential using a client key stored in the key table
    specified.

    Args:
        context: Krb5 context.
        client: The client principal the credentials are for.
        k5_gic_options: The initial credentials options.
        keytab: The keytab to use when getting the credential.
        start_time: Time when the ticket becomes valid, 0 for now.
        in_tkt_service: The service name of the initial credentials.

    Returns:
        Creds: The retrieved credentials.
    """

def get_init_creds_password(
    context: Context,
    client: Principal,
    k5_gic_options: GetInitCredsOpt,
    password: typing.Optional[bytes] = None,
    start_time: int = 0,
    in_tkt_service: typing.Optional[bytes] = None,
    prompter: typing.Optional[Krb5Prompt] = None,
) -> Creds:
    """Get initial credential using a password.

    Requests the KDC for credentials using a password.

    Args:
        context: Krb5 context.
        client: The client principal the credentials are for.
        k5_gic_options: The initial credentials options.
        password: The password to use - set to ``None`` to use the prompter.
        start_time: Time when the ticket becomes valid, 0 for now.
        in_tkt_service: The service name of the initial credentials.
        prompter: The prompter instance that will handle interactive prompts.

    Returns:
        Creds: The retrieved credentials.
    """

def init_creds_get(
    context: Context,
    ctx: InitCredsContext,
) -> None:
    """Acquire credentials using initial creds context.

    Obtains credentials using the initial creds context from
    :meth:`init_creds_init`. The credentials can be retrieved with
    :meth:`init_creds_get_creds`.

    Args:
        context: Krb5 context.
        ctx: Initial credentials context.
    """

def init_creds_get_creds(
    context: Context,
    ctx: InitCredsContext,
) -> Creds:
    """Retreived acquired creds from an initial creds context.

    Gets the acquired creds from a successful call of :meth:`init_creds_get`.

    Args:
        context: Krb5 context.
        ctx: Initial credentials context.

    Returns:
        Creds: The acquired credentials.
    """

def init_creds_init(
    context: Context,
    client: Principal,
    k5_gic_options: typing.Optional[GetInitCredsOpt] = None,
    start_time: int = 0,
    prompter: typing.Optional[Krb5Prompt] = None,
) -> InitCredsContext:
    """Get initial acquiring credential context.

    Creates a new context used for acquiring initial credentials.

    Args:
        context: Krb5 context.
        client: The client principal the credentials are for.
        k5_gic_options: The initial credentials options.
        start_time: Time when the ticket becomes valid, 0 for now.
        prompter: The prompter instance that will handle interactive prompts.

    Returns:
        InitCredsContext: The retrieved acquiring initial credentials context.
    """

def init_creds_set_keytab(
    context: Context,
    ctx: InitCredsContext,
    keytab: KeyTab,
) -> None:
    """Set the keytab used for acquiring initial credentials.

    Sets the keytab used to contruct the client key for an initial
    credentials request. See :meth:`get_init_creds_keytab` for a simpler
    way to get credentials with a keytab.

    Args:
        context: Krb5 context.
        ctx: Initial credentials context.
        keytab: The keytab to set.
    """

def init_creds_set_password(
    context: Context,
    ctx: InitCredsContext,
    password: bytes,
) -> None:
    """Set the password used for acquiring initial credentials.

    Sets the password used to contruct the client key for an initial
    credentials request. See :meth:`get_init_creds_password` for a simpler
    way to get credentials with a password.

    Args:
        context: Krb5 context.
        ctx: Initial credentials context.
        password: The password to set.
    """
