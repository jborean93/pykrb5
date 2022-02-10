# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context

def enctype_to_string(
    context: Context,
    enctype: int,
) -> str:
    """Convert an encryption type to a string.

    Converts the encryption type identifier to the string name representation.

    Note:
        This API is marked as public but should not be called directly in MIT.

    Note:
        The Heimdal and MIT implementation return quite different values. It is
        recommended to use :meth:`enctype_to_name` if available on MIT to get
        a common value back.

    Args:
        context: Krb5 context.
        enctype: The encryption type identifier to convert.

    Returns:
        str: The encryption type name.
    """

def string_to_enctype(
    context: Context,
    string: str,
) -> int:
    """Convert string to encryption type.

    Converts a string to an encryption type integer.

    Args:
        context: Krb5 context.
        string: The string to convert from.

    Returns:
        int: The encryption type.
    """
