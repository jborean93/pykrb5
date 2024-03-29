# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context

def init_secure_context() -> Context:
    """Create a secure krb5 library context.

    Create a context structure, using only system configuration files. All
    information passed through environment variables are ignored.

    Returns:
        Context: The opened krb5 library context.
    """

def get_time_offsets(
    context: Context,
) -> typing.Tuple[int, int]:
    """Return the time offset of the specified context.

    Returns the time offset of the specified context.

    Args:
        context: Krb5 context.

    Returns:
        The seconds and microseconds of the time offset.
    """
