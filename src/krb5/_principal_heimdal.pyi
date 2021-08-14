# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context
from krb5._principal import Principal

def principal_get_realm(
    context: Context,
    principal: Principal,
) -> bytes:
    """Get the realm of the principal.

    Gets the realm portion of the principal name passed in.

    Args:
        context: Krb5 context.
        principal: Krb5 principal to get the realm for.

    Returns:
        bytes: The realm portion of the principal specified.
    """
