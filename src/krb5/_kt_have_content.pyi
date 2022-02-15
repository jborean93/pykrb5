# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context
from krb5._kt import KeyTab

def kt_have_content(
    context: Context,
    keytab: KeyTab,
) -> bool:
    """Check if a keytab exists and contains entries.

    Checks if the keytab passed in exists and contains entries.

    Args:
        context: Krb5 context.
        keytab: They keytab to query.

    Returns:
        bool: Whether the keytab exists and contains entries.
    """
