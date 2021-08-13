# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context
from krb5._kt import KeyTab

def kt_client_default(
    context: Context,
) -> KeyTab:
    """Resolve the default client key table.

    Get a handle to the default client key tab.

    Args:
        context: Krb5 context.

    Returns:
        KeyTab: The default client keytab.
    """

def kt_dup(
    context: Context,
    keytab: KeyTab,
) -> KeyTab:
    """Duplicate keytab handle.

    Duplicates the referenced keytab. The new handle can be closed
    independently to the referenced keytab.

    Args:
        context: Krb5 context.
        keytab: The keytab to duplicate.

    Returns:
        KeyTab: The duplicated keytab.
    """
