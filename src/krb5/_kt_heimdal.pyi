# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context
from krb5._kt import KeyTab

def kt_get_full_name(
    context: Context,
    keytab: KeyTab,
) -> bytes:
    """Retrieve the full name of the keytab.

    Retrieves the full name of the keytab in the form ``type:residual``.

    Args:
        Context: Krb5 context.
        keytab: The keytab to query.

    Returns:
        bytes: The fullname of the keytab.
    """
