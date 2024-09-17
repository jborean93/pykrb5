from krb5._context import Context

def chpw_message(context: Context, server_response: bytes) -> bytes:
    """This function processes the byte sequence returned as the
    `server_response` by :meth:`set_password()` and
    :meth:`set_password_using_ccache()` functions, and returns a human readable
    byte string.

    Note that `gettext` library is used to translate the strings according
    to locale settings. For the list of existing translations, pls. refer
    to MIT krb5 source code. Not all translations may be available on your
    system. Caller is responsible for decoding the string according to
    locale settings.

    Args:
        context: Krb5 context.
        server_response: The `server_response` bytes received from the KDC.

    Returns:
        bytes: The human readable bytes string.
    """
