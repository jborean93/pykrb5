from krb5._context import Context

def chpw_message(context: Context, server_string: bytes) -> str:
    """This function processes the server response returned as the
    `result_string` of `krb5_change_password()`, `krb5_set_password()`, and
    related functions, and returns a displayable string.
    If server_string contains Active Directory structured policy information,
    it will be converted into human-readable text.
    Note the `gettext` library is used to translate the strings.

    Args:
        context: Krb5 context.
        server_string: The `result_string` received from the KDC.

    Returns:
        str: The human readable reason string, locale sensitive.
    """
