# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context

class Krb5Error(Exception):
    """Base Keberos Error class."""

    def __init__(
        self,
        context: Context,
        err_code: int,
    ) -> None: ...
    err_code: int  #: The Kerberos error code.
