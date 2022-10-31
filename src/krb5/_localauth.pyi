# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context
from krb5._principal import Principal

def aname_to_localname(context: Context, principal: Principal) -> str:
    """Translate a Kerberos principal to an authorization ID ("local name").

    Using configured rules, translate a Kerberos principal name to a
    string suitable for use in authorization rules; often, this means
    mapping it to a username for the host OS. See krb5.conf(5)
    "localauth interface" for details.

    Args:
          context: krb5 context
        principal: principal name to translate

    Returns:
      str: translation
     None: principal has no translation
           (krb5_aname_to_localname() returns KRB5_LNAME_NOTRANS)
    """
