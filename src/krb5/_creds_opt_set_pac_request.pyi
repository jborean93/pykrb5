# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._context import Context
from krb5._creds_opt import GetInitCredsOpt

def get_init_creds_opt_set_pac_request(
    context: Context,
    opt: GetInitCredsOpt,
    req_pac: bool,
) -> None:
    """Ask KDC to include or not include a PAC in the ticket.

    If this option is set, the AS request will include a PAC-REQUEST pa-data
    item explicitly asking the KDC to either include or include a privilege
    attribute certificate in the ticket authorization data. By default, no
    request is made; typically the KDC will default to including a PAC if it
    supports them.

    Args:
        context: Krb5 context.
        opt: The initial credential options.
        canonicalize: Whether to set or unset the canonicalize option.
    """
