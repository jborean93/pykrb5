# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._creds_opt cimport GetInitCredsOpt
from krb5._krb5_types cimport *


cdef extern from "python_krb5.h":
    void krb5_get_init_creds_opt_set_default_flags(
        krb5_context context,
        const char *appname,
        const char *realm,
        krb5_get_init_creds_opt *opt,
    ) nogil


def get_init_creds_opt_set_default_flags(
    Context context not None,
    GetInitCredsOpt opt not None,
    const unsigned char[:] appname = None,
    const unsigned char[:] realm = None,
) -> None:
    cdef const char *appname_ptr = NULL
    if appname is not None and len(appname):
        appname_ptr = <const char*>&appname[0]

    cdef const char *realm_ptr = NULL
    if realm is not None and len(realm):
        realm_ptr = <const char*>&realm[0]

    krb5_get_init_creds_opt_set_default_flags(context.raw, appname_ptr, realm_ptr, opt.raw)
