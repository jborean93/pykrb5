# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._exceptions import Krb5Error

from krb5._context cimport Context
from krb5._krb5_types cimport *
from krb5._principal cimport Principal


cdef extern from "krb5.h":
    krb5_error_code krb5_cc_close(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_default(
        krb5_context context,
        krb5_ccache *cache,
    ) nogil

    const char *krb5_cc_default_name(
        krb5_context context,
    ) nogil

    krb5_error_code krb5_cc_destroy(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_dup(
        krb5_context context,
        krb5_ccache in_cc,
        krb5_ccache *out,
    ) nogil

    krb5_error_code krb5_cc_initialize(
        krb5_context context,
        krb5_ccache cache,
        krb5_principal principal,
    ) nogil

    const char *krb5_cc_get_name(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_get_principal(
        krb5_context context,
        krb5_ccache cache,
        krb5_principal *principal,
    ) nogil

    const char *krb5_cc_get_type(
        krb5_context context,
        krb5_ccache cache,
    ) nogil

    krb5_error_code krb5_cc_new_unique(
        krb5_context context,
        const char *type,
        const char *hint,
        krb5_ccache *id,
    ) nogil

    krb5_error_code krb5_cc_resolve(
        krb5_context context,
        const char *name,
        krb5_ccache *cache,
    ) nogil


cdef class CCache:
    """Kerberos CCache

    This class represents a Credential Cache object.

    Args:
        context: Krb5 context.
    """
    # cdef Context ctx
    # cdef krb5_ccache raw

    def __cinit__(CCache self, Context context):
        self.ctx = context
        self.raw = NULL

    def __dealloc__(CCache self):
        if self.raw:
            krb5_cc_close(self.ctx.raw, self.raw)
            self.raw = NULL

    @property
    def name(self) -> typing.Optional[bytes]:
        """The name of the credential cache."""
        if self.raw:
            return cc_get_name(self.ctx, self)

    @property
    def principal(self) -> typing.Optional[Principal]:
        """Default client principal of the credential cache."""
        if self.raw:
            return cc_get_principal(self.ctx, self)

    @property
    def cache_type(self) -> typing.Optional[bytes]:
        """The type of the credential cache."""
        if self.raw:
            return cc_get_type(self.ctx, self)


def cc_default(
    Context context not None,
) -> CCache:
    """Resolve the default credential cache name.

    Create a handle to the default credential cache as given by
    :meth:`cc_default_name()`.

    Args:
        context: Krb5 context.

    Returns:
        CCache: The opened credential cache.
    """
    ccache = CCache(context)
    cdef krb5_error_code err = 0

    err = krb5_cc_default(context.raw, &ccache.raw)
    if err:
        raise Krb5Error(context, err)

    return ccache


def cc_default_name(
    Context context not None,
) -> bytes:
    """Get the name of the default credential cache.

    The name of the default credential cache. This value consults a wide range
    of sources such as the ``KRB5CCNAME`` env var, config settings, build time
    variables, etc.

    Args:
        context: Krb5 context.

    Returns:
        bytes: The name of the default credential cache.
    """
    return <bytes>krb5_cc_default_name(context.raw)


def cc_destroy(
    Context context not None,
    CCache cache not None,
) -> None:
    """Destroy a credential cache.

    Destroys the contents of the cache and closes the handle to it.

    Args:
        context: Krb5 context.
        cache: The credential cache to destroy.
    """
    cdef krb5_error_code err = 0

    err = krb5_cc_destroy(context.raw, cache.raw)
    if err:
        raise Krb5Error(context, err)
    cache.raw = NULL  # Stops dealloc from calling close


def cc_dup(
    Context context not None,
    CCache cache not None,
) -> CCache:
    """Duplicate ccache handle.

    Create a new handle referring to the same cache referenced. The new cache
    can be closed independently.

    Args:
        context: Krb5 context.
        cache: The credential cache to duplicate.

    Returns:
        CCache: The duplicated ccache.
    """
    dup = CCache(context)
    cdef krb5_error_code err = 0

    err = krb5_cc_dup(context.raw, cache.raw, &dup.raw)
    if err:
        raise Krb5Error(context, err)

    return dup


def cc_get_name(
    Context context not None,
    CCache cache not None,
) -> bytes:
    """Retrieve the name of a credential cache.

    Gets the name of the credential, but not the type of a credential cache.

    Args:
        context: Krb5 context.
        cache: The credential cache to query.

    Returns:
        bytes: The credential cache name.
    """
    return krb5_cc_get_name(context.raw, cache.raw)


def cc_get_principal(
    Context context not None,
    CCache cache not None,
) -> Principal:
    """Get the default principal of a credential cache.

    Gets the default principal of a credential as set by
    :meth:`cc_initialize()`.

    Args:
        context: Krb5 context.
        cache: The credential cache to query.

    Returns:
        Principal: The default principal of the cache.
    """
    princ = Principal(context)
    cdef krb5_error_code err = 0

    err = krb5_cc_get_principal(context.raw, cache.raw, &princ.raw)
    if err:
        raise Krb5Error(context, err)

    return princ


def cc_get_type(
    Context context not None,
    CCache cache not None,
) -> bytes:
    """Retrieve the type of a credential cache.

    Gets the credential cache type.

    Args:
        context: Krb5 context.
        cache: The credential cache to query.

    Returns:
        bytes: The credential cache type.
    """
    return krb5_cc_get_type(context.raw, cache.raw)


def cc_initialize(
    Context context not None,
    CCache cache not None,
    Principal principal not None,
) -> None:
    """Initialize a credential cache.

    Destroy any existing contents of a cache and initialize it for the default
    principal specified.

    Args:
        context: Krb5 context.
        cache: The cache to destroy and recreate.
        principal: The default principal of the cache.
    """
    cdef krb5_error_code err = 0

    err = krb5_cc_initialize(context.raw, cache.raw, principal.raw)
    if err:
        raise Krb5Error(context, err)


def cc_new_unique(
    Context context not None,
    const unsigned char[:] cred_type not None,
    const unsigned char[:] hint = None,
) -> CCache:
    """Create a new unique credential cache.

    Create a new credential cache of the specified type with a unique name.

    Args:
        context: Krb5 context.
        cred_type: The credential cache type to create.
        hint: Unused.

    Returns:
        CCache: The created credential cache.
    """
    ccache = CCache(context)
    cdef krb5_error_code err = 0

    # TODO: Test that this cannot be NULL
    if not len(cred_type):
        raise ValueError("cred_type must be set to a valid type value not an empty byte string")

    cdef const char *hint_ptr = NULL
    if hint is not None and len(hint):
        hint_ptr = <const char*>&hint[0]

    err = krb5_cc_new_unique(context.raw, <const char*>&cred_type[0], hint_ptr, &ccache.raw)
    if err:
        raise Krb5Error(context, err)

    return ccache


def cc_resolve(
    Context context not None,
    const unsigned char[:] name not None,
) -> CCache:
    """Resolve a credential cache name.

    Resolves/opens a credential cache by the name specified. The name should be
    in the form ``type:residual`` where the type is known to the krb5 library
    being called. If the name does not contain a colon then it is interpreted
    as a file name (``FILE:*``).

    Args:
        context: Krb5 context.
        name: The name of the cache to resolve.

    Returns:
        CCache: The credential cache that was resolved.
    """
    ccache = CCache(context)
    cdef krb5_error_code err = 0

    cdef const char *name_ptr = NULL
    if len(name):
        name_ptr = <const char*>&name[0]
    else:
        raise ValueError("name cannot be an empty byte string")

    err = krb5_cc_resolve(context.raw, name_ptr, &ccache.raw)
    if err:
        raise Krb5Error(context, err)

    return ccache
