# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context
from krb5._creds import Creds
from krb5._principal import Principal

class CCache:
    """Kerberos CCache

    This class represents a Credential Cache object.

    Args:
        context: Krb5 context.
    """

    def __iter__(self) -> typing.Iterator[Creds]:
        """Iterate credentials in a ccache."""
    @property
    def addr(self) -> typing.Optional[int]:
        """The raw krb5_ccache pointer address of this credential cache."""
    @property
    def name(self) -> typing.Optional[bytes]:
        """The name/residual of the credential cache."""
    @property
    def principal(self) -> typing.Optional[Principal]:
        """Default client principal of the credential cache."""
    @property
    def cache_type(self) -> typing.Optional[bytes]:
        """The type of the credential cache."""

def cc_default(
    context: Context,
) -> CCache:
    """Resolve the default credential cache name.

    Create a handle to the default credential cache as given by
    :meth:`cc_default_name()`.

    Args:
        context: Krb5 context.

    Returns:
        CCache: The opened credential cache.
    """

def cc_default_name(
    context: Context,
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

def cc_destroy(
    context: Context,
    cache: CCache,
) -> None:
    """Destroy a credential cache.

    Destroys the contents of the cache and closes the handle to it.

    Args:
        context: Krb5 context.
        cache: The credential cache to destroy.
    """

def cc_get_name(
    context: Context,
    cache: CCache,
) -> bytes:
    """Retrieve the name of a credential cache.

    Gets the name of the credential, but not the type of a credential cache.

    Args:
        context: Krb5 context.
        cache: The credential cache to query.

    Returns:
        bytes: The credential cache name.
    """

def cc_get_principal(
    context: Context,
    cache: CCache,
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

def cc_get_type(
    context: Context,
    cache: CCache,
) -> bytes:
    """Retrieve the type of a credential cache.

    Gets the credential cache type.

    Args:
        context: Krb5 context.
        cache: The credential cache to query.

    Returns:
        bytes: The credential cache type.
    """

def cc_initialize(
    context: Context,
    cache: CCache,
    principal: Principal,
) -> None:
    """Initialize a credential cache.

    Destroy any existing contents of a cache and initialize it for the default
    principal specified.

    Args:
        context: Krb5 context.
        cache: The cache to destroy and recreate.
        principal: The default principal of the cache.
    """

def cc_new_unique(
    context: Context,
    cred_type: bytes,
    hint: typing.Optional[bytes] = None,
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

def cc_resolve(
    context: Context,
    name: bytes,
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

def cc_set_default_name(
    context: Context,
    name: typing.Optional[bytes],
) -> None:
    """Set the default ccache name.

    Set the default credential cache name to the name specified for future
    operations using the context. If name is `None` or an empty byte string
    this will clear any previous application-set default name and forget any
    cached value of the default name for the context.

    Args:
        context: Krb5 context.
        name: The default credential name or `None` to reset back to the config
            defaults.
    """

def cc_store_cred(
    context: Context,
    cache: CCache,
    creds: Creds,
) -> None:
    """Store credentials in a credential cache.

    Stores the credentials into the credential cache specified.

    Args:
        context: Krb5 context.
        cache: The credential cache to store the creds into.
        creds: The credentials to store.
    """

def cc_switch(
    context: Context,
    cache: CCache,
) -> None:
    """Switch primary cache in a collection.

    If the type of cache supports it, set the cache to be the primary
    credential cache for the collection it belongs to.

    Args:
        context: Krb5 context.
        cache: The credential cache to set as the primary in its collection.
    """
