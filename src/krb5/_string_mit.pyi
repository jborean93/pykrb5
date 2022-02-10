# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

def enctype_to_name(
    enctype: int,
    shortest: bool = False,
) -> str:
    """Convert an encryption type to a name or alias.

    Converts the encryption type identifier to either the full canonical name
    or the types shortest alias.

    Note:
        This API is marked as public but should not be called directly in MIT.

    Args:
        enctype: The encryption type identifier to convert.
        shortest: Return the shortest alias if `True` otherwise return the full
            canonical name.

    Returns:
        str: The encryption type name.

    Raises:
        ValueError: If the encryption type is invalid
    """
