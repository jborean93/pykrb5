import os.path
import shlex
import typing

from Cython.Build import cythonize
from setuptools import Extension

# krb5-config --libs krb5
raw_link_args = shlex.split("-Wl,-z,relro -Wl,--as-needed -Wl,-z,now -lkrb5 -lk5crypto -lcom_err")
library_dirs, libraries, link_args = [], [], []
for arg in raw_link_args:
    if arg.startswith("-L"):
        library_dirs.append(arg[2:])
    elif arg.startswith("-l"):
        libraries.append(arg[2:])
    else:
        link_args.append(arg)

# krb5-config --cflags krb5
compile_args = shlex.split("")


def make_extension(name: str) -> Extension:  # type: ignore[no-any-unimported]
    source = name.replace(".", "/") + ".pyx"
    if not os.path.exists(source):
        raise FileNotFoundError(source)

    return Extension(
        name=name,
        sources=[source],
        extra_link_args=link_args,
        extra_compile_args=compile_args,
        library_dirs=library_dirs,
        libraries=libraries,
    )


extensions = cythonize(
    [
        make_extension(f"krb5._{e}")
        for e in [
            "ccache",
            "context",
            "creds",
            "creds_opt",
            "exceptions",
            "kt",
            "principal",
        ]
    ],
    language_level=3,
)


def build(setup_kwargs: typing.Dict) -> None:
    """Needed for the poetry building interface."""

    setup_kwargs.update(
        {
            "ext_modules": extensions,
        }
    )
