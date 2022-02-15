#!/usr/bin/env python

# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Builds the project.

Logic has mostly been derived from python-gssapi - thanks to them for all the
hard work.

https://github.com/pythongssapi/python-gssapi/blob/main/setup.py
"""

import ctypes
import ctypes.util
import glob
import os
import os.path
import platform
import shlex
import subprocess
import sys
import typing

from setuptools import Extension, find_packages, setup
from setuptools.command.sdist import sdist

SKIP_CYTHON_FILE = "__dont_use_cython__.txt"
SKIP_MODULE_CHECK = os.environ.get("KRB5_SKIP_MODULE_CHECK", "false").lower() == "true"
CYTHON_LINETRACE = os.environ.get("KRB5_CYTHON_TRACING", "false").lower() == "true"

if os.path.exists(SKIP_CYTHON_FILE):
    print("In distributed package, building from C files...")
    SOURCE_EXT = "c"
else:
    try:
        from Cython.Build import cythonize

        print("Building from Cython files...")
        SOURCE_EXT = "pyx"
    except ImportError:
        print("Cython not found, building from C files...")
        SOURCE_EXT = "c"


def run_command(*args: str) -> str:
    stdout = subprocess.check_output(args, shell=True)
    return stdout.decode("utf-8").strip()


def make_extension(
    name: str,
    module: ctypes.CDLL,
    canary: typing.Optional[str] = None,
    **kwargs: typing.Any,
) -> Extension:
    source = os.path.join("src", name.replace(".", os.sep)) + f".{SOURCE_EXT}"

    if not SKIP_MODULE_CHECK and canary and not hasattr(module, canary):
        print(f"Skipping {source} as it is not supported by the selected Kerberos implementation.")
        return

    if not os.path.exists(source):
        raise FileNotFoundError(source)

    print(f"Compiling {source}")
    return Extension(
        name=name,
        sources=[source],
        **kwargs,
    )


def get_krb5_config() -> str:
    """Gets the path to the krb5-config binary.

    Determines the path to the krb5-confing to use for detecting linker and
    compiler args on the current platform. The default behaviour is to use
    the value of the env var ``KRB5_KRB5CONFIG`` defaulting to just
    krb5-conf in the path.

    FreeBSD is slightly different as it favours ``/usr/local/bin/krb5-config``
    over ``/usr/bin/krb5-config`` due to the latter being based on an ancient
    Heimdal version.

    Returns:
        str: Path to krb5-conf.
    """
    kc_env = os.environ.get("KRB5_KRB5CONFIG", "")
    kc = kc_env if kc_env else "krb5-config"

    if sys.platform.startswith("freebsd") and not kc_env:
        # FreeBSD does $PATH backward, for our purposes.  That is, the package
        # manager's version of the software is in /usr/local, which is in PATH
        # *after* the version in /usr.  We prefer the package manager's version
        # because the Heimdal in base is truly ancient, but this can be overridden
        # - either in the "normal" fashion by putting something in PATH in front
        # of it, or by removing /usr/local from PATH.
        bins = []
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            p = os.path.join(entry, "krb5-config")
            if not os.path.exists(p):
                continue
            bins.append(p)

        if len(bins) > 1 and bins[0] == "/usr/bin/krb5-config" and "/usr/local/bin/krb5-config" in bins:
            kc = "/usr/local/bin/krb5-config"

    return kc


def get_krb5_lib_path(
    libraries: typing.List[str],
    library_dirs: typing.List[str],
    link_args: typing.List[str],
    macos_native: bool,
) -> str:
    """Gets the path to the main libkrb5.so library.

    This path is used to check if the Kerberos library supports the optional
    APIs when compiling.

    Args:
        libraries: The libraries specified by krb5-config (-l).
        librariy_dirs: The library dirs specified by krb5-config (-L).
        link_args: The linking args specified by krb5-config.
        macos_native: Whether this is for the native macOS Kerberos library.

    Returns:
        str: The path to the krb5 library.
    """
    krb5_lib = os.environ.get("KRB5_MAIN_LIB", "")
    krb5_path = ""

    if not krb5_lib and macos_native:
        # Cannot use find_library as it won't look into the private framework path.
        krb5_lib = "/System/Library/PrivateFrameworks/Heimdal.framework/Heimdal"

    elif not krb5_lib:
        for opt in libraries:
            if opt.startswith("krb5"):
                ext = {
                    "nt": "dll",
                    "darwin": "dylib",
                }.get(os.name, "so")

                krb5_lib = f"lib{opt}.{ext}"
                break

        for opt in link_args:
            # To support Heimdal on Debian, read the linker path.
            if opt.startswith("-Wl,/"):
                krb5_path = opt[4:] + "/"
                break

        if not krb5_path:
            for d in library_dirs:
                if os.path.exists(os.path.join(d, krb5_lib)):
                    krb5_path = d
                    break

    if not krb5_lib:
        raise Exception(
            "Could not find the main krb5 shared library. Set this manually with the env var KRB5_MAIN_LIB."
        )

    return os.path.join(krb5_path, krb5_lib)


with open(os.path.join(os.path.dirname(__file__), "README.md"), mode="rb") as fd:
    long_description = fd.read().decode("utf-8")

kc = get_krb5_config()
print(f"Using krb5-config at '{kc}'")

macos_native = False
if sys.platform == "darwin":
    mac_ver = [int(v) for v in platform.mac_ver()[0].split(".")]
    macos_native = mac_ver >= [10, 7, 0]

compile_args, raw_link_args = [
    shlex.split(os.environ[e], posix=True) if e in os.environ else None
    for e in ["KRB5_COMPILER_ARGS", "KRB5_LINKER_ARGS"]
]
if compile_args is None:
    if macos_native:
        compile_args = []

    else:
        compile_args = shlex.split(run_command(f"{kc} --cflags krb5"))

    compile_args.append("-Werror")

    # Python 3.8 on macOS errors on these deprecation warnings. We ignore them as things are fixed on 3.9 but the
    # code still needs to compile on 3.8.
    if sys.platform == "darwin" and sys.version_info[:2] == (3, 8):
        compile_args.append("-Wno-deprecated")

    if CYTHON_LINETRACE:
        compile_args.append("-DCYTHON_TRACE_NOGIL=1")

if raw_link_args is None:
    if macos_native:
        raw_link_args = ["-framework", "Heimdal", "-F", "/System/Library/PrivateFrameworks"]

    else:
        raw_link_args = shlex.split(run_command(f"{kc} --libs krb5"))

library_dirs, include_dirs, libraries, link_args = [], [], [], []
for arg in raw_link_args:
    if arg.startswith("-L"):
        library_dirs.append(arg[2:])
    elif arg.startswith("-l"):
        libraries.append(arg[2:])
    elif arg.startswith("-I"):
        include_dirs.append(arg[2:])
    else:
        link_args.append(arg)

if macos_native:
    # Because this is doing a naughty thing and linking against a private framework there are no krb5.h header files
    # available. A hack is to just compile Heimdal itself and include that during compilation.
    heimdal_dir = os.environ.get("KRB5_MACOS_HEIMDAL_DIR", "")
    if not heimdal_dir:
        heimdal_dir = os.path.join(os.path.dirname(__file__), "build_helpers", "heimdal")

    include_dirs.append(os.path.join(os.path.abspath(heimdal_dir), "include"))


krb5_path = get_krb5_lib_path(libraries, library_dirs, link_args, macos_native)
print(f"Using {krb5_path} as Kerberos module for platform checks")
krb5 = ctypes.CDLL(krb5_path)

if hasattr(krb5, "krb5_xfree"):
    compile_args.append("-DHEIMDAL_XFREE")


raw_extensions = []
for e in [
    "ccache",
    ("ccache_mit", "krb5_cc_dup"),
    ("ccache_match", "krb5_cc_cache_match"),
    ("ccache_support_switch", "krb5_cc_support_switch"),
    "cccol",
    "context",
    ("context_mit", "krb5_init_secure_context"),
    "creds",
    "creds_opt",
    ("creds_opt_heimdal", "krb5_get_init_creds_opt_set_default_flags"),
    ("creds_opt_mit", "krb5_get_init_creds_opt_set_out_ccache"),
    ("creds_opt_set_in_ccache", "krb5_get_init_creds_opt_set_in_ccache"),
    ("creds_opt_set_pac_request", "krb5_get_init_creds_opt_set_pac_request"),
    "exceptions",
    "keyblock",
    "kt",
    ("kt_mit", "krb5_kt_dup"),
    ("kt_heimdal", "krb5_kt_get_full_name"),
    ("kt_have_content", "krb5_kt_have_content"),
    "principal",
    ("principal_heimdal", "krb5_principal_get_realm"),
    "string",
    ("string_mit", "krb5_enctype_to_name"),
]:
    name = e
    canary = None
    if isinstance(e, tuple):
        name = e[0]
        if len(e) > 1:
            canary = e[1]

    ext = make_extension(
        f"krb5._{name}",
        module=krb5,
        canary=canary,
        extra_link_args=link_args,
        extra_compile_args=compile_args,
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
    )
    if ext:
        raw_extensions.append(ext)

if SOURCE_EXT == "c":
    extensions = raw_extensions
else:
    extensions = cythonize(
        raw_extensions,
        language_level=3,
        compiler_directives={"linetrace": CYTHON_LINETRACE},
    )


class sdist_krb5(sdist):
    def run(self) -> None:
        if not self.dry_run:
            with open(SKIP_CYTHON_FILE, mode="wb") as flag_file:
                flag_file.write(b"")

            sdist.run(self)

            os.remove(SKIP_CYTHON_FILE)


setup(
    name="krb5",
    version="0.3.0",
    packages=find_packages(where="src"),
    package_data={
        "krb5": ["py.typed", "*.pyi"],
    },
    package_dir={"": "src"},
    py_modules=[os.path.splitext(os.path.basename(path))[0] for path in glob.glob("src/*.py")],
    cmdclass={
        "sdist": sdist_krb5,
    },
    ext_modules=extensions,
    include_package_data=False,
    install_requires=[],
    extras_require={},
    author="Jordan Borean",
    author_email="jborean93@gmail.com",
    url="https://github.com/jborean93/pykrb5",
    description="Kerberos API bindings for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="krb5 kerberos",
    license="MIT",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
