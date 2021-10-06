# Python Kerberos 5 Library

[![Test workflow](https://github.com/jborean93/pykrb5/actions/workflows/ci.yml/badge.svg)](https://github.com/jborean93/pykrb5/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/krb5.svg)](https://badge.fury.io/py/krb5)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/pykrb5/blob/main/LICENSE)

This library provides Python functions that wraps the Kerberos 5 C API.
Due to the complex nature of this API it is highly recommended to use something like [python-gssapi](https://github.com/pythongssapi/python-gssapi) which exposes the Kerberos authentication details through GSSAPI.

## Requirements

* An implementation of the Kerberos 5 API - including the header files
  * [MIT Kebreros](https://web.mit.edu/kerberos/)
  * [Heimdal](https://github.com/heimdal/heimdal)
* A C compiler, such as GCC
* Python 3.6+

_Note: macOS includes their own implementation of Heimdal and a compiler isn't needed on that platform if installing from the wheel._

## Installation

Simply run:

```bash
pip install krb5
```

To install from source run the following:

```bash
git clone https://github.com/jborean93/pykrb5.git
pip install Cython
python setup.py bdist_wheel
pip install dist/krb5-*.whl
```

Compiling the code should automatically pick up the proper paths for the KRB5 headers and locations.
If further customisation is needed, the following environment variables can be set when building the wheel:

* `KRB5_KRB5CONFIG`
  * The path to `krb5-config` to use for detecting the Kerberos library to link to
  * The compiler and linker args are derived from what this function outputs
  * Defaults to whatever `krb5-config` is on the `PATH`
  * FreeBSD will default to `/usr/local/bin/krb5-config` instead of `/usr/bin/krb5-config`
* `KRB5_MAIN_LIB`
  * The path to the `libkrb5` shared library used to check if any of the optional functions are available
* `KRB5_COMPILER_ARGS`
  * Compiler flags to use when compiling the extensions
  * Defaults to the output of `krb5-config --cflags krb5` if not set
* `KRB5_LINKER_ARGS`
  * Linker flags to use when compiling the extensions
  * Defaults to the output of `krb5-config --libs krb5` if not set
* `KRB5_SKIP_MODULE_CHECK`
  * Skips the checks used to detect if optional functions are available - will treat them all as available
  * This is only really useful when building the sdist as no implementation provides all these functions
* `KRB5_CYTHON_TRACING`
  * Used to generate the Cython extensions with line tracing for coverage collection
* `KRB5_MACOS_HEIMDAL_DIR`
  * Used when compiling on macOS to point to the Heimdal install directory
  * Used to find the Heimdal header files as macOS does not include, or provide a way to obtain, these header files for their Heimdal framework
  * Defaults to `{git_root}/build_helpers/heimdal`

## Development

To run the tests or make changes to this repo run the following:

```bash
git clone https://github.com/jborean93/pykrb5.git
pip install -r requirements-dev.txt
pre-commit install

python setup.py build_ext --inplace
```

From there an editor like VSCode can be used to make changes and run the test suite.
To recompile the Cython files after a change run the `build_ext --inplace` command.

## Structure

This library is merely a wrapper around the Kerberos 5 APIs.
The functions under the `krb5` namespace match the KRB5 API specification but with the `krb5_` prefix remove.
For example the [krb5_init_context](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_init_context.html) function is called through `krb5.init_context()`.
Errors are raised as a `Krb5Error` which contains the message as formatted by the KRB5 implementation and the error code for that error.
Some of the structures returned by these functions are represented by a Python class and are freed once they are deallocated once all references to that object is removed.
Some classes expose an `addr` property that returns the raw pointer address of the structure it is wrapping.
This is so the structure can be used in other libraries like `python-gssapi` but great care must be taken that nothing else frees the structure as that could cause a segmentation fault.

Not all the functions exposed in this library are available on every KRB5 API implementation.
To check if a function is available run the following:

```python
import krb5

if not hasattr(krb5, "kt_dup"):
    raise Exception("Current implementation does not support krb5_kt_dup")
```

There may also be some difference in behaviour, error codes, error messages, between te different implementations.
It is up to the caller to paper over these differences when required.
