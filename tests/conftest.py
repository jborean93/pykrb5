# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import typing

import k5test
import pytest

import krb5


# This could be extensive to do per function so just do it once and share that
@pytest.fixture(scope="session")
def realm() -> typing.Iterator[k5test.K5Realm]:
    test_realm = k5test.K5Realm()
    try:
        original_env: typing.Dict[str, typing.Optional[str]] = {}
        for k in test_realm.env.keys():
            original_env[k] = os.environ.pop(k, None)

        try:
            os.environ.update(test_realm.env)

            yield test_realm

        finally:
            for k, v in original_env.items():
                if v:
                    os.environ[k] = v
                else:
                    del os.environ[k]

    finally:
        test_realm.stop()
        del test_realm


@pytest.fixture(autouse=True)
def requires_api(request: typing.Any) -> None:
    marker = request.node.get_closest_marker("requires_api")
    if marker:
        api_name = marker.args[0]
        if not hasattr(krb5, api_name):
            pytest.skip(f"KRB5 API {api_name} not available on current environment")

    return


def pytest_configure(config: typing.Any) -> None:
    config.addinivalue_line(
        "markers",
        "requires_api(name): skip tests that don't have the required KRB5 API installed",
    )
