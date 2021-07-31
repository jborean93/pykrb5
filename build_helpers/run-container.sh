#!/bin/bash -ex

# Run with 'KRB5_PROVIDER=heimdal build_helpers/run-container.sh' to run tests
# against Heimdal.

docker run \
    --rm \
    --interactive \
    --hostname test.krbtest.com \
    --volume "$( pwd )":/tmp/build:z \
    --workdir /tmp/build \
    --env KRB5_PROVIDER=${KRB5_PROVIDER:-mit} \
    debian:10 /bin/bash -ex -c 'source /dev/stdin' << 'EOF'

source ./build_helpers/lib.sh
lib::setup::system_requirements

apt-get -y install \
    cython3 \
    python3 \
    python3-{dev,pip,setuptools,virtualenv,wheel}
ln -s /usr/bin/python3 /usr/bin/python

python setup.py bdist_wheel
lib::setup::python_requirements

# Ensure we don't pollute the local dir + mypy doesn't like this
rm -rf dist
rm -rf build

lib::sanity::run

export PYTEST_ADDOPTS="--color=yes"
lib::tests::run
EOF
