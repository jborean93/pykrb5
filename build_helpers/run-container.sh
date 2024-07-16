#!/bin/bash -ex

# KRB5_PROVIDER and DEBIAN_VERSION can be set to run tests against different
# versions. A full test suite before release should be run with
# DEBIAN_VERSION=10 KRB5_PROVIDER=mit build_helpers/run-container.sh
# DEBIAN_VERSION=10 KRB5_PROVIDER=heimdal build_helpers/run-container.sh
# DEBIAN_VERSION=11 KRB5_PROVIDER=mit build_helpers/run-container.sh
# DEBIAN_VERSION=12 KRB5_PROVIDER=mit build_helpers/run-container.sh

export DEBIAN_VERSION="${DEBIAN_VERSION:-10}"

docker run \
    --rm \
    --interactive \
    --hostname test.krbtest.com \
    --volume "$( pwd )":/tmp/build:z \
    --workdir /tmp/build \
    --env KRB5_PROVIDER=${KRB5_PROVIDER:-mit} \
    --env DEBIAN_VERSION=${DEBIAN_VERSION} \
    debian:${DEBIAN_VERSION} /bin/bash -ex -c 'source /dev/stdin' << 'EOF'

source ./build_helpers/lib.sh
lib::setup::system_requirements

apt-get -y install \
    python3 \
    python3-{dev,pip,venv}

. /etc/os-release
if [ "$VERSION_ID" = "10" ]; then
    ln -s /usr/bin/python3 /usr/bin/python
else
    python3 -m venv .venv
    source .venv/bin/activate
fi

python -m pip install build
python -m build
lib::setup::python_requirements

# Ensure we don't pollute the local dir + mypy doesn't like this
rm -rf dist
rm -rf build

lib::sanity::run

export PYTEST_ADDOPTS="--color=yes"
lib::tests::run
EOF
