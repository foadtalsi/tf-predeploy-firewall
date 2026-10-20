# The image the GitHub Action runs in.
#
# Two stages, for one reason: the build stage needs a build backend and a wheel
# cache, and none of that belongs in an image that gets pulled on every PR in
# every repo that uses this action.
#
# `slim` rather than `alpine`: the dependencies do publish musllinux wheels, so
# alpine would work and would be smaller — but it would work by luck. The day a
# wheel is missing for the runner's architecture, alpine starts compiling C on a
# CI runner, and the failure surfaces as a red check on somebody's PR rather
# than here. The scanner's whole argument is that it should never be the reason
# a pipeline breaks; a larger image is the cheaper side of that trade.

# Every input is pinned: the base image by digest, Python packages by version and hash
# (requirements/*.txt). The image is rebuilt from this file on every run of the Action, in
# every repository that uses it, so anything left floating would change what those
# repositories run without a commit here. Dependabot proposes the updates.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS build
WORKDIR /src

COPY requirements/build.txt /tmp/build.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/build.txt

# Copied separately so a change to the scanner's source does not invalidate the
# layer that installed the build backend. --no-isolation builds with the pinned
# backend above instead of downloading an unpinned one.
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m build --wheel --no-isolation --outdir /dist .


FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

# git is not optional: the scanner reads the diff between two refs from a local
# checkout, which is why a scan needs no credentials of any kind by default.
# ca-certificates is for the optional control plane and for the optional
# read-only cloud lookups.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
COPY requirements/image.txt /tmp/image.txt

# `[aws]` — boto3, for --cloud-read-access. It roughly triples the image, which
# is why it is an extra in pyproject.toml rather than a dependency, and why a
# `pip install` of the scanner does not carry it. Here it has to be present:
# whether the option is used is decided by the person writing the workflow,
# long after this image was built, and "install a package to turn a flag on" is
# not something a container action lets them do. The flag stays off by default,
# so the bytes sit unused for anyone who never asks for it.
#
# The dependencies come from the hash-locked file; the wheel itself is installed without
# resolving anything further.
RUN pip install --no-cache-dir --require-hashes -r /tmp/image.txt \
    && pip install --no-cache-dir --no-deps /tmp/*.whl \
    && rm /tmp/*.whl /tmp/image.txt

# Git ownership overrides are passed per command in tfpdf.diff.git; a build-time global config
# would be lost when Actions changes HOME.

ENTRYPOINT ["tf-predeploy-firewall"]
