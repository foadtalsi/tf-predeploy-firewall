# The image the GitHub Action runs in.
#
# Two stages, for one reason: the build stage needs a build backend and a wheel
# cache, and none of that belongs in an image that gets pulled on every PR in
# every repo that uses this action.
#
# `slim` rather than `alpine`: PyYAML is the only dependency and it does publish
# musllinux wheels, so alpine would work and would be smaller — but it would
# work by luck. The day a wheel is missing for the runner's architecture, alpine
# starts compiling C on a CI runner, and the failure surfaces as a red check on
# somebody's PR rather than here. The scanner's whole argument is that it should
# never be the reason a pipeline breaks; a 60 MB image is the cheaper side of
# that trade.

FROM python:3.12-slim-bookworm AS build
WORKDIR /src

RUN pip install --no-cache-dir hatchling build

# Copied separately so a change to the scanner's source does not invalidate the
# layer that installed the build backend.
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m build --wheel --outdir /dist .


FROM python:3.12-slim-bookworm

# git is not optional: the scanner reads the diff between two refs from a local
# checkout, which is also why it needs no cloud credentials and no terraform
# state. ca-certificates is for the optional control plane.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Actions check out the repository into the workspace and run the container
# against it. `git` refuses to operate on a repository owned by another user,
# which is exactly what a bind-mounted workspace looks like from in here — so
# the workspace is declared safe rather than left to fail with a message about
# dubious ownership that has nothing to do with Terraform.
RUN git config --global --add safe.directory /github/workspace \
    && git config --global --add safe.directory '*'

ENTRYPOINT ["tf-predeploy-firewall"]
