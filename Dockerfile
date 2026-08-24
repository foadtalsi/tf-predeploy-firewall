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
# checkout, which is why a scan needs no credentials of any kind by default.
# ca-certificates is for the optional control plane and for the optional
# read-only cloud lookups.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/

# `[aws]` — boto3, for --cloud-read-access. It roughly triples the image, which
# is why it is an extra in pyproject.toml rather than a dependency, and why a
# `pip install` of the scanner does not carry it. Here it has to be present:
# whether the option is used is decided by the person writing the workflow,
# long after this image was built, and "install a package to turn a flag on" is
# not something a container action lets them do. The flag stays off by default,
# so the bytes sit unused for anyone who never asks for it.
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[aws]" && rm /tmp/*.whl

# La garde de propriété de git ne se règle PAS ici, et c'est délibéré.
#
# Il y avait à cet endroit un `git config --global --add safe.directory`. Il
# n'a jamais eu d'effet : `--global` écrit dans `$HOME/.gitconfig` au moment de
# la construction de l'image, et GitHub réécrit `HOME` à l'exécution
# (`/github/home`). Le fichier existait, git ne le lisait jamais, et chaque
# scan échouait sur « dubious ownership » — donc l'Action ne calculait aucun
# diff, chez personne.
#
# Le réglage est désormais passé par `-c` à chaque appel git, dans
# `tfpdf.diff.git`. Il ne dépend plus de l'environnement, et il couvre les
# usages que cette image ne voit pas.

ENTRYPOINT ["tf-predeploy-firewall"]
