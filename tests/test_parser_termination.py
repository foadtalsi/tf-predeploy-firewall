"""The parser terminates on any malformed input, so a broken file cannot hang a CI job.

A pull request is untrusted input. A file that makes the parser loop does not fail the scan, it
stops it: the job runs until the CI timeout. Each prefix of a representative file is a realistic
malformed input (an unterminated string, heredoc, interpolation, block or expression), and every
one of them must come back with a result or diagnostics, quickly.
"""

from __future__ import annotations

import signal
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from tfpdf import hcl

_REPRESENTATIVE = """\
locals {
  name   = "${var.prefix}-app"
  tags   = { Name = "web", Team = "platform" }
  ports  = [for port in var.ports : port if port > 1024]
  greeting = "%{ if var.formal }Good day%{ else }Hi%{ endif }, ${var.user}"
}

resource "aws_instance" "web" {
  count         = var.enabled ? 1 : 0
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  user_data     = <<-EOT
    #!/bin/bash
    echo "${local.name}" > /etc/hostname
  EOT

  dynamic "ebs_block_device" {
    for_each = var.volumes
    content {
      device_name = ebs_block_device.value.name
      volume_size = ebs_block_device.value.size
    }
  }
}
"""

_SECONDS_PER_PARSE = 2


@contextmanager
def _time_limit(seconds: int) -> Iterator[None]:
    def _raise(_signal: int, _frame: object) -> None:
        raise TimeoutError

    previous = signal.signal(signal.SIGALRM, _raise)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _parse_within_limit(source: str) -> None:
    try:
        with _time_limit(_SECONDS_PER_PARSE):
            hcl.parse_config(source.encode(), "main.tf")
    except TimeoutError:
        pytest.fail(f"the parser did not terminate on:\n{source}")


def test_every_truncation_of_a_file_terminates() -> None:
    for end in range(len(_REPRESENTATIVE) + 1):
        # With and without a line break after the cut: an unterminated string behaves
        # differently at a newline than at the end of the file.
        _parse_within_limit(_REPRESENTATIVE[:end])
        _parse_within_limit(_REPRESENTATIVE[:end] + "\n")


@pytest.mark.parametrize(
    "line",
    [
        'name = "unterminated',
        'name = "${var.prefix-app"',
        'name = "${var.prefix}',
        'name = "%{ if var.formal }',
        'name = "${"${"${x',
        "body = <<EOT\nnever closed",
        "values = [1, 2,",
        "object = { a = 1",
    ],
)
def test_an_unterminated_construct_is_a_diagnostic(line: str) -> None:
    _parse_within_limit(line + "\nnext = 1\n")
    _, diagnostics = hcl.parse_config((line + "\nnext = 1\n").encode(), "main.tf")
    assert diagnostics.has_errors()
