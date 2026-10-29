# Copyright 2026 Aman Karir
# SPDX-License-Identifier: Apache-2.0
# Part of Shadow AI Guard, https://github.com/AmanSK5/shadow-ai-guard

"""Where discovery may talk to the receiver over plain HTTP: inside the
deployment only. In-cluster under the chart, by service name under Compose -
which it refused, so discovery never started under Compose at all."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import discover  # noqa: E402


@pytest.mark.parametrize("url", ["https://ai-guard.example.com", "http://ai-guard-receiver.ai-guard.svc.cluster.local:8080",
                                 "http://receiver:8080"])
def test_inside_the_deployment_or_over_https_is_allowed(url):
    discover._require_https_or_cluster("RECEIVER_URL", url)


@pytest.mark.parametrize("url", ["http://ai-guard.example.com", "http://10.0.0.5:8080", "http://receiver.example.com"])
def test_plain_http_to_anywhere_else_is_refused(url):
    with pytest.raises(SystemExit):
        discover._require_https_or_cluster("RECEIVER_URL", url)
