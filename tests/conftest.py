"""Shared fixtures: a real gateway talking to the real demo MCP servers over stdio."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from byteshield.app import create_app
from byteshield.config import Settings


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("byteshield-data")


@pytest.fixture(scope="session")
def client(data_dir):
    settings = Settings(data_dir=data_dir, demo_mode=True, admin_token=None, mode_override=None)
    with TestClient(create_app(settings), base_url="http://testserver") as c:
        yield c


@pytest.fixture()
def agent(client):
    from demo.scenarios import Agent
    return Agent(client, "pytest-agent")
