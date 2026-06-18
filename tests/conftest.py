import pytest

from core.http_client import clear_request_cache, set_allow_localhost


@pytest.fixture(autouse=True)
def reset_scan_state():
    clear_request_cache()
    set_allow_localhost(False)
    yield
    clear_request_cache()
    set_allow_localhost(False)
