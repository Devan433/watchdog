import pytest
from core.http_client import is_safe_hostname, SSRFDetectedException, set_allow_localhost


def test_blocks_private_ip():
    with pytest.raises(SSRFDetectedException):
        is_safe_hostname("127.0.0.1")


def test_allows_localhost_when_enabled():
    set_allow_localhost(True)
    assert is_safe_hostname("127.0.0.1") == "127.0.0.1"
    set_allow_localhost(False)
