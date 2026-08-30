from app.main import app
from app.database import add_source, get_sources
from app.security import is_safe_url


def test_health():
    client = app.test_client()

    response = client.get("/api/health")

    assert response.status_code == 200


def test_source_creation():
    test_name = "Test Kaynagi"
    test_url = "https://test-source-osint.example.com"

    add_source(
        test_name,
        test_url,
        "web",
        0,
        1
    )

    sources = get_sources()

    assert any(
        source[1] == test_name and source[2] == test_url
        for source in sources
    )


def test_url_safety_blocks_localhost():
    assert is_safe_url("http://localhost") is False


def test_url_safety_blocks_loopback():
    assert is_safe_url("http://127.0.0.1") is False


def test_url_safety_blocks_private_ip():
    assert is_safe_url("http://192.168.1.1") is False


def test_url_safety_blocks_metadata():
    assert is_safe_url("http://169.254.169.254") is False


def test_url_safety_blocks_invalid_scheme():
    assert is_safe_url("ftp://example.com") is False


def test_url_safety_allows_public_ip():
    assert is_safe_url("https://8.8.8.8") is True