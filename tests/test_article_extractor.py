"""Security regression tests for conservative same-site extraction."""

from unittest.mock import Mock

from src.ethio_cyber_intel.article_extractor import ArticleExtractor


def test_redirected_robots_file_does_not_allow_page_fetch():
    session = Mock()
    response = Mock(status_code=302, ok=True, text="", headers={})
    session.get.return_value = response
    extractor = ArticleExtractor(session=session)

    result = extractor.extract(
        "https://news.example.test/report", allowed_hostname="news.example.test",
        delay_seconds=0,
    )

    assert result is None
    assert session.get.call_count == 1
    assert session.get.call_args.args[0] == "https://news.example.test/robots.txt"
    assert session.get.call_args.kwargs["allow_redirects"] is False


def test_non_success_robots_response_does_not_allow_page_fetch():
    session = Mock()
    session.get.return_value = Mock(status_code=503, ok=False, text="", headers={})
    extractor = ArticleExtractor(session=session)

    result = extractor.extract(
        "https://news.example.test/report", allowed_hostname="news.example.test",
        delay_seconds=0,
    )

    assert result is None
    assert session.get.call_count == 1


def test_non_https_or_cross_host_pages_are_not_requested():
    session = Mock()
    extractor = ArticleExtractor(session=session)

    assert extractor.extract("http://news.example.test/a", allowed_hostname="news.example.test") is None
    assert extractor.extract("https://other.example.test/a", allowed_hostname="news.example.test") is None
    session.get.assert_not_called()
