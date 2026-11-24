"""Security regression tests for conservative same-site extraction."""

from unittest.mock import Mock
from time import struct_time

from src.ethio_cyber_intel.article_extractor import ArticleExtractor
from src.ethio_cyber_intel.rss_collector import normalize_entry
from tests.test_rss_collector import source


EXPECTED_TITLE = "Google Researcher Shows How a Single Bit Change in .NET Files Bypassed Windows Code Integrity"
ARTICLE_URL = "https://news.example.test/google-researcher-dotnet-code-integrity"
RELATED_CARD = "11 Real Stories: How Identity Exposure Unlocks Active Attack Paths Map cross-domain privilege escalation to sever breach routes at key choke points."
ARTICLE_BODY = ("Google Project Zero researcher James Forshaw showed that a single bit change in .NET files "
                "bypassed Windows code integrity protections. The report explains the affected behavior and "
                "describes the vendor response and publication timeline. " * 8)


def response(status_code, *, text="", content=b"", headers=None):
    value = Mock(status_code=status_code, text=text, content=content, headers=headers or {})
    value.raise_for_status.return_value = None
    return value


def test_redirected_robots_file_does_not_allow_page_fetch():
    session = Mock()
    response = Mock(status_code=302, ok=True, text="", headers={})
    session.get.return_value = response
    extractor = ArticleExtractor(session=session)

    result = extractor.extract(
        "https://news.example.test/report", allowed_hostname="news.example.test",
        expected_title="Security report on the public network",
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
        expected_title="Security report on the public network",
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


def test_private_literal_article_hosts_are_rejected():
    session = Mock()
    extractor = ArticleExtractor(session=session)
    assert extractor.extract(
        "https://127.0.0.1/report", allowed_hostname="127.0.0.1",
        expected_title="A report", delay_seconds=0,
    ) is None
    session.get.assert_not_called()


def test_extractor_uses_article_body_not_first_recommendation_card():
    html = f"""<!doctype html><html><head>
      <link rel="canonical" href="{ARTICLE_URL}">
      <meta property="og:title" content="{EXPECTED_TITLE}">
      </head><body>
      <h1>{EXPECTED_TITLE}</h1>
      <article class="recommendation">{RELATED_CARD}</article>
      <div id="articlebody">{ARTICLE_BODY}</div>
      </body></html>""".encode()
    session = Mock()
    session.get.side_effect = [
        response(200, text="User-agent: *\nAllow: /"),
        response(200, content=html, headers={"Content-Type": "text/html; charset=utf-8"}),
    ]
    extractor = ArticleExtractor(session=session)

    article = normalize_entry({
        "title": EXPECTED_TITLE,
        "summary": "The report describes a .NET behavior affecting Windows code integrity protections.",
        "link": ARTICLE_URL,
        "published_parsed": struct_time((2026, 11, 24, 12, 2, 0, 0, 329, 0)),
    }, source(), extractor=extractor)

    assert article is not None
    assert article["title"] == EXPECTED_TITLE
    assert article["url"] == ARTICLE_URL
    assert article["published_at"] == "2026-11-24T12:02:00Z"
    assert article["content"].startswith("Google Project Zero researcher")
    assert RELATED_CARD not in article["content"]
    assert article["content_validation_status"] == "page_identity_verified"
    assert article["language"] == "en"


def test_extraction_rejects_mismatched_page_headline():
    html = f"""<html><head><title>Unrelated Identity Exposure Report</title></head>
      <body><h1>Unrelated Identity Exposure Report</h1><main>{ARTICLE_BODY}</main></body></html>""".encode()
    session = Mock()
    session.get.side_effect = [
        response(200, text="User-agent: *\nAllow: /"),
        response(200, content=html, headers={"Content-Type": "text/html"}),
    ]
    extractor = ArticleExtractor(session=session)

    result = extractor.extract(
        ARTICLE_URL, allowed_hostname="news.example.test", expected_title=EXPECTED_TITLE,
        delay_seconds=0,
    )

    assert result is None
    assert session.get.call_count == 2


def test_normalization_keeps_rss_provenance_when_page_identity_fails():
    html = b"<html><head><title>Unrelated Identity Exposure Report</title></head><body><main>" + ARTICLE_BODY.encode() + b"</main></body></html>"
    session = Mock()
    session.get.side_effect = [
        response(200, text="User-agent: *\nAllow: /"),
        response(200, content=html, headers={"Content-Type": "text/html"}),
    ]
    extractor = ArticleExtractor(session=session)
    description = "The RSS source description remains the authoritative fallback for this report."

    article = normalize_entry({
        "title": EXPECTED_TITLE, "summary": description, "link": ARTICLE_URL,
        "published_parsed": struct_time((2026, 11, 24, 12, 2, 0, 0, 329, 0)),
    }, source(), extractor=extractor)

    assert article["title"] == EXPECTED_TITLE
    assert article["url"] == ARTICLE_URL
    assert article["published_at"] == "2026-11-24T12:02:00Z"
    assert article["summary"] == description
    assert article["content"] is None
    assert article["content_validation_status"] == "extraction_rejected"


def test_unexpected_page_extraction_error_preserves_rss_fallback():
    class FailingExtractor:
        def extract(self, *args, **kwargs):
            raise RuntimeError("simulated extractor failure")

    article = normalize_entry({
        "title": EXPECTED_TITLE, "summary": "Publisher supplied RSS fallback description.",
        "link": ARTICLE_URL,
    }, source(), extractor=FailingExtractor())
    assert article["summary"] == "Publisher supplied RSS fallback description."
    assert article["content"] is None
    assert article["content_validation_status"] == "extraction_rejected"


def test_extraction_rejects_canonical_url_for_another_article():
    html = f"""<html><head><link rel="canonical" href="https://news.example.test/other">
      <title>{EXPECTED_TITLE}</title></head><body><h1>{EXPECTED_TITLE}</h1>
      <main>{ARTICLE_BODY}</main></body></html>""".encode()
    session = Mock()
    session.get.side_effect = [
        response(200, text="User-agent: *\nAllow: /"),
        response(200, content=html, headers={"Content-Type": "text/html"}),
    ]
    extractor = ArticleExtractor(session=session)

    assert extractor.extract(
        ARTICLE_URL, allowed_hostname="news.example.test", expected_title=EXPECTED_TITLE,
        delay_seconds=0,
    ) is None


def test_extraction_fails_closed_without_an_article_body_container():
    html = f"""<html><head><title>{EXPECTED_TITLE}</title></head><body>
      <main><h1>{EXPECTED_TITLE}</h1><article class="recommendation">{RELATED_CARD}</article></main>
      </body></html>""".encode()
    session = Mock()
    session.get.side_effect = [
        response(200, text="User-agent: *\nAllow: /"),
        response(200, content=html, headers={"Content-Type": "text/html"}),
    ]
    extractor = ArticleExtractor(session=session)

    assert extractor.extract(
        ARTICLE_URL, allowed_hostname="news.example.test", expected_title=EXPECTED_TITLE,
        delay_seconds=0,
    ) is None
