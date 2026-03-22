"""
Unit tests for core.mimic.downloader (AssetDownloader).

Tests URL filtering and download result construction.
"""
import pytest
from core.mimic.downloader import AssetDownloader, DownloadResult


def test_filter_accepts_js_css_map():
    """Verify the URL filter accepts .js, .css, and .map files."""
    downloader = AssetDownloader.__new__(AssetDownloader)

    assert downloader._filter_asset_url("https://example.com/app.js") is True
    assert downloader._filter_asset_url("https://example.com/app.js.map") is True
    assert downloader._filter_asset_url("https://example.com/styles.css") is True
    assert downloader._filter_asset_url("https://cdn.example.com/bundle.min.js?v=123") is True


def test_filter_rejects_non_assets():
    """Verify the URL filter rejects non-JS/CSS/MAP files."""
    downloader = AssetDownloader.__new__(AssetDownloader)

    assert downloader._filter_asset_url("https://example.com/logo.png") is False
    assert downloader._filter_asset_url("https://example.com/page.html") is False
    assert downloader._filter_asset_url("https://example.com/data.json") is False
    assert downloader._filter_asset_url("https://example.com/api/users") is False


def test_filter_case_insensitive():
    """URL filter should work regardless of case."""
    downloader = AssetDownloader.__new__(AssetDownloader)

    assert downloader._filter_asset_url("https://example.com/App.JS") is True
    assert downloader._filter_asset_url("https://example.com/STYLES.CSS") is True
    assert downloader._filter_asset_url("https://example.com/bundle.JS.MAP") is True
