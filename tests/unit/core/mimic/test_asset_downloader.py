from core.sentient.mimic.downloader import AssetDownloader, AssetType


def test_detect_type_from_url_extensions():
    assert AssetDownloader.detect_type_from_url("https://example.com/app.js") == AssetType.JAVASCRIPT
    assert AssetDownloader.detect_type_from_url("https://example.com/app.js.map") == AssetType.SOURCE_MAP
    assert AssetDownloader.detect_type_from_url("https://example.com/styles.css") == AssetType.CSS
    assert AssetDownloader.detect_type_from_url("https://example.com/manifest.json") == AssetType.MANIFEST
    assert AssetDownloader.detect_type_from_url("https://example.com/logo.png") == AssetType.IMAGE


def test_replay_reconstructs_assets():
    downloader = AssetDownloader()
    recorded = {
        "assets": [
            {
                "url": "https://example.com/app.js",
                "asset_type": "javascript",
                "content": "console.log('x');",
                "size_bytes": 17,
                "content_hash": "abc123",
                "headers": {"content-type": "application/javascript"},
            }
        ]
    }
    restored = downloader.replay(recorded)
    assert len(restored) == 1
    assert restored[0].url == "https://example.com/app.js"
    assert restored[0].asset_type == AssetType.JAVASCRIPT
