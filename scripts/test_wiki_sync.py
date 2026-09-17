from __future__ import annotations

import unittest
from pathlib import Path

import wiki_sync


class WalkthroughLinksTest(unittest.TestCase):
    def test_home_uses_published_release_media(self: WalkthroughLinksTest) -> None:
        page: wiki_sync.Page = next(
            page for page in wiki_sync.discover_pages() if page.wiki_name == "Home"
        )
        warnings: list[str] = []
        rendered: str = wiki_sync.transform_page(page, warnings)
        for name in ("walkthrough.mp4", "poster.png", "captions.vtt", "chapters.vtt", "transcript.txt"):
            self.assertIn(f"https://1-3-7.github.io/disrobe/latest/assets/walkthrough/{name}", rendered)
        self.assertNotIn("./assets/walkthrough/", rendered)

    def test_repository_images_keep_their_existing_location(self: WalkthroughLinksTest) -> None:
        source: Path = wiki_sync.DOCS_SRC / "introduction.md"
        self.assertEqual(
            wiki_sync.resolve_asset_url(source, "./assets/social-card.png"),
            "https://raw.githubusercontent.com/1-3-7/disrobe/main/docs/src/assets/social-card.png",
        )

    def test_external_links_are_preserved(self: WalkthroughLinksTest) -> None:
        source: Path = wiki_sync.DOCS_SRC / "introduction.md"
        text: str = '[video](https://example.com/video.mp4)'
        self.assertEqual(wiki_sync.rewrite_links(source, text, []), text)


if __name__ == "__main__":
    unittest.main()
