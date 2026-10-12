"""Remove the binary files MkDocs and the theme add to the built site.

The site is published from a branch that holds only the built output, and the
publication scan refuses a file it cannot read as text. The two binaries are
a gzipped copy of the sitemap, which MkDocs writes itself, and the theme's
default PNG favicon, which the SVG favicon in mkdocs.yml replaces. Nothing
links to either.
"""

import os

_BINARIES = ("sitemap.xml.gz", os.path.join("assets", "images", "favicon.png"))


def on_post_build(config, **kwargs):
    for name in _BINARIES:
        path = os.path.join(config["site_dir"], name)
        if os.path.exists(path):
            os.remove(path)
