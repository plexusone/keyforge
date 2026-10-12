"""Remove the theme's default PNG favicon from the built site.

The site is published from a branch that holds only the built output, and the
publication scan refuses a file it cannot read as text. The theme's PNG favicon
is replaced by the SVG favicon in mkdocs.yml and nothing links to it.

The gzipped sitemap that MkDocs writes is kept: search engines read it, and it
is allowed by name in the central publication policy.

Python writes bytecode for this file into hooks/__pycache__, which the
publication scan of the working tree also refuses as an unreadable binary. Build
with PYTHONDONTWRITEBYTECODE=1 to avoid creating it, or delete the directory.
"""

import os

_BINARIES = (os.path.join("assets", "images", "favicon.png"),)


def on_post_build(config, **kwargs):
    for name in _BINARIES:
        path = os.path.join(config["site_dir"], name)
        if os.path.exists(path):
            os.remove(path)
