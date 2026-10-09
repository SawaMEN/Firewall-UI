#!/usr/bin/env python3
"""Create the updater manifest from binaries already built and tested by CI."""
import hashlib
import json
import os
import pathlib
import sys

channel, version, tag = sys.argv[1:]
folder = pathlib.Path(f"dist-{channel}")
assets = {}
for arch in ("amd64", "arm64"):
    binary = folder / f"firewall-ui-linux-{arch}"
    assets[arch] = {
        "url": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/releases/download/{tag}/{binary.name}",
        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
(folder / "update.json").write_text(json.dumps({
    "version": version,
    "channel": channel,
    "commit": os.environ["BUILD_COMMIT"],
    "buildTime": os.environ["BUILD_TIME"],
    "assets": assets,
}, indent=2) + "\n")
