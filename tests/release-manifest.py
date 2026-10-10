#!/usr/bin/env python3
"""Check unified release metadata using the real generator and image downloader."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.env = dict(os.environ, GITHUB_REPOSITORY="SawaMEN/Firewall-UI",
                        BUILD_COMMIT="test-commit", BUILD_TIME="2026-10-10T00:00:00Z")
        for channel in ("stable", "dev"):
            (self.directory / f"dist-{channel}").mkdir()
            for arch in ("amd64", "arm64"):
                (self.directory / f"dist-{channel}" / f"firewall-ui-linux-{arch}").write_bytes(arch.encode())
        for channel in ("stable", "dev"):
            (self.directory / "release-images" / channel).mkdir(parents=True)
            for arch in ("amd64", "arm64"):
                (self.directory / "release-images" / channel / f"firewall-ui-docker-linux-{arch}.tar.gz").write_bytes(f"image-{channel}-{arch}".encode())

    def generate(self, channel="stable"):
        tag = "v1.3.2" if channel == "stable" else "dev"
        subprocess.run(["python3", str(ROOT / "scripts/release-manifest.py"), channel, "1.3.2", tag],
                       cwd=self.directory, env=self.env, check=True)
        return json.loads((self.directory / f"dist-{channel}/update.json").read_text())

    def test_one_manifest_and_native_compatibility(self):
        manifest = self.generate()
        self.assertEqual(set(manifest["assets"]), {"amd64", "arm64", "docker-amd64", "docker-arm64"})
        self.assertFalse((self.directory / "release-images/docker-update.json").exists())
        for arch in ("amd64", "arm64"):
            binary = self.directory / f"dist-stable/firewall-ui-linux-{arch}"
            self.assertEqual(manifest["assets"][arch]["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            # Existing shell installers select the exact architecture key.
            result = subprocess.run(["sed", "-n", f'/"{arch}"[[:space:]]*:/,/^[[:space:]]*}}/p',
                                     str(self.directory / "dist-stable/update.json")], capture_output=True, text=True, check=True)
            self.assertIn(f"/firewall-ui-linux-{arch}", result.stdout)
            self.assertNotIn("firewall-ui-docker", result.stdout)
        dev = self.generate("dev")
        self.assertEqual(set(dev["assets"]), {"amd64", "arm64", "docker-amd64", "docker-arm64"})
        self.assertTrue(dev["assets"]["docker-amd64"]["url"].endswith("/dev/firewall-ui-docker-linux-amd64.tar.gz"))

    def download(self, arch, legacy=False, bad_checksum=False):
        manifest = self.generate()
        if bad_checksum:
            manifest["assets"][f"docker-{arch}"]["sha256"] = "0" * 64
        old = dict(manifest, assets={arch: manifest["assets"][f"docker-{arch}"]})
        if legacy:
            manifest["assets"] = {key: value for key, value in manifest["assets"].items() if not key.startswith("docker-")}
        (self.directory / "manifest.json").write_text(json.dumps(manifest, indent=2))
        (self.directory / "old-manifest.json").write_text(json.dumps(old, indent=2))
        script = r'''
set -Eeuo pipefail
source "$TASK_ROOT/deploy/firewall-ui-docker"
unset FIREWALL_UI_DOCKER_IMAGE_ARCHIVE FIREWALL_UI_DOCKER_IMAGE_SHA256
uname() { printf '%s\n' "$TASK_ARCH"; }
curl() {
  local url="${@: -3:1}" destination="${@: -1}"
  printf '%s\n' "$url" >> "$TASK_FIXTURE/requests"
  case "$url" in
    */docker-update.json) cp "$TASK_FIXTURE/old-manifest.json" "$destination";;
    */update.json) cp "$TASK_FIXTURE/manifest.json" "$destination";;
    */firewall-ui-docker-linux-*.tar.gz) cp "$TASK_FIXTURE/release-images/stable/firewall-ui-docker-linux-$TASK_ARCH.tar.gz" "$destination";;
    *) return 1;;
  esac
}
docker() {
  if [[ "$1" == load ]]; then
    cmp "$3" "$TASK_FIXTURE/release-images/firewall-ui-docker-linux-$TASK_ARCH.tar.gz"
    printf loaded > "$TASK_FIXTURE/loaded"
  fi
}
docker_download_image
'''
        env = dict(self.env, TASK_ROOT=str(ROOT), TASK_FIXTURE=str(self.directory), TASK_ARCH=arch)
        return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)

    def test_unified_image_download_for_both_architectures(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                result = self.download(arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.directory / "loaded").exists())
                self.assertNotIn("docker-update.json", (self.directory / "requests").read_text())

    def test_previous_release_can_still_be_installed(self):
        result = self.download("amd64", legacy=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("docker-update.json", (self.directory / "requests").read_text())

    def test_invalid_image_checksum_is_rejected(self):
        result = self.download("amd64", bad_checksum=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / "loaded").exists())


if __name__ == "__main__":
    unittest.main()
