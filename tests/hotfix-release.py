#!/usr/bin/env python3
"""Exercise the destructive release path against a disposable GitHub fixture."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = '50c78b4db8b8771b8e069085c63dd087c988e14e'
BUILD = 'a' * 40
OLD = {'v1.4.1': 'eb22b457d29a318b6f399ea1798f59374f35d0ac',
       'v1.4.2': '395f27d36efb73415e6b5586ff4ca6209ef5047c',
       'v1.4.3': '6d25354901e9f775af1735da0b1489d7c062f4a8',
       'v1.4.4': '5fa13eb10a663b6a0e08a1f182cca97b0a815e1e',
       'v1.4.0': BASE}
NAMES = ['firewall-ui-linux-amd64', 'firewall-ui-linux-arm64', 'update.json',
         'firewall-ui-docker-linux-amd64.tar.gz', 'firewall-ui-docker-linux-arm64.tar.gz']
FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args=sys.argv[1:]
if pathlib.Path(sys.argv[0]).name == 'git':
 if args[0] == 'log': print('hotfix: 1.4.1')
 elif args[-1] == 'HEAD^': print(os.environ['TASK_PARENT'])
 else: print(os.environ['BUILD_COMMIT'])
 sys.exit()
p=pathlib.Path(os.environ['TASK_STATE']); state=json.loads(p.read_text())
if args[0] == 'api':
 endpoint=next(a for a in args if a.startswith('repos/'))
 if endpoint.endswith('/branches/main'): print(os.environ.get('TASK_MAIN',os.environ['BUILD_COMMIT'])); sys.exit()
 tag=endpoint.rsplit('/',1)[-1]
 if '-X' not in args:
  if tag not in state['tags']:
   if os.environ.get('TASK_MISSING_TAG_NULL') == '1': print('null')
   sys.exit(1)
  print(state['tags'][tag]); sys.exit()
 state['tags'].pop(tag,None)
elif args[:2] == ['release','view']:
 tag=args[2]
 if tag not in state['releases']: sys.exit(1)
 if '--json' in args: print('\n'.join(state['assets'].get(tag,[])))
 sys.exit()
elif args[:2] == ['release','delete']:
 tag=args[2]; state['releases'].remove(tag); state['tags'].pop(tag,None)
elif args[:2] == ['release','create']:
 tag=args[2]; state['releases'].append(tag); state['tags'][tag]=os.environ['BUILD_COMMIT']
 state['assets'][tag]=json.loads(os.environ['TASK_ASSETS'])
elif args[:2] == ['release','upload']:
 state['assets'][args[2]]=json.loads(os.environ['TASK_ASSETS'])
elif args[:2] != ['release','edit']: raise RuntimeError(args)
state['writes'].append(args)
p.write_text(json.dumps(state))
'''


class HotfixReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cwd = Path(self.tmp.name)
        tools = self.cwd / 'bin'; tools.mkdir()
        for tool in ('git', 'gh'):
            path = tools / tool; path.write_text(FAKE); path.chmod(0o755)
        (self.cwd / 'VERSION').write_text('1.4.1\n')
        (self.cwd / 'docs').mkdir()
        (self.cwd / 'docs/CHANGELOG.md').write_text('# Changes\n\n## 1.4.1\n\nHotfix notes.\n')
        (self.cwd / 'dist-stable').mkdir()
        (self.cwd / 'release-images/stable').mkdir(parents=True)
        for name in NAMES:
            folder = 'release-images/stable' if name.endswith('.tar.gz') else 'dist-stable'
            (self.cwd / folder / name).write_bytes(name.encode())
        self.state = self.cwd / 'github.json'
        self.state.write_text(json.dumps({'tags': dict(OLD), 'releases': list(OLD),
                                         'assets': {'v1.4.1': NAMES}, 'writes': []}))
        self.env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}",
                        GITHUB_REPOSITORY='SawaMEN/Firewall-UI', BUILD_COMMIT=BUILD,
                        BUILD_TIME='2026-10-23T00:00:00Z', TASK_PARENT=BASE,
                        TASK_STATE=str(self.state), TASK_ASSETS=json.dumps(NAMES))
        subprocess.run(['python3', str(ROOT / 'scripts/release-manifest.py'),
                        'stable', '1.4.1', 'v1.4.1'], cwd=self.cwd, env=self.env, check=True)

    def run_stage(self, stage, success=True):
        result = subprocess.run(['bash', str(ROOT / 'scripts/hotfix-1.4.1.sh'), stage],
                                cwd=self.cwd, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return json.loads(self.state.read_text())

    def test_publish_then_retire_and_retry(self):
        state = self.run_stage('publish')
        self.assertEqual(state['tags']['v1.4.1'], BUILD)
        self.assertIn('v1.4.4', state['releases'])  # Still available until verification.
        self.assertEqual([a[1] for a in state['writes']], ['delete', 'create'])
        count = len(state['writes'])
        state = self.run_stage('publish')
        self.assertEqual(state['writes'][count][1], 'edit')  # No delete/reupload churn.
        state = self.run_stage('retire')
        self.assertEqual(set(state['releases']), {'v1.4.0', 'v1.4.1'})
        self.assertEqual(state['tags']['v1.4.0'], BASE)
        self.run_stage('retire')  # Idempotent after a partial upstream retry.

    def test_missing_tag_null_does_not_block_publication(self):
        state = json.loads(self.state.read_text())
        state['tags'].pop('v1.4.1')
        state['releases'].remove('v1.4.1')
        self.state.write_text(json.dumps(state))
        self.env['TASK_MISSING_TAG_NULL'] = '1'
        state = self.run_stage('publish')
        self.assertEqual(state['tags']['v1.4.1'], BUILD)
        self.assertEqual(state['writes'][0][1], 'create')

    def test_missing_asset_never_deletes_release(self):
        (self.cwd / 'dist-stable/firewall-ui-linux-arm64').unlink()
        self.assertFalse(self.run_stage('publish', False)['writes'])

    def test_bad_manifest_never_deletes_release(self):
        path = self.cwd / 'dist-stable/update.json'
        manifest = json.loads(path.read_text()); manifest['commit'] = 'unexpected'
        path.write_text(json.dumps(manifest))
        self.assertFalse(self.run_stage('publish', False)['writes'])

    def test_changed_tag_is_preserved(self):
        state = json.loads(self.state.read_text()); state['tags']['v1.4.1'] = 'b' * 40
        self.state.write_text(json.dumps(state))
        self.assertFalse(self.run_stage('publish', False)['writes'])

    def test_all_retirement_leases_checked_before_any_deletion(self):
        state = self.run_stage('publish'); state['writes'] = []
        state['tags']['v1.4.4'] = 'b' * 40; self.state.write_text(json.dumps(state))
        self.assertFalse(self.run_stage('retire', False)['writes'])

    def test_newer_main_is_preserved(self):
        self.env['TASK_MAIN'] = 'b' * 40
        self.assertFalse(self.run_stage('publish', False)['writes'])

    def test_wrong_parent_is_preserved(self):
        self.env['TASK_PARENT'] = 'b' * 40
        self.assertFalse(self.run_stage('publish', False)['writes'])


if __name__ == '__main__':
    unittest.main()
