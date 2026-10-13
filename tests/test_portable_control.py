"""Portable setup, probe evidence, backup round-trip and owner confirmation checks."""
import importlib.util
import json
import io
import os
import struct
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

CONTROL = Path(__file__).resolve().parents[1] / 'control'
sys.path.insert(0, str(CONTROL))
if os.name == 'nt':
    sys.modules.setdefault('fcntl', types.SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=2))
import fleet
import fleetctl
import node_agent
import advanced
import generic_control


class PortableControlTests(unittest.TestCase):
    def setUp(self):
        scratch = CONTROL.parent / 'outputs'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.base = Path(self.temp.name)
        self.root = self.base / 'etc'
        self.state = self.base / 'state'
        self.root.mkdir()
        self.state.mkdir()
        self.patches = [patch.object(fleet, 'ROOT', self.root), patch.object(fleet, 'CONFIG', self.root / 'fleet.json'),
                        patch.object(fleet, 'STATE', self.state), patch.object(fleet, 'BASE', CONTROL),
                        patch.object(advanced, 'STATE', self.state)]
        for item in self.patches: item.start()
        self.profile = fleetctl.default_profile(['nginx'])
        self.profile['allowed_restarts'] = ['nginx']
        fleet.save({'version': 1, 'nodes': {'main': {'name': 'MY-CONTROLLER', 'kind': 'server',
            'address': 'my.example', 'user': 'local', 'transport': 'local', 'profile': self.profile}}})

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.assertTrue(self.base.resolve().is_relative_to(CONTROL.parent.resolve()))
        self.temp.cleanup()

    def test_fresh_registration_uses_own_name_without_legacy_inventory(self):
        fleet.CONFIG.unlink()
        with patch.object(fleetctl.subprocess, 'run', return_value=types.SimpleNamespace(stdout='not-found\n')):
            fleetctl.register_main('OTHER-PERSON-SERVER')
        self.assertEqual(list(fleet.nodes()), ['main'])
        self.assertEqual(fleet.nodes()['main']['name'], 'OTHER-PERSON-SERVER')
        self.assertTrue((self.root / 'main-profile.json').is_file())
        self.assertFalse((self.root / 'control-nodes.json').exists())

    def test_rescan_adds_panel_without_granting_restart_or_losing_routes(self):
        data = fleet.load()
        data['nodes']['main']['profile']['urls'] = [{'url': 'https://example.com', 'label': 'health', 'codes': [200]}]
        fleet.save(data)
        with patch.object(fleet, 'rpc', side_effect=[{'services': ['nginx', 'x-ui']}, {'configured': True}]) as rpc:
            result = fleet.rescan('main')
        self.assertEqual(result['added'], ['x-ui'])
        updated = fleet.nodes()['main']['profile']
        self.assertEqual(updated['allowed_restarts'], ['nginx'])
        self.assertEqual(updated['urls'], data['nodes']['main']['profile']['urls'])
        self.assertEqual(updated['services'], ['nginx', 'x-ui'])
        with patch.object(fleet, 'rpc', return_value={'services': ['nginx', 'x-ui']}) as rpc:
            self.assertEqual(fleet.rescan('main')['added'], [])
            self.assertEqual(rpc.call_count, 1)

    def test_failed_rescan_does_not_commit_profile(self):
        original = fleet.load()
        with patch.object(fleet, 'rpc', side_effect=[{'services': ['x-ui']}, RuntimeError('failed')]):
            with self.assertRaises(RuntimeError): fleet.rescan('main')
        self.assertEqual(fleet.load(), original)

        with patch.object(fleet, 'rpc', return_value={'services': ['arbitrary-service']}):
            with self.assertRaises(ValueError): fleet.rescan('main')
        self.assertEqual(fleet.load(), original)

    def test_rescan_refreshes_auto_tls_preserves_manual_routes_and_permissions(self):
        data = fleet.load()
        profile = data['nodes']['main']['profile']
        manual = {'label':'manual','host':'manual.example.com','port':443}
        profile['tls'] = [manual, {'discovery_id':'auto:panel:tls','label':'Panel','host':'127.0.0.1','port':2053,'server_name':'panel.example.com'}]
        fleet.save(data)
        discovery = {'services':['nginx'], 'tls':[{'discovery_id':'auto:panel:tls','label':'Panel','host':'127.0.0.1','port':8443,'server_name':'panel.example.com'}],
                     'domains':['panel.example.com'], 'dns_routes':[{'discovery_id':'auto:adguard-doh','id':'d_adguard','label':'AdGuard DoH','transport':'doh','endpoint':'https://dns.example.com/dns-query','count':1}]}
        with patch.object(fleet, 'rpc', side_effect=[discovery, {'configured':True}]): fleet.rescan('main')
        updated = fleet.nodes()['main']['profile']
        self.assertEqual(updated['tls'][0], manual)
        self.assertEqual(updated['tls'][1]['port'],8443)
        self.assertEqual(updated['allowed_restarts'], profile['allowed_restarts'])
        self.assertEqual(updated['dns_routes'][0]['transport'],'doh')
        with patch.object(fleet, 'rpc', return_value=discovery) as rpc:
            self.assertEqual(fleet.rescan('main')['added_probes'],0)
            self.assertEqual(rpc.call_count,1)

    def test_discovery_includes_loaded_inactive_panel(self):
        def probe(args, timeout):
            return types.SimpleNamespace(returncode=0, stdout='loaded\n' if args[-1] == 'x-ui' else 'not-found\n')
        with patch.object(node_agent, 'run', side_effect=probe):
            self.assertEqual(node_agent.discover_services(), ['x-ui'])
        self.assertFalse(fleet.allowed_action({'transport': 'ssh-shell'}, 'discover'))

    def test_disabled_node_does_not_appear_in_runtime_inventory(self):
        data = fleet.load()
        data['nodes']['new_host'] = {**data['nodes']['main'], 'enabled': False}
        fleet.save(data)
        self.assertEqual(list(fleet.nodes()), ['main'])
        data['nodes']['new_host']['enabled'] = True
        fleet.save(data)
        self.assertEqual(set(fleet.nodes()), {'main', 'new_host'})

    def test_no_arbitrary_or_removed_restart_action(self):
        node = fleet.nodes()['main']
        self.assertTrue(fleet.allowed_action(node, 'restart nginx'))
        self.assertFalse(fleet.allowed_action(node, 'restart ssh'))
        self.assertFalse(fleet.allowed_action(node, 'sh -c reboot'))
        node['profile']['allowed_restarts'] = []
        self.assertFalse(fleet.allowed_action(node, 'restart nginx'))

    def test_unsafe_profile_and_unmonitored_restart_are_rejected(self):
        for profile in ({'services': ['-x']}, {'services': ['nginx'], 'allowed_restarts': ['ssh']},
                        {'querylog_path': '/etc/passwd'}, {'dns_routes': [{'id': 'a', 'label': 'route', 'transport': 'doh', 'endpoint': 'http://example/dns', 'count': 16}]}):
            with self.assertRaises(ValueError): node_agent.validate_profile(profile)

    def dns_fixture(self, arrived):
        token = '1234567890abcdef'
        names = ['rvkomi-' + token + '-' + str(i) + '.example.com' for i in range(2)]
        data = fleet.load()
        data['nodes']['main']['profile']['dns_routes'] = [{'id': 'a', 'label': 'DoH-origin',
            'transport': 'doh', 'endpoint': 'https://example/dns', 'querylog_node': 'self', 'count': 2, 'log_wait_seconds': 0}]
        fleet.save(data)
        result = {'last_check': time.time(), 'failures': [], 'services': {}, 'report': {'groups': {}},
                  'dns_results': {'a': {'responses': 2, 'expected': 2, 'probe_token': token, 'probe_names': names}}}
        def rpc(identifier, action):
            if action == 'check': return result
            self.assertEqual(identifier, 'main')
            self.assertEqual(action, 'querylog ' + token)
            return {'names': names[:arrived] + ['unrelated.example.com']}
        return rpc

    def test_dns_delivery_requires_each_unique_name_in_adguard_log(self):
        with patch.object(fleet, 'rpc', side_effect=self.dns_fixture(1)):
            result = fleet.check('main')
        self.assertFalse(result['dns_results']['a']['ok'])
        self.assertEqual(result['dns_results']['a']['arrived'], 1)
        self.assertIn('DoH-origin', result['failures'])
        self.assertIn('дошли до AdGuard по журналу 1/2', result['report']['notes'][0])

    def test_complete_dns_delivery_succeeds(self):
        with patch.object(fleet, 'rpc', side_effect=self.dns_fixture(2)):
            self.assertTrue(fleet.check('main')['dns_results']['a']['ok'])

    def test_adguard_parser_excludes_other_probes_and_duplicates(self):
        path = self.root / 'querylog.json'
        name = 'rvkomi-1234567890abcdef-0.example.com'
        path.write_text(json.dumps({'QH': name + '.'}) + '\n' + json.dumps({'QH': name}) + '\n' + json.dumps({'QH': 'unrelated.example.com'}))
        self.assertEqual(node_agent.querylog({'querylog_path': str(path)}, '1234567890abcdef')['names'], [name])

    def test_dns_checks_transaction_id_and_accepts_nxdomain(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *args): return self.wire
        response = Response()
        opener = Mock()
        opener.open.return_value = response
        _, request = node_agent.packet('example.com')
        with patch.object(node_agent, 'packet', return_value=(123, request)), patch.object(node_agent.urllib.request, 'build_opener', return_value=opener):
            response.wire = struct.pack('!HHHHHH', 123, 0x8003, 1, 0, 0, 0) + request[12:]
            self.assertTrue(node_agent.dns_probe({'transport': 'doh', 'endpoint': 'https://example/dns'}, 'example.com'))
            response.wire = struct.pack('!HHHHHH', 124, 0x8000, 1, 0, 0, 0) + request[12:]
            self.assertFalse(node_agent.dns_probe({'transport': 'doh', 'endpoint': 'https://example/dns'}, 'example.com'))

    def test_node_agent_rejects_unapproved_restart_before_execution(self):
        profile = self.root / 'profile.json'
        profile.write_text(json.dumps(self.profile))
        with patch.dict(os.environ, {}, clear=True), patch.object(sys, 'argv', ['node_agent.py', '--profile', str(profile), 'restart', 'ssh']), patch.object(node_agent, 'run') as execute:
            with self.assertRaises(ValueError): node_agent.main()
            execute.assert_not_called()

    def provision_fixture(self, failure=False):
        files = {'/root/.ssh/authorized_keys': b'ssh-ed25519 OLDKEY owner\n'}
        class File(io.BytesIO):
            def __init__(self, path, mode):
                self.path, self.mode = path, mode
                if mode == 'r' and path not in files: raise FileNotFoundError(path)
                super().__init__(files.get(path, b'') if mode == 'r' else b'')
            def close(self):
                if self.mode == 'w': files[self.path] = self.getvalue()
                super().close()
        class SFTP:
            def open(self, path, mode): return File(path, mode)
            def put(self, local, remote): files[remote] = Path(local).read_bytes()
            def chmod(self, *args): pass
            def posix_rename(self, source, target): files[target] = files.pop(source)
            def close(self): pass
        class Key:
            def asbytes(self): return b'trusted server key'
            def get_name(self): return 'ssh-ed25519'
            def get_base64(self): return 'HOSTKEY'
        class Transport:
            def __init__(self, *args): pass
            def start_client(self, **kwargs): pass
            def get_remote_server_key(self): return Key()
            def auth_password(self, *args): pass
            def is_authenticated(self): return True
            def close(self): pass
        fake = types.SimpleNamespace(Transport=Transport, SFTPClient=types.SimpleNamespace(from_transport=lambda transport: SFTP()))
        def keygen(argv):
            path = Path(argv[-1]); path.write_text('PRIVATE'); path.with_suffix('.pub').write_text('ssh-ed25519 NEWKEY controller')
        def remote(transport, command):
            if command == 'printf "%s" "$HOME"': return '/root'
            if command == 'command -v python3 || true': return '/usr/bin/python3'
            if command.startswith('for s in'): return 'nginx'
            return ''
        result = RuntimeError('unreachable') if failure else {'failures': []}
        stack = [patch.dict(sys.modules, {'paramiko': fake}), patch.object(fleetctl, 'public_ip', return_value='198.51.100.10'),
                 patch.object(fleetctl, 'remote_exec', side_effect=remote), patch.object(fleetctl, 'command', side_effect=keygen),
                 patch.object(fleetctl.getpass, 'getpass', return_value='password not stored'),
                 patch('builtins.input', side_effect=['REMOTE', '192.0.2.1', 'root', '22', 'yes', 'n']),
                 patch.object(fleet, 'check', side_effect=result if failure else None, return_value=result)]
        return files, stack

    def test_provisioned_node_has_source_restricted_key_and_no_saved_password(self):
        files, stack = self.provision_fixture()
        try:
            for item in stack: item.start()
            fleetctl.add_node('server')
        finally:
            for item in reversed(stack): item.stop()
        nodes = fleet.nodes()
        self.assertEqual(len(nodes), 2)
        remote = next(node for identifier, node in nodes.items() if identifier != 'main')
        self.assertEqual(remote['name'], 'REMOTE')
        self.assertIn('from="198.51.100.10",restrict,command=', files['/root/.ssh/authorized_keys'].decode())
        self.assertNotIn('password not stored', fleet.CONFIG.read_text())
        self.assertEqual(remote['transport'], 'ssh-agent')

    def test_failed_key_connection_restores_authorized_keys_and_inventory(self):
        files, stack = self.provision_fixture(failure=True)
        try:
            for item in stack: item.start()
            with self.assertRaises(RuntimeError): fleetctl.add_node('server')
        finally:
            for item in reversed(stack): item.stop()
        self.assertEqual(list(fleet.nodes()), ['main'])
        self.assertEqual(files['/root/.ssh/authorized_keys'], b'ssh-ed25519 OLDKEY owner\n')

    def test_ssh_status_failure_does_not_get_hidden_by_cached_success(self):
        folder = self.state / 'fleet-results'
        folder.mkdir()
        (folder / 'main.json').write_text(json.dumps({'last_check': time.time(), 'failures': []}))
        with patch.object(fleet, 'rpc', side_effect=RuntimeError('SSH down')):
            with self.assertRaises(RuntimeError): fleet.status('main')

    def test_owner_message_and_single_use_confirmation(self):
        spec = importlib.util.spec_from_file_location('test_control', CONTROL / 'telegram-control.py')
        tc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tc)
        (self.root / 'telegram.json').write_text(json.dumps({'bot_token': 'fake', 'chat_id': 12345}))
        captured, messages = [], []
        class API:
            def __init__(self, *args): pass
            def call(self, method, data=None, **kwargs):
                if method == 'getMe': return {'username': 'test_bot'}
                if method == 'getWebhookInfo': return {}
                if method == 'sendMessage': messages.append(data); return {'message_id': len(messages)}
                return True
        original_init = tc.Bot.__init__
        def init(bot, *args, **kwargs): original_init(bot, *args, **kwargs); captured.append(bot)
        with patch.object(tc, 'API', API), patch.object(tc.Bot, '__init__', init), patch.object(fleet, 'check', return_value={'failures': [], 'services': {}, 'last_check': time.time()}), patch.object(advanced, 'journal'):
            generic_control.run(tc, 'verify')
        bot = captured[0]
        bot.reboot_executor.shutdown()
        bot.reboot_executor = Mock()
        bot.repair('main', 0)
        token = next(iter(bot.state['repairs']))
        proposal = bot.state['repairs'][token]
        query = {'id': 'q', 'from': {'id': 99999}, 'data': 'fleetconfirm:' + token,
                 'message': {'message_id': proposal['message_id'], 'chat': {'id': 12345, 'type': 'private'}}}
        bot.callback(query)
        bot.reboot_executor.submit.assert_not_called()
        query['from']['id'] = 12345
        query['message']['message_id'] += 1
        bot.callback(query)
        bot.reboot_executor.submit.assert_not_called()
        query['message']['message_id'] -= 1
        bot.callback(query)
        bot.reboot_executor.submit.assert_called_once()
        bot.callback(query)
        bot.reboot_executor.submit.assert_called_once()
        bot.executor.shutdown()

    def test_portable_encrypted_backup_round_trip_and_wrong_password(self):
        try: import runtime_bundle as bundle
        except ImportError: self.skipTest('cryptography is required for this integration check')
        key = self.root / 'my_key'
        known = self.root / 'my_known_hosts'
        key.write_text('test private key bytes')
        known.write_text('example ssh-ed25519 fake')
        data = fleet.load()
        data['nodes']['custom_node'] = {'name': 'CUSTOM', 'transport': 'ssh-agent', 'kind': 'server',
            'address': 'example', 'user': 'root', 'key': str(key), 'known_hosts': str(known), 'profile': self.profile}
        fleet.save(data)
        (self.root / 'telegram.json').write_text(json.dumps({'bot_token': 'fake', 'chat_id': 12345}))
        archive = self.base / 'runtime.enc'
        target = self.base / 'restored'
        target_state = self.base / 'restored-state'
        with patch.object(bundle, 'ROOT', self.root), patch.object(bundle, 'STATE', self.state), patch.object(bundle, 'TIMER_DROPIN', self.base / 'override.conf'), patch.object(os, 'geteuid', return_value=0, create=True), patch.object(bundle.getpass, 'getpass', return_value='long test password'):
            bundle.export_bundle(archive)
        self.assertFalse(archive.read_bytes().find(b'test private key bytes') >= 0)
        with patch.object(bundle, 'ROOT', target), patch.object(bundle, 'STATE', target_state), patch.object(bundle, 'TIMER_DROPIN', self.base / 'timer' / 'override.conf'), patch.object(os, 'geteuid', return_value=0, create=True):
            with patch.object(bundle.getpass, 'getpass', return_value='wrong password'):
                with self.assertRaises(SystemExit): bundle.import_bundle(archive)
            self.assertFalse(target.exists())
            with patch.object(bundle.getpass, 'getpass', return_value='long test password'): bundle.import_bundle(archive)
        restored = json.loads((target / 'fleet.json').read_text())
        self.assertEqual(set(restored['nodes']), {'main', 'custom_node'})
        self.assertEqual((target / 'keys' / 'custom_node_ed25519').read_text(), 'test private key bytes')
        self.assertFalse(bundle.safe_member_name('etc/rvkomi-watchdog/keys/../../etc/passwd'))


if __name__ == '__main__': unittest.main()
