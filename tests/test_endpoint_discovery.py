import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

CONTROL = Path(__file__).resolve().parents[1] / 'control'
sys.path.insert(0, str(CONTROL))
import endpoint_discovery as discovery


class EndpointDiscoveryTests(unittest.TestCase):
    def setUp(self):
        outputs = CONTROL.parent / 'outputs'
        outputs.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=outputs)
        self.root = Path(self.scratch.name)
        def mapped(*parts):
            return self.root / str(Path(*parts)).replace('\\', '/').lstrip('/')
        self.mapping = patch.object(discovery, 'Path', side_effect=mapped)
        self.mapping.start()

    def tearDown(self):
        self.mapping.stop()
        self.scratch.cleanup()

    def write(self, name, text):
        path = self.root / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_adguard_enabled_doh_dot_and_udp_without_credentials(self):
        self.write('/opt/AdGuardHome/AdGuardHome.yaml', '''
users: [{name: owner, password: SECRET}]
dns:
  bind_hosts: [0.0.0.0]
  port: 5353
  upstream_dns: ["https://resolver.example/dns-query"]
tls:
  enabled: true
  server_name: dns.example.com
  port_https: 8443
  port_dns_over_tls: 8853
''')
        result = discovery.discover()
        routes = {item['discovery_id']: item for item in result['dns_routes']}
        self.assertEqual(routes['auto:adguard:0']['port'], 5353)
        self.assertEqual(routes['auto:adguard-doh']['endpoint'], 'https://dns.example.com:8443/dns-query')
        self.assertEqual(routes['auto:adguard-dot']['port'], 8853)
        self.assertEqual(routes['auto:adguard-dot']['server_name'], 'dns.example.com')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_disabled_adguard_tls_does_not_create_doh_dot(self):
        self.write('/opt/AdGuardHome/AdGuardHome.yaml', 'dns: {port: 53}\ntls: {enabled: false, server_name: dns.example.com, port_https: 443, port_dns_over_tls: 853}\n')
        routes = discovery.discover()['dns_routes']
        self.assertEqual([r['transport'] for r in routes], ['udp'])

    def test_panel_and_xray_tls_exclude_secrets_and_reality_is_distinct(self):
        path = self.write('/etc/x-ui/x-ui.db', '')
        with sqlite3.connect(path) as connection:
            connection.execute('CREATE TABLE settings (key text, value text)')
            connection.executemany('INSERT INTO settings VALUES (?,?)', [('webPort', '2053'), ('webCertFile', '/cert.pem'), ('webKeyFile', '/private.pem'), ('webDomain', 'panel.example.com'), ('password', 'SECRET')])
        connection.close()
        self.write('/usr/local/x-ui/bin/config.json', json.dumps({'inbounds': [
            {'port':443,'protocol':'vless','settings':{'clients':[{'id':'SECRET'}]},'streamSettings':{'security':'tls','tlsSettings':{'certificates':[{'certificateFile':'/cert.pem','keyFile':'/private.pem'}]}}},
            {'port':8443,'streamSettings':{'security':'reality','realitySettings':{'privateKey':'SECRET'}}}]}))
        with patch.object(discovery, 'certificate', return_value={'domains':['panel.example.com'],'expires':'Jan 1 00:00:00 2030 GMT'}), patch.object(discovery.subprocess, 'run', return_value=types.SimpleNamespace(stdout='0')):
            result = discovery.discover()
        self.assertEqual([item['port'] for item in result['tls']], [2053,443])
        self.assertEqual(result['components'][-1]['security'], 'reality')
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('/private.pem', json.dumps(result))

    def test_authenticated_doh_urls_are_not_exported(self):
        result = {'domains':[], 'dns_routes':[]}
        discovery.add_dns(result, 'auto:dns:0', 'https://user:SECRET@resolver.example/dns-query')
        self.assertEqual(result['dns_routes'], [])

    def test_nginx_nested_locations_do_not_mix_server_blocks(self):
        text = 'server { listen 443 ssl; server_name a.example; location / { proxy_pass http://localhost; } } server { listen 8443 ssl; server_name b.example; }'
        blocks = list(discovery.server_blocks(text))
        self.assertEqual(len(blocks),2)
        self.assertNotIn('b.example',blocks[0])


if __name__ == '__main__': unittest.main()
