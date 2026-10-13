import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest import mock

spec = importlib.util.spec_from_file_location('configure_mtu', Path(__file__).resolve().parents[1] / 'configure-mtu.py')
mtu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mtu)


class InterfacesMTUTest(unittest.TestCase):
    def test_apply_backs_up_config_and_persists_without_network_restart(self):
        outputs = Path(__file__).resolve().parents[1] / 'outputs'
        outputs.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=outputs) as directory:
            root = Path(directory)
            for relative in ['sys/class/net/ens3', 'etc/network', 'etc/systemd/system']:
                (root / relative).mkdir(parents=True)
            config = root / 'etc/network/interfaces'
            original = 'iface ens3 inet dhcp\n    mtu 1500\n'
            config.write_text(original)
            def mapped_path(*parts):
                return root / str(Path(*parts)).replace('\\', '/').lstrip('/')
            with mock.patch.object(mtu, 'Path', side_effect=mapped_path), \
                    mock.patch.object(mtu.os, 'geteuid', return_value=0, create=True), \
                    mock.patch.object(mtu.shutil, 'which', return_value='/usr/sbin/ip'), \
                    mock.patch.object(mtu.subprocess, 'run') as run:
                mtu.apply('ens3', 1452)
            backups = list(config.parent.glob('interfaces.rvkomi-backup-*'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), original)
            self.assertIn('mtu 1452', config.read_text())
            unit = (root / 'etc/systemd/system/rvkomi-network-mtu.service').read_text()
            self.assertIn('After=network-online.target', unit)
            self.assertIn('ExecStart=/usr/sbin/ip link set dev ens3 mtu 1452', unit)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn(['/usr/sbin/ip', 'link', 'set', 'dev', 'ens3', 'mtu', '1452'], commands)
            self.assertNotIn(['systemctl', 'restart', 'networking'], commands)

    def test_changes_only_selected_interface_and_is_idempotent(self):
        original = ('auto lo\niface lo inet loopback\n\nauto ens3\niface ens3 inet static\n'
                    '    address 192.0.2.1/24\n    mtu 1500\n    gateway 192.0.2.254\n'
                    'auto ens4\niface ens4 inet dhcp\n    mtu 1500\n')
        updated, found = mtu.update_interfaces(original, 'ens3', 1452)
        self.assertTrue(found)
        self.assertIn('address 192.0.2.1/24', updated)
        self.assertIn('gateway 192.0.2.254', updated)
        self.assertIn('iface ens4 inet dhcp\n    mtu 1500', updated)
        self.assertEqual(updated.count('mtu 1452'), 1)
        self.assertEqual(mtu.update_interfaces(updated, 'ens3', 1452)[0], updated)

    def test_absent_interface_leaves_config_unchanged(self):
        original = 'source /etc/network/interfaces.d/*\niface lo inet loopback\n'
        self.assertEqual(mtu.update_interfaces(original, 'ens3', 1452), (original, False))

    def test_both_address_families_and_stanza_boundaries(self):
        original = 'iface ens3 inet dhcp\nsource interfaces.d/*\niface ens3 inet6 auto\n'
        updated, found = mtu.update_interfaces(original, 'ens3', 1452)
        self.assertTrue(found)
        self.assertEqual(updated.count('mtu 1452'), 2)
        self.assertIn('mtu 1452\nsource interfaces.d/*', updated)


if __name__ == '__main__':
    unittest.main()
