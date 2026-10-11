#!/usr/bin/python3
"""Read-only preflight for the configured control-bot SSH fleet."""
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path('/etc/rvkomi-watchdog')
EXPECTED = {
    'control-nodes.json': {'spb', 'nl'},
    'extra-nodes.json': {'dns', 'www', 'space', 'latvia', 'fin', 'telegramm'},
}


def main():
    if os.geteuid() != 0:
        raise SystemExit('Запустите от root: sudo rvkomi-control-verify')
    import fleet
    if fleet.enabled():
        failed = []
        for identifier, node in fleet.nodes().items():
            try:
                fleet.rpc(identifier, 'status')
                print(node['name'] + ': ' + ('локальные проверки доступны' if node['transport'] == 'local' else 'SSH/RPC доступен'))
            except Exception:
                failed.append(node['name'])
                print(node['name'] + ': подключение недоступно')
        if failed: raise SystemExit('Проверьте подключения: ' + ', '.join(failed))
        if not fleet.nodes(): raise SystemExit('Нет настроенных узлов')
        return
    if not (ROOT / 'telegram.json').is_file():
        raise SystemExit('Нет telegram.json. Настройте контрольного Telegram-бота.')
    for name, required in EXPECTED.items():
        path = ROOT / name
        if not path.is_file():
            raise SystemExit(f'Нет {name}. Импортируйте runtime-копию старого управляющего сервера.')
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            raise SystemExit(f'{name} не читается как JSON.') from None
        if set(data) != required:
            raise SystemExit(f'{name}: ожидаются узлы {", ".join(sorted(required))}.')
        for host, cfg in data.items():
            for field in ('key', 'known_hosts'):
                file = Path(cfg.get(field, ''))
                if not file.is_absolute() or not file.is_file():
                    raise SystemExit(f'{host}: отсутствует файл SSH-подключения ({field}).')
                if field == 'key' and file.stat().st_mode & 0o077:
                    raise SystemExit(f'{host}: закрытый SSH-ключ должен иметь права 0600.')
    sys.path.insert(0, '/usr/local/lib/rvkomi-watchdog')
    source = Path('/usr/local/lib/rvkomi-watchdog/telegram-control.py')
    spec = importlib.util.spec_from_file_location('rvkomi_telegram_control', source)
    if spec is None or spec.loader is None:
        raise SystemExit('Не найден исходный код контрольного бота.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    failed = []
    for host in module.HOSTS:
        try:
            result = module.Nodes().call(host, 'status')
            if not isinstance(result, dict):
                raise RuntimeError('invalid response')
            print(f'{host.upper()}: SSH/RPC доступен')
        except Exception as exc:
            failed.append(host)
            print(f'{host.upper()}: SSH/RPC недоступен ({type(exc).__name__})')
    if failed:
        raise SystemExit('Проверка не пройдена. Не запускайте мониторинг, пока не восстановите SSH-доступ к: ' + ', '.join(failed))
    print('Все восемь узлов ответили по SSH. Выполнялась только команда status; службы не перезапускались.')


if __name__ == '__main__':
    main()
