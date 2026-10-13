#!/usr/bin/env bash
# Sourced by both installers before downloads.
echo "Если путь до GitHub ограничен MTU 1452 при MTU интерфейса 1500, возможны SSL connection timeout."
read -r -p "Настроить MTU 1452 сейчас и после перезагрузки? [y/N]: " SETUP_MTU
case "$SETUP_MTU" in
    y|Y)
        read -r -p "Сетевой интерфейс [ens3]: " MTU_INTERFACE
        python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/configure-mtu.py" --interface "${MTU_INTERFACE:-ens3}" --mtu 1452
        ;;
esac
