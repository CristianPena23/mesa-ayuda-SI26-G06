#!/usr/bin/env bash
# Instala el agente Wazuh 4.14.8 en un nodo Ubuntu y lo registra contra sg-robayo-security
# por la tailnet — Grupo SI26-G06
# Uso:  sudo bash instalar-agente-wazuh.sh
set -euo pipefail

MANAGER_IP="100.91.88.2"        # IP Tailscale de sg-robayo-security
VERSION="4.14.8-1"              # misma versión que el manager (el agente nunca debe ser más nuevo)
NOMBRE="$(hostname)"            # el enunciado exige que el agente se llame como el hostname

echo "==> 1. Repositorio oficial de Wazuh (firmado con su llave GPG)"
apt-get install -y gnupg apt-transport-https curl
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update

echo "==> 2. Instalar el agente apuntando al manager por Tailscale"
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$NOMBRE" \
  apt-get install -y "wazuh-agent=$VERSION"

echo "==> 3. Fijar la versión (que unattended-upgrades no lo actualice por encima del manager)"
apt-mark hold wazuh-agent

echo "==> 4. Arrancar el agente"
systemctl daemon-reload
systemctl enable --now wazuh-agent
sleep 10

echo "==> Verificación"
systemctl is-active wazuh-agent
grep -E "<address>|<port>" /var/ossec/etc/ossec.conf | head -2
tail -n 5 /var/ossec/logs/ossec.log
