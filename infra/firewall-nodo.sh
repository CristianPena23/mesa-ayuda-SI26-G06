#!/usr/bin/env bash
# Firewall de host (ufw) — Grupo SI26-G06
# Uso:  sudo bash firewall-nodo.sh <rol>      rol = db | backend | frontend | security
# deny incoming por defecto; solo se abre lo necesario y ÚNICAMENTE sobre tailscale0.
set -euo pipefail

ROL="${1:?Indica el rol: db | backend | frontend | security}"

case "$ROL" in
  db)       PUERTOS="22 33066" ;;                 # SSH + MySQL del grupo
  backend)  PUERTOS="22 8106" ;;                  # SSH + API del grupo
  frontend) PUERTOS="22" ;;                       # Solo SSH: Cloudflare Tunnel es saliente
  security) PUERTOS="22 443 9000 1514 1515" ;;    # SSH + Wazuh dashboard + SonarQube + agentes
  *) echo "Rol inválido"; exit 1 ;;
esac

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

for P in $PUERTOS; do
  ufw allow in on tailscale0 to any port "$P" proto tcp comment "SI26-G06 $ROL"
done

ufw --force enable
ufw status verbose
