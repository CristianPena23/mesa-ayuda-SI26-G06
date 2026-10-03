#!/usr/bin/env bash
# Bastionado base de un nodo — Grupo SI26-G06
# Uso:  sudo bash bootstrap-nodo.sh <rol> <archivo_llaves.pub> <archivo_authkey>
#       rol = db | backend | frontend | security
# Ejemplo: sudo bash bootstrap-nodo.sh frontend /home/ubuntu/llaves.pub /tmp/tskey
# Hace: hostname, actualizaciones + unattended-upgrades, usuario admin con SSH solo por llave,
#       /opt/examen/grupo.txt y unión a la tailnet con una auth key de un solo uso.
# Las llaves y la auth key se leen de ARCHIVOS (no se pegan en la terminal) y el de la key se destruye al final.
set -euo pipefail

ROL="${1:?Indica el rol: db | backend | frontend | security}"
LLAVES="${2:?Indica el archivo con las llaves públicas (.pub)}"
TSKEY_FILE="${3:?Indica el archivo con la auth key de Tailscale}"
APELLIDO="robayo"
GRUPO="SI26-G06"
ADMIN="sgadmin"
HOST="sg-${APELLIDO}-${ROL}"

# Validaciones previas: falla antes de tocar nada si los archivos no sirven
grep -qE '^ssh-(ed25519|rsa) ' "$LLAVES" || { echo "ERROR: $LLAVES no contiene una llave pública válida"; exit 1; }
grep -q '^tskey-auth-' "$TSKEY_FILE"    || { echo "ERROR: $TSKEY_FILE no contiene una auth key (tskey-auth-...)"; exit 1; }

echo "==> 1. Hostname: $HOST"
hostnamectl set-hostname "$HOST"
sed -i '/^127\.0\.1\.1/d' /etc/hosts
echo "127.0.1.1 $HOST" >> /etc/hosts

echo "==> 2. Actualización del sistema y parches automáticos"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y unattended-upgrades ufw curl netcat-openbsd
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades

echo "==> 3. Usuario administrador '$ADMIN' (distinto de root)"
if ! id "$ADMIN" &>/dev/null; then
  # La contraseña solo sirve para sudo y la consola de emergencia; SSH NO la acepta.
  adduser --gecos "" "$ADMIN"
  usermod -aG sudo "$ADMIN"
fi
install -d -m 700 -o "$ADMIN" -g "$ADMIN" "/home/$ADMIN/.ssh"
# Solo se copian las líneas que son llaves públicas (descarta basura)
grep -E '^ssh-(ed25519|rsa) ' "$LLAVES" > "/home/$ADMIN/.ssh/authorized_keys"
chmod 600 "/home/$ADMIN/.ssh/authorized_keys"
chown "$ADMIN:$ADMIN" "/home/$ADMIN/.ssh/authorized_keys"

echo "==> 4. SSH solo por llave"
# Prefijo 00- para que cargue ANTES que 50-cloud-init.conf (en sshd gana el primer valor leído)
cat > /etc/ssh/sshd_config.d/00-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
EOF
sshd -t
systemctl reload ssh

echo "==> 5. Archivo de grupo"
mkdir -p /opt/examen
echo "$GRUPO" > /opt/examen/grupo.txt
chmod 644 /opt/examen/grupo.txt

echo "==> 6. Tailscale"
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --auth-key="$(tr -d '[:space:]' < "$TSKEY_FILE")" --hostname="$HOST"
# Sobrescribe y borra el archivo de la key para que no quede en disco
shred -u "$TSKEY_FILE"

echo "==> Listo. Verificación:"
hostnamectl --static
cat /opt/examen/grupo.txt
systemctl is-enabled unattended-upgrades
tailscale ip -4
sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication)'
echo "NO actives el firewall todavía: primero comprueba 'ssh $ADMIN@$HOST' desde tu PC por Tailscale."
