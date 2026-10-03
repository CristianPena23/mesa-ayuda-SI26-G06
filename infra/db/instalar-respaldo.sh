#!/usr/bin/env bash
# Respaldo diario cifrado de mesa_ayuda — Grupo SI26-G06
# Uso (en sg-robayo-db):  sudo bash instalar-respaldo.sh "age1...LLAVE_PUBLICA..."
#
# Diseño:
#  - mysqldump se ejecuta como root por SOCKET local (auth_socket): no se guarda ninguna contraseña.
#  - El volcado se cifra con age usando SOLO la llave PÚBLICA. La llave privada vive fuera del
#    servidor (en el PC de un integrante): quien comprometa sg-db no puede leer los respaldos.
#  - Un systemd timer lo ejecuta todos los días; Persistent=true lo corre al arrancar si la VM
#    estaba apagada a la hora programada.
#  - Cada ejecución deja un mensaje en syslog (journal), que Wazuh puede vigilar.
set -euo pipefail

RECIPIENT="${1:?Pasa la llave PÚBLICA de age (empieza por age1...)}"
[[ "$RECIPIENT" == age1* ]] || { echo "ERROR: eso no parece una llave pública de age"; exit 1; }

echo "==> 1. Instalar age (cifrado moderno de archivos)"
apt-get install -y age

echo "==> 2. Guardar la llave PÚBLICA del destinatario"
install -d -m 700 /etc/mysql/backup
echo "$RECIPIENT" > /etc/mysql/backup/age-recipient.txt
chmod 600 /etc/mysql/backup/age-recipient.txt

echo "==> 3. Script de respaldo"
cat > /usr/local/sbin/backup-mesa-ayuda.sh <<'EOF'
#!/usr/bin/env bash
# Volcado diario de mesa_ayuda comprimido y cifrado con age — SI26-G06
set -euo pipefail
umask 077
DEST=/var/backups/mysql
RECIP=/etc/mysql/backup/age-recipient.txt
mkdir -p "$DEST"
ARCHIVO="$DEST/mesa_ayuda_$(date +%F_%H%M%S).sql.gz.age"
# --single-transaction: copia consistente sin bloquear tablas InnoDB
mysqldump --single-transaction --routines --triggers mesa_ayuda \
  | gzip \
  | age -R "$RECIP" -o "$ARCHIVO"
# Retención: se borran respaldos de más de 7 días
find "$DEST" -name 'mesa_ayuda_*.sql.gz.age' -mtime +7 -delete
logger -t backup-mesa-ayuda "Respaldo cifrado creado: $ARCHIVO ($(stat -c %s "$ARCHIVO") bytes)"
EOF
chmod 700 /usr/local/sbin/backup-mesa-ayuda.sh

echo "==> 4. Servicio y timer de systemd"
cat > /etc/systemd/system/backup-mesa-ayuda.service <<'EOF'
[Unit]
Description=Respaldo cifrado de la base mesa_ayuda (SI26-G06)
After=mysql.service
Requires=mysql.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/backup-mesa-ayuda.sh
EOF

cat > /etc/systemd/system/backup-mesa-ayuda.timer <<'EOF'
[Unit]
Description=Respaldo diario de mesa_ayuda a las 02:30 (SI26-G06)

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now backup-mesa-ayuda.timer

echo "==> 5. Primer respaldo de prueba"
systemctl start backup-mesa-ayuda.service
ls -l /var/backups/mysql/
systemctl list-timers backup-mesa-ayuda.timer --no-pager
journalctl -t backup-mesa-ayuda --no-pager | tail -3
