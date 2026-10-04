# Ataque de fuerza bruta SSH de prueba - D3, Grupo SI26-G06
# Uso (PowerShell, desde el PC de un integrante):
#   .\ataque_d3.ps1 -Nodo "sg-robayo-db"
# Intenta entrar por SSH con usuarios inexistentes (atacante1..N). Cada intento genera
# un evento "Invalid user" en el nodo; al acumularse, dispara la regla nativa 5712 (nivel 10)
# y la respuesta activa bloquea la IP de este PC durante 180 s.
# No usa contraseñas: la autenticacion por contraseña esta deshabilitada en los nodos.

param(
    [Parameter(Mandatory = $true)][string]$Nodo,
    [int]$Intentos = 10
)

Write-Host "Atacando SSH de $Nodo con $Intentos usuarios inexistentes..." -ForegroundColor Yellow

for ($i = 1; $i -le $Intentos; $i++) {
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 "atacante$i@$Nodo" exit 2>$null
    Write-Host ("Intento {0,2}: usuario atacante{0} (rechazado)" -f $i)
    Start-Sleep -Milliseconds 500
}

Write-Host "Listo. Revisa las alertas 5710/5712 y el bloqueo (regla 651) en Wazuh." -ForegroundColor Green
Write-Host "Si ahora 'ssh sgadmin@$Nodo' se queda colgado, es la respuesta activa bloqueando tu IP." -ForegroundColor Cyan
