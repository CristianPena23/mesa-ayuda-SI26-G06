# Ataque de fuerza bruta de prueba contra el login - D2, Grupo SI26-G06
# Uso (PowerShell, desde el PC de un integrante):
#   .\ataque_d2.ps1 -Url "https://<tu-url>.trycloudflare.com"
#
# Hace 8 intentos de login invalidos ESPACIADOS 7 s. El espaciado es a proposito:
# Nginx limita /api/auth/ a 10 req/min, asi que peticiones muy seguidas darian 429
# (el propio control de la Parte 4). Con 7 s cada intento pasa el limite y el backend
# responde 401, que es lo que registra el log de auditoria y cuenta la regla 100106.
# 8 fallos en ~49 s (< 60 s) disparan la alerta de fuerza bruta.
# NO usa contraseñas reales de nadie.

param(
    [Parameter(Mandatory = $true)][string]$Url,
    [int]$Intentos = 8,
    [int]$SegundosEntre = 7
)

$endpoint = "$Url/api/auth/login"
Write-Host "Atacando $endpoint con $Intentos intentos (uno cada $SegundosEntre s)..." -ForegroundColor Yellow

for ($i = 1; $i -le $Intentos; $i++) {
    $body = @{ username = "admin"; password = "intento-malo-$i" } | ConvertTo-Json
    try {
        Invoke-WebRequest -UseBasicParsing -Method Post -Uri $endpoint `
            -ContentType "application/json" -Body $body | Out-Null
        $code = 200
    } catch {
        $code = [int]$_.Exception.Response.StatusCode
    }
    $marca = if ($code -eq 401) { "fallo de login (se registra)" }
             elseif ($code -eq 429) { "bloqueado por rate-limit" }
             else { "" }
    Write-Host ("Intento {0,2}: HTTP {1}  {2}" -f $i, $code, $marca)
    if ($i -lt $Intentos) { Start-Sleep -Seconds $SegundosEntre }
}

Write-Host "Listo. Revisa la alerta 100106 en el dashboard de Wazuh." -ForegroundColor Green
