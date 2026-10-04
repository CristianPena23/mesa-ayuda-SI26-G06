# Pruebas de seguridad de la Parte 6 - Grupo SI26-G06
# Repite contra la app DESPLEGADA los ataques que funcionaban en la version base
# y comprueba que ahora fallan. No usa credenciales reales: crea dos usuarios de
# prueba con claves aleatorias.
#
# Uso (PowerShell, desde la raiz del repo):
#   .\infra\pruebas\pruebas-parte6.ps1 -Url "https://<tunel>.trycloudflare.com"

param(
    [Parameter(Mandatory = $true)][string]$Url
)

$ErrorActionPreference = "Stop"
$Url = $Url.TrimEnd("/")
$api = "$Url/api"
$resultados = @()

function Llamar {
    param([string]$Metodo, [string]$Ruta, $Cuerpo = $null, [string]$Token = "")
    $headers = @{}
    if ($Token) { $headers["Authorization"] = "Bearer $Token" }
    $parametros = @{ UseBasicParsing = $true; Method = $Metodo; Uri = "$api$Ruta"; Headers = $headers }
    if ($null -ne $Cuerpo) {
        $parametros["ContentType"] = "application/json"
        $parametros["Body"] = [Text.Encoding]::UTF8.GetBytes(($Cuerpo | ConvertTo-Json -Compress))
    }
    try {
        $r = Invoke-WebRequest @parametros
        return @{ code = [int]$r.StatusCode; body = $r.Content }
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        return @{ code = $code; body = "$($_.ErrorDetails.Message)" }
    }
}

function Comprobar {
    param([string]$Hallazgo, [string]$Prueba, [bool]$Ok, [string]$Detalle)
    $script:resultados += [pscustomobject]@{ Hallazgo = $Hallazgo; Prueba = $Prueba; Resultado = $(if ($Ok) { "OK" } else { "FALLA" }); Detalle = $Detalle }
    $color = if ($Ok) { "Green" } else { "Red" }
    Write-Host ("[{0}] {1,-5} {2}  -> {3}" -f $(if ($Ok) { "OK" } else { "XX" }), $Hallazgo, $Prueba, $Detalle) -ForegroundColor $color
}

function B64Url([byte[]]$bytes) { [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_") }
function JwtFalso([hashtable]$payload, [string]$secreto) {
    $h = B64Url ([Text.Encoding]::UTF8.GetBytes((@{ alg = "HS256"; typ = "JWT" } | ConvertTo-Json -Compress)))
    $p = B64Url ([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress)))
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($secreto)
    $firma = B64Url ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$h.$p")))
    return "$h.$p.$firma"
}
function ClaveAleatoria { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }) }
# Nginx limita /api/auth/ a 10 peticiones por minuto: se espacian para no recibir 429.
function PausaAuth { Start-Sleep -Seconds 7 }

$sufijo = Get-Random -Minimum 1000 -Maximum 9999
$userA = "prueba_a_$sufijo"; $claveA = ClaveAleatoria
$userB = "prueba_b_$sufijo"; $claveB = ClaveAleatoria

Write-Host "`n=== Preparacion: dos usuarios de prueba ===" -ForegroundColor Cyan
$r = Llamar POST "/auth/registro" @{ username = $userA; email = "$userA@ejemplo.com"; password = $claveA }
Write-Host "Registro $userA -> HTTP $($r.code)"; PausaAuth
$r = Llamar POST "/auth/registro" @{ username = $userB; email = "$userB@ejemplo.com"; password = $claveB }
Write-Host "Registro $userB -> HTTP $($r.code)"; PausaAuth
$r = Llamar POST "/auth/login" @{ username = $userA; password = $claveA }
if ($r.code -ne 200) { Write-Host "No se pudo iniciar sesion con $userA (HTTP $($r.code)): $($r.body)" -ForegroundColor Red; exit 1 }
$tokenA = ($r.body | ConvertFrom-Json).access_token; PausaAuth
$r = Llamar POST "/auth/login" @{ username = $userB; password = $claveB }
$tokenB = ($r.body | ConvertFrom-Json).access_token; PausaAuth

$xss = '<b>Texto en negrita</b> <img src=x onerror="alert(''XSS'')"> <script>alert("XSS")</script>'
$r = Llamar POST "/tickets" @{ titulo = "Ticket privado de A"; descripcion = $xss; prioridad = "alta" } $tokenA
$ticketA = ($r.body | ConvertFrom-Json).id
Write-Host "Ticket de A creado: #$ticketA (su descripcion trae una carga XSS)"

Write-Host "`n=== Ataques ===" -ForegroundColor Cyan

# H12 - Inyeccion SQL en el login: el UNION inventa un usuario "admin" cuyo hash
# es el MD5 de "x". En la version base la app comparaba la clave "x" con ese hash
# inventado y entregaba un token de administrador sin conocer ninguna clave.
$md5x = "9dd4e461268c8034f5c8564e155c67a6"
$r = Llamar POST "/auth/login" @{ username = "noexiste' UNION SELECT 1,'admin','admin','$md5x' -- "; password = "x" }
Comprobar "H12" "SQLi UNION en login para entrar como admin" ($r.code -eq 401) "HTTP $($r.code) (antes: 200 con token de admin)"
PausaAuth

# H13 - Inyeccion SQL en la busqueda
$carga = "x' UNION SELECT id,username,password_hash,email,rol,'abierto',id,creado_en FROM usuarios -- "
$r = Llamar GET ("/tickets/buscar?q=" + [uri]::EscapeDataString($carga)) $null $tokenB
$filtra = $r.body -match "scrypt|password_hash|$userA"
Comprobar "H13" "SQLi UNION en /tickets/buscar" (($r.code -eq 200) -and -not $filtra) "HTTP $($r.code), respuesta: $($r.body)"

# H14 - Endpoint de depuracion
$r = Llamar GET "/debug/config"
Comprobar "H14" "GET /api/debug/config" (($r.code -eq 404) -or ($r.code -eq 403)) "HTTP $($r.code) (antes: devolvia la clave de la BD y el JWT_SECRET)"

# Documentacion de la API
$r = Llamar GET "/openapi.json"
Comprobar "Docs" "GET /api/openapi.json" (($r.code -eq 404) -or ($r.code -eq 403)) "HTTP $($r.code)"

# H28 / H4 - Tokens fabricados
$ahora = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$falso = JwtFalso @{ sub = "1"; username = "admin"; rol = "admin"; iat = $ahora; exp = $ahora + 600 } "mesa-ayuda-secret-2026"
$r = Llamar GET "/admin/usuarios" $null $falso
Comprobar "H4/H28" "Token admin firmado con el secreto viejo publicado" ($r.code -eq 401) "HTTP $($r.code)"
$sinFirma = (B64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"none","typ":"JWT"}'))) + "." + (B64Url ([Text.Encoding]::UTF8.GetBytes("{`"sub`":`"1`",`"rol`":`"admin`",`"iat`":$ahora,`"exp`":$($ahora + 600)}"))) + "."
$r = Llamar GET "/admin/usuarios" $null $sinFirma
Comprobar "H28" "Token admin sin firma (alg=none)" ($r.code -eq 401) "HTTP $($r.code)"

# Control de acceso de admin con un token valido de usuario normal
$r = Llamar GET "/admin/usuarios" $null $tokenB
Comprobar "Acceso" "Usuario normal pide /admin/usuarios" ($r.code -eq 403) "HTTP $($r.code)"

# H17 / H18 - IDOR
$r = Llamar GET "/tickets/$ticketA" $null $tokenB
Comprobar "H17" "B lee el ticket #$ticketA de A" ($r.code -eq 404) "HTTP $($r.code) (antes: 200 con el ticket ajeno)"
$r = Llamar PATCH "/tickets/$ticketA/estado" @{ estado = "cerrado" } $tokenB
Comprobar "H18" "B cierra el ticket #$ticketA de A" ($r.code -eq 404) "HTTP $($r.code)"
$r = Llamar PATCH "/tickets/$ticketA/estado" @{ estado = "hackeado" } $tokenA
Comprobar "H18" "A pone un estado inventado" ($r.code -eq 400) "HTTP $($r.code)"

# Control: lo legitimo sigue funcionando
$r = Llamar GET "/tickets/$ticketA" $null $tokenA
Comprobar "Control" "A lee SU propio ticket" ($r.code -eq 200) "HTTP $($r.code)"

Write-Host "`n=== Resumen ===" -ForegroundColor Cyan
$resultados | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
$fallas = ($resultados | Where-Object { $_.Resultado -eq "FALLA" }).Count
if ($fallas -eq 0) { Write-Host "Las $($resultados.Count) pruebas dieron el resultado esperado: los ataques quedaron bloqueados y lo legitimo funciona." -ForegroundColor Green }
else { Write-Host "$fallas prueba(s) no se comportaron como se esperaba." -ForegroundColor Red }

Write-Host "`nPara la prueba de XSS (H24) en el navegador, inicie sesion con:" -ForegroundColor Yellow
Write-Host "  Usuario: $userA"
Write-Host "  Clave:   $claveA"
Write-Host "y abra el ticket #$ticketA. Debe verse 'Texto en negrita' en negrita y NINGUNA alerta."
