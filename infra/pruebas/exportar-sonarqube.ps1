# Exporta a docs/ el historial de analisis de SonarQube (antes y despues) - Grupo SI26-G06
# SonarQube Community no genera PDF; este script consulta su API y escribe un informe
# en Markdown con fecha, para dejarlo en el repositorio como pide el enunciado (6.3 / 6.5).
#
# Uso (PowerShell, desde la raiz del repo, con SonarQube encendido en localhost:9000):
#   .\infra\pruebas\exportar-sonarqube.ps1
# El token se pide por teclado y NO se guarda en ningun archivo.

param(
    [string]$Servidor = "http://localhost:9000",
    [string[]]$Proyectos = @("mesa-ayuda-backend", "mesa-ayuda-frontend")
)

$ErrorActionPreference = "Stop"

$seguro = Read-Host "Token de SonarQube (no se muestra ni se guarda)" -AsSecureString
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($seguro))
$auth = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${token}:")) }

function Api([string]$ruta) {
    Invoke-RestMethod -UseBasicParsing -Headers $auth -Uri "$Servidor$ruta"
}

function Nota($valor) {
    if ($null -eq $valor -or $valor -eq "") { return "-" }
    switch ([int][double]$valor) { 1 { "A" } 2 { "B" } 3 { "C" } 4 { "D" } 5 { "E" } default { "$valor" } }
}

$metricas = "security_rating,vulnerabilities,reliability_rating,bugs,sqale_rating,code_smells,security_hotspots,ncloc,coverage,duplicated_lines_density"
$fecha = Get-Date -Format "yyyy-MM-dd"
$salida = Join-Path (Get-Location) "docs\sonarqube-$fecha.md"

$md = @()
$md += "# Informe de SonarQube Community - Grupo SI26-G06"
$md += ""
$md += "Generado el $fecha desde la API de SonarQube ($Servidor). Cada fila es un analisis; la primera es la version base (``v-base``) y las siguientes, el codigo corregido."
$md += "Notas: A = mejor, E = peor. Security/Reliability/Maintainability = cantidad de problemas abiertos."
$md += ""

foreach ($p in $Proyectos) {
    $hist = Api "/api/measures/search_history?component=$p&metrics=$metricas&ps=100"
    $analisis = Api "/api/project_analyses/search?project=$p&ps=100"
    $gate = Api "/api/qualitygates/project_status?projectKey=$p"

    $versiones = @{}
    foreach ($a in $analisis.analyses) {
        $v = ($a.events | Where-Object { $_.category -eq "VERSION" } | Select-Object -First 1).name
        if (-not $v) { $v = $a.projectVersion }
        $versiones[$a.date] = $v
    }

    $porMetrica = @{}
    foreach ($m in $hist.measures) { $porMetrica[$m.metric] = $m.history }
    $fechas = $porMetrica["ncloc"] | ForEach-Object { $_.date }

    $md += "## $p"
    $md += ""
    $md += "| Fecha del analisis | Version | Security | Reliability | Maintainability | Hotspots | Lineas | Cobertura | Duplicacion |"
    $md += "|---|---|---|---|---|---|---|---|---|"
    for ($i = 0; $i -lt $fechas.Count; $i++) {
        $val = @{}
        foreach ($k in $porMetrica.Keys) { $val[$k] = $porMetrica[$k][$i].value }
        $ver = $versiones[$fechas[$i]]; if (-not $ver) { $ver = "-" }
        $f = $fechas[$i]; if ($f -is [datetime]) { $f = $f.ToString("yyyy-MM-dd HH:mm") }
        $md += "| $f | $ver | $(Nota $val['security_rating']) ($($val['vulnerabilities'])) | $(Nota $val['reliability_rating']) ($($val['bugs'])) | $(Nota $val['sqale_rating']) ($($val['code_smells'])) | $($val['security_hotspots']) | $($val['ncloc']) | $($val['coverage'])% | $($val['duplicated_lines_density'])% |"
    }
    $md += ""
    $md += "Quality Gate actual: **$($gate.projectStatus.status)**"
    foreach ($c in $gate.projectStatus.conditions) {
        if ($c.status -ne "OK") { $md += "- Condicion que falla: ``$($c.metricKey)`` = $($c.actualValue) (umbral $($c.comparator) $($c.errorThreshold))" }
    }
    $md += ""
}

$md += "Limitacion de la edicion Community: no hace analisis de flujo de datos (taint analysis), por lo que no detecta inyecciones SQL ni XSS; ver Bearer, ZAP y las pruebas de ataque en ``infra/pruebas/``."

Set-Content -Path $salida -Value $md -Encoding UTF8
Write-Host "Informe escrito en $salida" -ForegroundColor Green
$token = $null
