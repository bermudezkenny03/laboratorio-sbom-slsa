<#
.SYNOPSIS
  Paso 4: consume el SBOM de la imagen con Grype y reporta vulnerabilidades.
.DESCRIPTION
  Un SBOM solo es útil si se consume. Grype cruza cada componente del SBOM con su base de
  datos de vulnerabilidades sin necesidad de volver a analizar la imagen.
.PARAMETER Sbom
  SBOM a escanear (por defecto el de la imagen, generado en el paso 3).
.PARAMETER FallarEn
  Severidad a partir de la cual el script falla (negligible, low, medium, high, critical).
  Úsalo como "quality gate"; vacío = solo reportar.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\02-escanear-sbom.ps1
  powershell -ExecutionPolicy Bypass -File .\scripts\02-escanear-sbom.ps1 -FallarEn critical
#>
param(
    [string]$Sbom = 'reports/sbom-imagen.cdx.json',
    [ValidateSet('', 'negligible', 'low', 'medium', 'high', 'critical')]
    [string]$FallarEn = ''
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

try {
    Test-Herramienta -Nombre 'grype' -ComoInstalar 'winget install Anchore.Grype' | Out-Null
    if (-not (Test-Path $Sbom)) {
        throw "No existe $Sbom. Ejecuta antes 03-construir-imagen.ps1 y 04-sbom-imagen.ps1."
    }

    Write-Paso "Paso 4 - Escaneo de vulnerabilidades a partir de $Sbom"

    $argumentos = @(
        "sbom:$Sbom",
        '-o', 'table',
        '-o', 'json=reports/grype-resultados.json'
    )
    if ($FallarEn) { $argumentos += @('--fail-on', $FallarEn) }

    # Grype devuelve código 1 cuando se supera --fail-on; lo evaluamos después del resumen
    Invoke-Herramienta -Comando 'grype' -Argumentos $argumentos -Log 'reports/grype-resultados.txt' -PermitirFallo
    $codigo = $LASTEXITCODE

    if (-not (Test-Path 'reports/grype-resultados.json')) {
        throw 'Grype no generó reports/grype-resultados.json. Revisa la conexión a internet (descarga de la base de datos).'
    }

    $resultado = Read-Json -Ruta 'reports/grype-resultados.json'
    $hallazgos = @($resultado.matches)

    Write-Host ''
    Write-Host 'Resumen por severidad' -ForegroundColor Cyan
    $orden = @('Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown')
    foreach ($sev in $orden) {
        $n = @($hallazgos | Where-Object { $_.vulnerability.severity -eq $sev }).Count
        if ($n -gt 0) { Write-Host ("  {0,-11} {1}" -f $sev, $n) }
    }
    Write-Host "  Total       $($hallazgos.Count)"

    $conFix = @($hallazgos | Where-Object { $_.vulnerability.fix.state -eq 'fixed' }).Count
    Write-Host "  Con versión corregida disponible: $conFix"

    if ($hallazgos.Count -gt 0) {
        Write-Host ''
        Write-Host 'Componentes afectados' -ForegroundColor Cyan
        $hallazgos | Group-Object { "$($_.artifact.name) $($_.artifact.version)" } |
            Sort-Object Count -Descending | ForEach-Object {
                Write-Host ("  {0,-40} {1} CVE" -f $_.Name, $_.Count)
            }
    }

    Write-Ok 'Resultados en reports/grype-resultados.json y reports/grype-resultados.txt'

    if ($FallarEn -and $codigo -ne 0) {
        throw "Quality gate: hay vulnerabilidades de severidad '$FallarEn' o superior."
    }
    if ($codigo -ne 0 -and -not $FallarEn) {
        throw "grype terminó con código $codigo"
    }
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
