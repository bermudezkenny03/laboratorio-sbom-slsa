<#
.SYNOPSIS
  Paso 1: genera el SBOM del código fuente (CycloneDX y SPDX) con Syft.
.DESCRIPTION
  Escanea el directorio del proyecto. Este SBOM solo ve lo que declaran los manifiestos
  (go.mod); compáralo con el de la imagen (paso 3) para ver lo que se pierde.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\01-generar-sbom.ps1
#>
param(
    [string]$Nombre  = 'lab246',
    [string]$Version = '1.0.0'
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

try {
    Test-Herramienta -Nombre 'syft' -ComoInstalar 'winget install Anchore.Syft' | Out-Null
    Write-Paso 'Paso 1 - SBOM del código fuente con Syft'

    # Se usa "formato=archivo" en vez de "> archivo" para que el JSON quede en UTF-8
    Invoke-Herramienta -Comando 'syft' -Argumentos @(
        'dir:.',
        '--exclude', './reports/**',
        '--exclude', './.git/**',
        '--source-name', $Nombre,
        '--source-version', $Version,
        '-o', 'cyclonedx-json=reports/sbom-codigo.cdx.json',
        '-o', 'spdx-json=reports/sbom-codigo.spdx.json',
        '-o', 'table'
    )

    $total = Show-ResumenSbom -Ruta 'reports/sbom-codigo.cdx.json'
    Write-Ok 'Generados reports/sbom-codigo.cdx.json y reports/sbom-codigo.spdx.json'
    if ($total -le 1) {
        Write-Aviso ('El SBOM del código casi no tiene componentes: la app solo usa la biblioteca estándar ' +
                     'y Syft no ve el sistema operativo base. Por eso la evidencia principal es el SBOM de la imagen.')
    }
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
