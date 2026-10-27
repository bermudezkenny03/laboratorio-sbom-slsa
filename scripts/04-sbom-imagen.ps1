<#
.SYNOPSIS
  Paso 3: genera el SBOM de la imagen final (CycloneDX y SPDX) con Syft.
.DESCRIPTION
  Es la evidencia principal: incluye los paquetes del sistema base (distroless/Debian)
  y el binario Go con la versión exacta de la biblioteca estándar con que se compiló.
.PARAMETER Imagen
  Imagen local (lab246:1.0.0) o publicada por digest (ghcr.io/usuario/repo@sha256:...).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\04-sbom-imagen.ps1
#>
param(
    [string]$Imagen = 'lab246:1.0.0'
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

try {
    Test-Herramienta -Nombre 'syft' -ComoInstalar 'winget install Anchore.Syft' | Out-Null
    Write-Paso "Paso 3 - SBOM de la imagen $Imagen"

    Invoke-Herramienta -Comando 'syft' -Argumentos @(
        $Imagen,
        '-o', 'cyclonedx-json=reports/sbom-imagen.cdx.json',
        '-o', 'spdx-json=reports/sbom-imagen.spdx.json',
        '-o', 'table'
    )

    $totalImagen = Show-ResumenSbom -Ruta 'reports/sbom-imagen.cdx.json'
    Write-Ok 'Generados reports/sbom-imagen.cdx.json y reports/sbom-imagen.spdx.json'

    # Comparación con el SBOM del código, si existe
    if (Test-Path 'reports/sbom-codigo.cdx.json') {
        $totalCodigo = @((Read-Json -Ruta 'reports/sbom-codigo.cdx.json').components).Count
        Write-Host ''
        Write-Host 'Comparación código vs imagen' -ForegroundColor Cyan
        Write-Host "  Componentes en SBOM del código: $totalCodigo"
        Write-Host "  Componentes en SBOM de la imagen: $totalImagen"
        Write-Host '  La diferencia son las dependencias que solo aparecen en el artefacto final.'
    }
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
