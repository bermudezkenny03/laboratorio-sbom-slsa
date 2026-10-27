<#
.SYNOPSIS
  Paso 9 (opcional en local): verifica la procedencia SLSA que generó GitHub Actions.
.DESCRIPTION
  Usa slsa-verifier para comprobar que la imagen fue construida por el builder oficial
  slsa-github-generator (SLSA Build L3) a partir del repositorio y la rama indicados.
  El workflow ya ejecuta esta verificación en CI; este script permite repetirla en tu PC.

  slsa-verifier no está en winget. Descárgalo una vez:
    https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.7.1
  archivo slsa-verifier-windows-amd64.exe -> guárdalo como tools\slsa-verifier.exe
  (o, si tienes Go: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1)
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\07-verificar-procedencia.ps1 `
    -ImageDigest "ghcr.io/bermudezkenny03/laboratorio-sbom-slsa@sha256:<digest>" -Repo "bermudezkenny03/laboratorio-sbom-slsa"
#>
param(
    [Parameter(Mandatory)][string]$ImageDigest,
    [Parameter(Mandatory)][string]$Repo,
    [string]$Rama = 'main'
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

try {
    Assert-ImageDigest -Referencia $ImageDigest

    # Buscar slsa-verifier en tools\ o en el PATH
    $local = Join-Path $script:RaizLab 'tools\slsa-verifier.exe'
    if (Test-Path $local) {
        $env:PATH = (Join-Path $script:RaizLab 'tools') + [System.IO.Path]::PathSeparator + $env:PATH
    }
    Test-Herramienta -Nombre 'slsa-verifier' -ComoInstalar `
        'descarga slsa-verifier-windows-amd64.exe (v2.7.1) y guárdalo como tools\slsa-verifier.exe' | Out-Null

    # slsa-verifier consulta GHCR; con la CLI de GitHub autenticada se toma el token automáticamente
    if (-not $env:GH_TOKEN -and (Get-Command gh -ErrorAction SilentlyContinue)) {
        $ErrorActionPreference = 'Continue'
        $token = (& gh auth token 2>$null)
        $ErrorActionPreference = 'Stop'
        if ($LASTEXITCODE -eq 0 -and $token) { $env:GH_TOKEN = "$token".Trim() }
    }
    if (-not $env:GH_TOKEN) {
        Write-Aviso ('GH_TOKEN no está definido. Si la verificación falla con error de autenticación, crea un token ' +
                     'en https://github.com/settings/tokens con permiso read:packages y ejecuta: $env:GH_TOKEN = "<token>"')
    }

    Write-Paso "Paso 9 - Verificación de procedencia SLSA de $ImageDigest"
    Invoke-HerramientaSeparada -Comando 'slsa-verifier' -Argumentos @(
        'verify-image', $ImageDigest,
        '--source-uri', "github.com/$Repo",
        '--source-branch', $Rama,
        '--print-provenance'
    ) -Stdout 'reports/procedencia-slsa.json' -Log 'reports/slsa-verifier.txt'

    $proc = Read-Json -Ruta 'reports/procedencia-slsa.json'
    Write-Host ''
    Write-Host 'Procedencia verificada' -ForegroundColor Cyan
    Write-Host "  Tipo de predicado: $($proc.predicateType)"
    if ($proc.predicate.builder.id) {
        Write-Host "  Builder:           $($proc.predicate.builder.id)"
        Write-Host "  Tipo de build:     $($proc.predicate.buildType)"
        Write-Host "  Commit:            $(@($proc.predicate.materials)[0].digest.sha1)"
    } elseif ($proc.predicate.runDetails) {
        Write-Host "  Builder:           $($proc.predicate.runDetails.builder.id)"
        Write-Host "  Tipo de build:     $($proc.predicate.buildDefinition.buildType)"
    }
    Write-Ok 'Procedencia SLSA verificada. Evidencia en reports/slsa-verifier.txt y reports/procedencia-slsa.json'
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
