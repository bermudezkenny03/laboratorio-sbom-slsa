<#
.SYNOPSIS
  Paso 7: verifica la atestación CycloneDX de la imagen con cosign.
.DESCRIPTION
  Tres modos, de menos a más estricto:
    1. Sin parámetros de identidad: acepta cualquier firmante (solo para practicar).
    2. -Identidad tu@correo: exige que la haya firmado tu cuenta (atestación hecha en el paso 6).
    3. -Repo usuario/repo: exige que la haya firmado el workflow de GitHub Actions de ese repo.
  En producción se usa siempre el modo 2 o 3: verificar sin fijar la identidad no prueba nada.
.EXAMPLE
  # Atestación que firmaste tú en el paso 6
  powershell -ExecutionPolicy Bypass -File .\scripts\06-verificar-atestacion.ps1 `
    -ImageDigest "ghcr.io/bermudezkenny03/laboratorio-sbom-slsa@sha256:<digest>" -Identidad "tu-correo@ejemplo.com"
.EXAMPLE
  # Atestación que firmó el pipeline de GitHub Actions
  powershell -ExecutionPolicy Bypass -File .\scripts\06-verificar-atestacion.ps1 `
    -ImageDigest "ghcr.io/bermudezkenny03/laboratorio-sbom-slsa@sha256:<digest>" -Repo "bermudezkenny03/laboratorio-sbom-slsa"
#>
param(
    [Parameter(Mandatory)][string]$ImageDigest,
    [string]$Identidad = '',
    [string]$Emisor    = 'https://github.com/login/oauth',
    [string]$Repo      = '',
    [string]$Rama      = 'main',
    [switch]$FormatoNuevo
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

try {
    Test-Herramienta -Nombre 'cosign' -ComoInstalar 'winget install Sigstore.Cosign' | Out-Null
    Assert-ImageDigest -Referencia $ImageDigest

    Write-Paso "Paso 7 - Verificación de la atestación CycloneDX de $ImageDigest"

    $argumentos = @('verify-attestation', '--type', 'cyclonedx')
    if (-not $FormatoNuevo) { $argumentos += '--new-bundle-format=false' }

    if ($Repo) {
        $workflow = "https://github.com/$Repo/.github/workflows/sbom-slsa.yml@refs/heads/$Rama"
        Write-Host "Modo estricto (CI): firmante esperado $workflow"
        $argumentos += @(
            '--certificate-identity', $workflow,
            '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'
        )
        $sufijo = 'ci'
    }
    elseif ($Identidad) {
        Write-Host "Modo estricto (local): firmante esperado $Identidad emitido por $Emisor"
        $argumentos += @(
            '--certificate-identity', $Identidad,
            '--certificate-oidc-issuer', $Emisor
        )
        $sufijo = 'local'
    }
    else {
        Write-Aviso ('Modo laboratorio: se acepta CUALQUIER identidad. Sirve para practicar, pero en producción ' +
                     'usa -Identidad o -Repo para fijar quién debe haber firmado.')
        $argumentos += @(
            '--certificate-identity-regexp', '.*',
            '--certificate-oidc-issuer-regexp', '.*'
        )
        $sufijo = 'abierta'
    }
    $argumentos += $ImageDigest

    $salidaJson = "reports/atestacion-sbom-$sufijo.jsonl"
    Invoke-HerramientaSeparada -Comando 'cosign' -Argumentos $argumentos `
        -Stdout $salidaJson -Log "reports/cosign-verify-$sufijo.txt"

    # Cada línea es un sobre DSSE; el payload en base64 es la declaración in-toto
    Write-Host ''
    Write-Host 'Contenido verificado' -ForegroundColor Cyan
    $n = 0
    Get-Content -Path $salidaJson -Encoding UTF8 | Where-Object { $_.Trim() } | ForEach-Object {
        $n++
        $sobre = $_ | ConvertFrom-Json
        $bytes = [System.Convert]::FromBase64String($sobre.payload)
        $declaracion = [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        $sujeto = @($declaracion.subject)[0]
        $componentes = @($declaracion.predicate.components).Count
        Write-Host "  Atestación #$n"
        Write-Host "    Tipo de predicado: $($declaracion.predicateType)"
        Write-Host "    Sujeto:            $($sujeto.name)@sha256:$($sujeto.digest.sha256)"
        Write-Host "    Componentes SBOM:  $componentes"
    }
    if ($n -eq 0) { throw 'cosign no devolvió atestaciones.' }

    Write-Ok "Firma verificada. Evidencia en reports/cosign-verify-$sufijo.txt y $salidaJson"
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
