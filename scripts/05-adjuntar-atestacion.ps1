<#
.SYNOPSIS
  Paso 6: adjunta el SBOM de la imagen como atestación in-toto firmada con cosign (keyless).
.DESCRIPTION
  cosign abrirá el navegador para que inicies sesión (elige GitHub). Sigstore emite un
  certificado de corta duración con tu identidad, firma la atestación y la registra en el
  log de transparencia público Rekor. La atestación queda guardada en el registro junto a la imagen.

  Por defecto se usa el formato clásico de cosign (etiqueta sha256-<digest>.att) porque
  GHCR no implementa la API de "referrers" de OCI 1.1 que usa el formato nuevo de cosign v3.
  Usa -FormatoNuevo si publicas en un registro que sí la soporte (por ejemplo Docker Hub).
.PARAMETER ImageDigest
  Imagen publicada, referenciada por digest: ghcr.io/usuario/repo@sha256:...
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\05-adjuntar-atestacion.ps1 `
    -ImageDigest "ghcr.io/bermudezkenny03/laboratorio-sbom-slsa@sha256:<digest>"
#>
param(
    [Parameter(Mandatory)][string]$ImageDigest,
    [string]$Sbom = 'reports/sbom-imagen.cdx.json',
    [switch]$FormatoNuevo
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

try {
    Test-Herramienta -Nombre 'cosign' -ComoInstalar 'winget install Sigstore.Cosign' | Out-Null
    Assert-ImageDigest -Referencia $ImageDigest
    if (-not (Test-Path $Sbom)) { throw "No existe $Sbom. Ejecuta antes 04-sbom-imagen.ps1." }

    Write-Paso "Paso 6 - Atestación firmada del SBOM sobre $ImageDigest"
    Write-Aviso 'Se abrirá el navegador para iniciar sesión en Sigstore. Elige "GitHub" y autoriza.'

    $argumentos = @(
        'attest', '--yes',
        '--predicate', $Sbom,
        '--type', 'cyclonedx'
    )
    if (-not $FormatoNuevo) {
        $argumentos += @('--new-bundle-format=false', '--use-signing-config=false')
    }
    $argumentos += $ImageDigest

    Invoke-Herramienta -Comando 'cosign' -Argumentos $argumentos -Log 'reports/cosign-attest.txt'

    Write-Ok 'Atestación creada y registrada en Rekor. Salida guardada en reports/cosign-attest.txt'
    Write-Host 'Siguiente paso: 06-verificar-atestacion.ps1 con el mismo -ImageDigest.'
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
