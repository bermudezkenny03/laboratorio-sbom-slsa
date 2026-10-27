<#
.SYNOPSIS
  Pipeline local completo del laboratorio 246.
.DESCRIPTION
  Sin parámetros: verifica el entorno, genera el SBOM del código, construye la imagen,
  genera el SBOM de la imagen y la escanea con Grype.
  Con -UsuarioGitHub: además publica la imagen en GHCR, adjunta el SBOM como atestación
  firmada con cosign y la verifica con tu identidad.
  Al final escribe reports/resumen-pipeline.md con los resultados.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-local.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-local.ps1 `
    -UsuarioGitHub bermudezkenny03 -Identidad "tu-correo@ejemplo.com"
#>
param(
    [string]$Imagen        = 'lab246',
    [string]$Tag           = '1.0.0',
    [string]$GoVersion     = '1.22',
    [string]$UsuarioGitHub = '',
    [string]$Repositorio   = 'laboratorio-sbom-slsa',
    [string]$Identidad     = ''
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

$inicio = Get-Date
$local  = "${Imagen}:${Tag}"
$digest = ''

function Invoke-Paso {
    param([string]$Script, [hashtable]$Parametros = @{})
    $ruta = Join-Path $PSScriptRoot $Script
    $global:LASTEXITCODE = 0
    & $ruta @Parametros
    if ($LASTEXITCODE -ne 0) { throw "Falló $Script" }
}

try {
    Invoke-Paso '00-verificar-entorno.ps1'
    Invoke-Paso '01-generar-sbom.ps1'     @{ Version = $Tag }
    Invoke-Paso '03-construir-imagen.ps1' @{ Imagen = $Imagen; Tag = $Tag; GoVersion = $GoVersion }
    Invoke-Paso '04-sbom-imagen.ps1'      @{ Imagen = $local }
    Invoke-Paso '02-escanear-sbom.ps1'

    if ($UsuarioGitHub) {
        $usuario = $UsuarioGitHub.ToLower()          # GHCR exige minúsculas
        # Sufijo -local para no pisar el tag que publica el CI
        $remota  = "ghcr.io/$usuario/$($Repositorio.ToLower()):$Tag-local"

        Write-Paso "Paso 5 - Publicando $remota"
        Write-Host 'Si falla por permisos, ejecuta antes: docker login ghcr.io -u <usuario>  (contraseña = token con write:packages)'
        Invoke-Herramienta -Comando 'docker' -Argumentos @('tag', $local, $remota)
        Invoke-Herramienta -Comando 'docker' -Argumentos @('push', $remota) -Log 'reports/docker-push.txt'

        $info = Read-JsonDesdeDocker -Referencia $remota
        $digest = @($info.RepoDigests | Where-Object { $_ -like "ghcr.io/$usuario/$($Repositorio.ToLower())@sha256:*" })[0]
        if (-not $digest) { throw 'No se pudo obtener el digest publicado (RepoDigests vacío).' }
        Write-Ok "Digest publicado: $digest"
        Set-Content -Path 'reports/imagen-digest.txt' -Value $digest -Encoding UTF8

        Invoke-Paso '05-adjuntar-atestacion.ps1' @{ ImageDigest = $digest }
        if ($Identidad) {
            Invoke-Paso '06-verificar-atestacion.ps1' @{ ImageDigest = $digest; Identidad = $Identidad }
        } else {
            Invoke-Paso '06-verificar-atestacion.ps1' @{ ImageDigest = $digest }
        }
    }

    # ---------- Resumen ----------
    $sbomCod = @((Read-Json 'reports/sbom-codigo.cdx.json').components).Count
    $sbomImg = @((Read-Json 'reports/sbom-imagen.cdx.json').components).Count
    $vulns   = @((Read-Json 'reports/grype-resultados.json').matches)
    $porSev  = $vulns | Group-Object { $_.vulnerability.severity } |
               ForEach-Object { "| $($_.Name) | $($_.Count) |" }
    $duracion = [int]((Get-Date) - $inicio).TotalSeconds
    $bt = [char]96   # comilla invertida para formato de código en Markdown

    if ($digest) {
        $txtDigest = "$bt$digest$bt"
        $txtAtest  = '- Atestación CycloneDX firmada con cosign: ver reports/cosign-attest.txt y reports/cosign-verify-*.txt'
    } else {
        $txtDigest = 'no publicada en esta ejecución'
        $txtAtest  = '- Ejecuta con -UsuarioGitHub para publicar, firmar y verificar.'
    }

    $md = @(
        '# Resumen del pipeline local - Laboratorio 246',
        '',
        "- Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
        "- Equipo: $env:COMPUTERNAME | PowerShell $($PSVersionTable.PSVersion)",
        "- Imagen local: $bt$local$bt (Go $GoVersion)",
        "- Imagen publicada: $txtDigest",
        "- Duración: $duracion s",
        '',
        '## SBOM',
        '',
        '| Origen | Componentes |',
        '|---|---|',
        "| Código (${bt}reports/sbom-codigo.cdx.json${bt}) | $sbomCod |",
        "| Imagen (${bt}reports/sbom-imagen.cdx.json${bt}) | $sbomImg |",
        '',
        '## Vulnerabilidades (Grype sobre el SBOM de la imagen)',
        '',
        '| Severidad | Cantidad |',
        '|---|---|'
    ) + $porSev + @(
        "| **Total** | **$($vulns.Count)** |",
        '',
        '## Atestación',
        '',
        $txtAtest
    )
    $md | Set-Content -Path 'reports/resumen-pipeline.md' -Encoding UTF8

    Write-Paso 'Pipeline local completado'
    Write-Ok "Resumen en reports/resumen-pipeline.md ($duracion s)"
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
