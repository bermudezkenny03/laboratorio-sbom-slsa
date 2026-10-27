<#
.SYNOPSIS
  Paso 2: construye la imagen Docker (multi-stage, distroless, usuario no root).
.PARAMETER GoVersion
  Versión de la imagen golang usada para compilar. La guía usa 1.22; una versión
  soportada (p. ej. 1.27) elimina los CVE de la biblioteca estándar.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\03-construir-imagen.ps1
  powershell -ExecutionPolicy Bypass -File .\scripts\03-construir-imagen.ps1 -GoVersion 1.27 -Tag 1.0.1
#>
param(
    [string]$Imagen    = 'lab246',
    [string]$Tag       = '1.0.0',
    [string]$GoVersion = '1.22'
)
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

try {
    Test-Herramienta -Nombre 'docker' -ComoInstalar 'winget install Docker.DockerDesktop' | Out-Null
    $referencia = "${Imagen}:${Tag}"

    Write-Paso "Paso 2 - Construyendo $referencia (Go $GoVersion)"
    Invoke-Herramienta -Comando 'docker' -Argumentos @(
        'build',
        '--build-arg', "GO_VERSION=$GoVersion",
        '--build-arg', "VERSION=$Tag",
        '-t', $referencia,
        '.'
    ) -Log 'reports/docker-build.txt'

    # Evidencia de endurecimiento: usuario, tamaño y punto de entrada
    $info = Read-JsonDesdeDocker -Referencia $referencia
    Write-Host ''
    Write-Host 'Propiedades de seguridad de la imagen' -ForegroundColor Cyan
    Write-Host "  ID:          $($info.Id)"
    Write-Host "  Usuario:     $($info.Config.User)"
    Write-Host "  Entrypoint:  $($info.Config.Entrypoint -join ' ')"
    Write-Host ("  Tamaño:      {0:N1} MB" -f ($info.Size / 1MB))
    Write-Host "  Capas:       $(@($info.RootFS.Layers).Count)"

    if ($info.Config.User -notmatch 'nonroot|65532') {
        Write-Aviso 'La imagen no declara un usuario no root.'
    } else {
        Write-Ok 'La imagen corre como usuario no root.'
    }

    @(
        "Imagen:     $referencia",
        "ID:         $($info.Id)",
        "Usuario:    $($info.Config.User)",
        "Entrypoint: $($info.Config.Entrypoint -join ' ')",
        ("Tamaño:     {0:N1} MB" -f ($info.Size / 1MB)),
        "Go:         $GoVersion",
        "Fecha:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
    ) | Set-Content -Path 'reports/imagen-info.txt' -Encoding UTF8

    Write-Ok "Imagen $referencia construida. Detalles en reports/imagen-info.txt"
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
