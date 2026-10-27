<#
.SYNOPSIS
  Paso 0: verifica que las herramientas del laboratorio estén instaladas y guarda sus versiones.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\00-verificar-entorno.ps1
#>
. "$PSScriptRoot\_comun.ps1"
Initialize-Lab

$herramientas = @(
    @{ Nombre = 'docker'; Version = @('--version');        Instalar = 'winget install Docker.DockerDesktop' },
    @{ Nombre = 'git';    Version = @('--version');        Instalar = 'winget install Git.Git' },
    @{ Nombre = 'syft';   Version = @('version');          Instalar = 'winget install Anchore.Syft' },
    @{ Nombre = 'grype';  Version = @('version');          Instalar = 'winget install Anchore.Grype' },
    @{ Nombre = 'cosign'; Version = @('version');          Instalar = 'winget install Sigstore.Cosign' }
)

$informe = New-Object System.Collections.Generic.List[string]
$informe.Add("# Versiones de herramientas - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
$informe.Add("# Sistema: $([System.Environment]::OSVersion.VersionString) | PowerShell $($PSVersionTable.PSVersion)")
$faltantes = 0

try {
    Write-Paso 'Verificando herramientas del laboratorio'
    foreach ($h in $herramientas) {
        $cmd = Get-Command $h.Nombre -ErrorAction SilentlyContinue
        if (-not $cmd) {
            Write-Fallo "$($h.Nombre) no está instalado. Instálalo con: $($h.Instalar)"
            $informe.Add("$($h.Nombre): NO INSTALADO")
            $faltantes++
            continue
        }
        $ErrorActionPreference = 'Continue'
        $ver = (& $h.Nombre @($h.Version) 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $ErrorActionPreference = 'Stop'
        # Primera línea con número de versión
        $linea = ($ver -split "`n" | Where-Object { $_ -match '\d+\.\d+' } | Select-Object -First 1)
        if (-not $linea) { $linea = ($ver -split "`n")[0] }
        Write-Ok ("{0,-7} {1}" -f $h.Nombre, $linea.Trim())
        $informe.Add("`n## $($h.Nombre)`n$ver")
    }

    Write-Paso 'Verificando que Docker Desktop esté corriendo'
    $ErrorActionPreference = 'Continue'
    $dockerInfo = (& docker info --format '{{.ServerVersion}} ({{.OperatingSystem}})' 2>&1 | ForEach-Object { "$_" }) -join ' '
    $codigoDocker = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($codigoDocker -eq 0) {
        Write-Ok "Docker Engine $dockerInfo"
        $informe.Add("`n## docker engine`n$dockerInfo")
    } else {
        Write-Fallo 'Docker no responde. Abre Docker Desktop y espera a que diga "Engine running".'
        $faltantes++
    }

    $ruta = Join-Path $script:CarpetaRep 'versiones-herramientas.txt'
    $informe | Set-Content -Path $ruta -Encoding UTF8
    Write-Host ''
    Write-Host "Versiones guardadas en $ruta"

    if ($faltantes -gt 0) {
        throw "Faltan $faltantes requisito(s). Corrígelos y vuelve a ejecutar este script."
    }
    Write-Ok 'Entorno listo para el laboratorio.'
}
catch {
    Write-Fallo $_.Exception.Message
    exit 1
}
