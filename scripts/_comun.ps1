# Funciones compartidas por los scripts del laboratorio 246.
# Compatible con Windows PowerShell 5.1 y PowerShell 7+.
# Se carga con:  . "$PSScriptRoot\_comun.ps1"

$ErrorActionPreference = 'Stop'

# Mostrar tildes y caracteres especiales correctamente en la consola
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# Raíz del proyecto = carpeta padre de scripts/
$script:RaizLab     = Split-Path -Parent $PSScriptRoot
$script:CarpetaRep  = Join-Path $script:RaizLab 'reports'

function Initialize-Lab {
    Set-Location $script:RaizLab
    if (-not (Test-Path $script:CarpetaRep)) {
        New-Item -ItemType Directory -Path $script:CarpetaRep | Out-Null
    }
}

function Write-Paso {
    param([Parameter(Mandatory)][string]$Texto)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "  $Texto" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

function Write-Ok    { param([string]$Texto) Write-Host "[OK]  $Texto" -ForegroundColor Green }
function Write-Aviso { param([string]$Texto) Write-Host "[!]   $Texto" -ForegroundColor Yellow }
function Write-Fallo { param([string]$Texto) Write-Host "[X]   $Texto" -ForegroundColor Red }

# Verifica que una herramienta esté instalada y en el PATH
function Test-Herramienta {
    param(
        [Parameter(Mandatory)][string]$Nombre,
        [string]$ComoInstalar = ''
    )
    $cmd = Get-Command $Nombre -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $msg = "No se encontró '$Nombre' en el PATH."
        if ($ComoInstalar) { $msg += " Instálalo con: $ComoInstalar (y abre una terminal nueva)." }
        throw $msg
    }
    return $cmd.Source
}

# Ejecuta una herramienta de línea de comandos mostrando la salida en vivo,
# opcionalmente la guarda en un archivo de log (UTF-8) y falla si el código de salida != 0.
# Se usa en lugar de "> archivo" porque en Windows PowerShell 5.1 la redirección
# escribe en UTF-16 y rompe los JSON que luego leen grype o cosign.
function Invoke-Herramienta {
    param(
        [Parameter(Mandatory)][string]$Comando,
        [string[]]$Argumentos = @(),
        [string]$Log = '',
        [switch]$PermitirFallo
    )
    Write-Host "> $Comando $($Argumentos -join ' ')" -ForegroundColor DarkGray

    $anterior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $salida = & $Comando @Argumentos 2>&1 | ForEach-Object {
            $linea = "$_"
            Write-Host $linea
            $linea
        }
        $codigo = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $anterior
    }

    if ($Log) {
        $encabezado = @(
            "# Comando: $Comando $($Argumentos -join ' ')",
            "# Fecha:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
            "# Código de salida: $codigo",
            ''
        )
        ($encabezado + @($salida)) | Set-Content -Path $Log -Encoding UTF8
    }

    # El código queda disponible para quien llama en $LASTEXITCODE
    if ($codigo -ne 0 -and -not $PermitirFallo) {
        throw "$Comando terminó con código de salida $codigo"
    }
}

# Ejecuta una herramienta separando stdout (a un archivo, sin tocar su contenido)
# de stderr (mensajes que se muestran y se guardan en un log).
function Invoke-HerramientaSeparada {
    param(
        [Parameter(Mandatory)][string]$Comando,
        [string[]]$Argumentos = @(),
        [Parameter(Mandatory)][string]$Stdout,
        [string]$Log = ''
    )
    $exe = Test-Herramienta -Nombre $Comando
    Write-Host "> $Comando $($Argumentos -join ' ')" -ForegroundColor DarkGray

    # Comillas para argumentos con espacios
    $lista = $Argumentos | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }
    $errTmp = [System.IO.Path]::GetTempFileName()
    $proc = Start-Process -FilePath $exe -ArgumentList $lista -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $Stdout -RedirectStandardError $errTmp
    $mensajes = @(Get-Content -Path $errTmp -Encoding UTF8 -ErrorAction SilentlyContinue)
    Remove-Item $errTmp -ErrorAction SilentlyContinue
    $mensajes | ForEach-Object { Write-Host $_ }

    if ($Log) {
        $encabezado = @(
            "# Comando: $Comando $($Argumentos -join ' ')",
            "# Fecha:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
            "# Código de salida: $($proc.ExitCode)",
            "# Salida JSON guardada en: $Stdout",
            ''
        )
        ($encabezado + $mensajes) | Set-Content -Path $Log -Encoding UTF8
    }
    if ($proc.ExitCode -ne 0) {
        throw "$Comando terminó con código de salida $($proc.ExitCode)"
    }
}

# Lee un JSON generado por las herramientas (UTF-8)
function Read-Json {
    param([Parameter(Mandatory)][string]$Ruta)
    if (-not (Test-Path $Ruta)) { throw "No existe el archivo $Ruta" }
    return (Get-Content -Path $Ruta -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# Devuelve el resultado de "docker image inspect" como objeto
function Read-JsonDesdeDocker {
    param([Parameter(Mandatory)][string]$Referencia)
    $ErrorActionPreference = 'Continue'
    $texto = (& docker image inspect $Referencia 2>&1 | ForEach-Object { "$_" }) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "No se pudo inspeccionar la imagen ${Referencia}: $texto" }
    return @($texto | ConvertFrom-Json)[0]
}

# Resumen de un SBOM CycloneDX: total de componentes y conteo por tipo
function Show-ResumenSbom {
    param([Parameter(Mandatory)][string]$Ruta)
    $sbom = Read-Json -Ruta $Ruta
    $componentes = @($sbom.components)
    Write-Host ''
    Write-Host "Resumen de $Ruta" -ForegroundColor Cyan
    Write-Host "  Formato: CycloneDX $($sbom.specVersion)"
    Write-Host "  Componentes: $($componentes.Count)"
    if ($componentes.Count -gt 0) {
        $componentes | Group-Object type | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("    - {0,-12} {1}" -f $_.Name, $_.Count)
        }
    }
    return $componentes.Count
}

# Valida el formato registro/repositorio@sha256:<64 hex>
function Assert-ImageDigest {
    param([Parameter(Mandatory)][string]$Referencia)
    if ($Referencia -notmatch '^[a-z0-9.\-]+(:[0-9]+)?/[a-z0-9._/\-]+@sha256:[a-f0-9]{64}$') {
        throw ("Referencia inválida: '$Referencia'. Debe ser por digest y en minúsculas, por ejemplo " +
               "ghcr.io/usuario/laboratorio-sbom-slsa@sha256:<64 caracteres hex>. " +
               "Firma siempre por digest, nunca por tag: el tag puede moverse.")
    }
}
