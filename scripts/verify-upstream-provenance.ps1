[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$Online,
    [switch]$RequireCurrentMain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$arguments = @('-B', (Join-Path $RepositoryRoot 'scripts/verify-pinned-source.py'))
if ($Online) {
    $arguments += '--online'
}
if ($RequireCurrentMain) {
    if (-not $Online) {
        throw '-RequireCurrentMain also requires -Online.'
    }
    $arguments += '--require-current-main'
}
& python @arguments
if ($LASTEXITCODE -ne 0) {
    throw 'Pinned upstream verification failed.'
}
$pythonResidue = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -Force |
        Where-Object {
            $_.Name -eq '__pycache__' -or
            (-not $_.PSIsContainer -and $_.Extension -in @('.pyc', '.pyo'))
        }
)
if ($pythonResidue.Count -gt 0) {
    throw 'Generated Python bytecode residue entered the upstream-verification boundary.'
}
