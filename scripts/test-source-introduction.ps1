[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = 'c8ccd1bf58d7aab6df47a3f742c16fd847a86706dd4f60cb9a2606551953d780'
$expectedContractSha256 = 'd423698bad0758dc79702f74611bd2405d1e97b55fa3caf5d144ffde36edf930'
$expectedPythonAcceptanceRootSha256 = '52ac010efcdb86faf16e86ccdcf7d3ab7d570109816524274fb156215af3468d'

function Get-PythonAcceptanceRootSha256 {
    param(
        [Parameter(Mandatory)][string]$ValidatorSha256,
        [Parameter(Mandatory)][string]$ContractSha256
    )
    $material = [Text.Encoding]::ASCII.GetBytes(
        'mochirii-forums-python-acceptance-root-v1' +
        [char]0 + $ValidatorSha256 + [char]0 + $ContractSha256 + [char]10
    )
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($material)
    ).ToLowerInvariant()
}

if ((Get-PythonAcceptanceRootSha256 -ValidatorSha256 $expectedValidatorSha256 -ContractSha256 $expectedContractSha256) -ne $expectedPythonAcceptanceRootSha256) {
    throw 'Trusted Python acceptance root differs.'
}
$contractPath = Join-Path $RepositoryRoot 'scripts/test-contracts.py'
$contract = Get-Item -LiteralPath $contractPath -Force
if (
    $contract.PSIsContainer -or
    $null -ne $contract.LinkType -or
    $contract.Length -le 0 -or
    $contract.Length -gt 1048576 -or
    (Get-FileHash -LiteralPath $contract.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedContractSha256
) {
    throw 'Trusted hostile-fixture source differs.'
}
& python -I -S -B $contract.FullName
if ($LASTEXITCODE -ne 0) {
    throw 'Source-introduction hostile fixtures failed.'
}
$pythonResidue = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -Force |
        Where-Object {
            $_.Name -eq '__pycache__' -or
            (-not $_.PSIsContainer -and $_.Extension -in @('.pyc', '.pyo'))
        }
)
if ($pythonResidue.Count -gt 0) {
    throw 'Generated Python bytecode residue entered the hostile-fixture boundary.'
}
