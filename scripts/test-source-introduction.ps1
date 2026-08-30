[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = '64226a8ba1d1e2da93a6316668a45538ca52478bbc715d1ec85c86625c9f38e2'
$expectedContractSha256 = 'a3252b4316abec528ed9e87d09a02ff2283adccbc2bf63a4a551dba88dd203bb'
$expectedPythonAcceptanceRootSha256 = '548dddd41f227181b54f695ab11f3c1247dd2aca9fc301c8bb7000cc7fc425e4'

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
