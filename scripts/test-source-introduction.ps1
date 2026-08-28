[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = 'ef8575e6b8579d85000f1730eafba3c1e3161c42553f737b401e9daa7e8c9eb6'
$expectedContractSha256 = '4a0530398d45d70664e5a275218d2b5a73d269d5b90748b75b37b07f18555319'
$expectedPythonAcceptanceRootSha256 = 'd50d004a8155092d5c4ff04c832a7192c0e3d1225374e1cc35eaf8477187b3f8'

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
