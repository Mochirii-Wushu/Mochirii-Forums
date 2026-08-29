[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = 'bdeec1910320e8820718692c6a5e9a3b14a48747e6765dfb2881c87d2963deb2'
$expectedContractSha256 = '9c714f98d76bb322fe2b8d5fbbf9af3b8994b789fbdf2c33f47abdf0f57fce99'
$expectedPythonAcceptanceRootSha256 = '7028005ca157267861607a3c72e5c7c9c105baa8131a1da446605e5af575be23'

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
$validatorPath = Join-Path $RepositoryRoot 'scripts/validate-repository.py'
$validator = Get-Item -LiteralPath $validatorPath -Force
if (
    $validator.PSIsContainer -or
    $null -ne $validator.LinkType -or
    $validator.Length -le 0 -or
    $validator.Length -gt 1048576 -or
    (Get-FileHash -LiteralPath $validator.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedValidatorSha256
) {
    throw 'Trusted repository validator source differs.'
}
& python -I -S -B $validator.FullName
if ($LASTEXITCODE -ne 0) {
    throw 'Source-introduction contract failed.'
}
$pythonResidue = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -Force |
        Where-Object {
            $_.Name -eq '__pycache__' -or
            (-not $_.PSIsContainer -and $_.Extension -in @('.pyc', '.pyo'))
        }
)
if ($pythonResidue.Count -gt 0) {
    throw 'Generated Python bytecode residue entered the source-introduction boundary.'
}
