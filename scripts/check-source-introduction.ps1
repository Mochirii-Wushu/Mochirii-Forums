[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = '5a21f33fd613fe4c8733deec55277943b03cf33e9d89c51339fd976409854f5f'
$expectedContractSha256 = '5ded66a3b6325c30c2fea03a9755e2d8987cec89c2c1a62000acc13a444effd0'
$expectedPythonAcceptanceRootSha256 = '243df14f0bbd001706a5de14bab276ae3142437951ad812eaca29e8f58ba381b'

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
