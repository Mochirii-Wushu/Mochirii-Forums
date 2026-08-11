[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repositoryRoot

$requiredFiles = @(
    '.gitattributes'
    '.github/CODEOWNERS'
    '.github/dependabot.yml'
    '.github/pull_request_template.md'
    '.github/workflows/inspect-upstream.yml'
    '.github/workflows/validate-repository.yml'
    '.gitignore'
    'AGENTS.md'
    'CODE_OF_CONDUCT.md'
    'CONTRIBUTING.md'
    'README.md'
    'SECURITY.md'
    'docs/adr/0001-clean-initialization-and-canonical-ownership.md'
    'docs/adr/0002-pull-only-upstream-and-source-introduction.md'
    'docs/adr/0003-supported-source-introduction-packet.md'
    'docs/operations/SOURCE-INTRODUCTION-READINESS.md'
    'docs/operations/CURRENT-STATE.md'
    'docs/operations/RELEASE-EVIDENCE.md'
    'docs/operations/RUNTIME-READINESS.md'
    'docs/operations/SOURCE-PROVENANCE.md'
    'docs/operations/backup-restore-contract.v1.json'
    'docs/operations/customizations.v1.json'
    'docs/operations/forum-central-identity.consumer.v1.json'
    'docs/operations/release-evidence.v1.example.json'
    'docs/operations/repository-capabilities.v1.json'
    'docs/operations/runtime-config.v1.example.json'
    'docs/operations/source-introduction.v1.json'
    'docs/operations/third-party-components.v1.json'
    'docs/operations/upstream-provenance.v1.json'
    'scripts/check-repository.ps1'
    'scripts/check-source-introduction.ps1'
    'scripts/configure-upstream.ps1'
    'scripts/test-upstream-policy.ps1'
    'scripts/test-source-introduction.ps1'
    'scripts/verify-upstream-policy.ps1'
    'scripts/verify-upstream-provenance.ps1'
)

$inventory = @(
    git ls-files --cached --others --exclude-standard |
        ForEach-Object { $_.Replace('\', '/').Trim() } |
        Where-Object { $_ }
)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to enumerate repository files.'
}

$comparison = [StringComparer]::Ordinal
$requiredSet = [Collections.Generic.HashSet[string]]::new($comparison)
$requiredFiles | ForEach-Object { [void]$requiredSet.Add($_) }

$inventorySet = [Collections.Generic.HashSet[string]]::new($comparison)
$inventory | ForEach-Object {
    if (-not $inventorySet.Add($_)) {
        throw "Duplicate normalized repository path: $_"
    }
}

$missing = @($requiredFiles | Where-Object { -not $inventorySet.Contains($_) })
$unexpected = @($inventory | Where-Object { -not $requiredSet.Contains($_) })
if ($missing.Count -gt 0) {
    throw "Required repository files are missing: $($missing -join ', ')"
}
if ($unexpected.Count -gt 0) {
    throw "Unexpected files are not allowed in the governance seed: $($unexpected -join ', ')"
}

$prohibitedNamePattern = '(?i)(^|/)(?:app\.ya?ml|dockerfile(?:\..*)?|docker-compose(?:\..*)?\.ya?ml)$|(^|/)(?:credentials?|secrets?|tokens?|passwords?|private[-_]?keys?)(?:/|\.|$)|(?:^|/).*\.(?:7z|aab|apk|app|bak|bin|bz2|cer|crt|db|der|dll|dmg|dump|exe|gz|iso|jar|key|msi|p12|pem|pfx|pkg|rar|so|sqlite\d*|tar|tgz|war|xz|zip)$'
$secretAssignmentPattern = '(?i)^\s*(?:export\s+)?(?<name>[A-Z0-9_]*(?:API_KEY|CLIENT_SECRET|PASSWORD|PRIVATE_KEY|SECRET|TOKEN)[A-Z0-9_]*)\s*[:=]\s*(?<value>.+?)\s*$'
$safeReferencePattern = '^\$\{\{\s*github\.token\s*\}\}$'
$maxBytes = 1MB
$prohibitedFixedZone = 'Etc/GMT' + '-8'
$prohibitedDisplayLabelField = 'displayTimeZone' + 'Label'

foreach ($relativePath in $inventory) {
    if ($relativePath -match $prohibitedNamePattern) {
        throw "Prohibited secret-like, runtime, archive, database, or binary path: $relativePath"
    }

    $absolutePath = Join-Path $repositoryRoot ($relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar))
    $item = Get-Item -LiteralPath $absolutePath -Force
    if ($item.PSIsContainer) {
        throw "Repository inventory unexpectedly contains a directory: $relativePath"
    }
    if ($item.LinkType) {
        throw "Symbolic links and junctions are not allowed in the governance seed: $relativePath"
    }
    if ($item.Length -gt $maxBytes) {
        throw "File exceeds the 1 MiB governance-seed limit: $relativePath"
    }

    $bytes = [IO.File]::ReadAllBytes($absolutePath)
    if ($bytes -contains 0) {
        throw "Binary or null-containing file is not allowed: $relativePath"
    }
    try {
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        $text = $strictUtf8.GetString($bytes)
    }
    catch [Text.DecoderFallbackException] {
        throw "Non-UTF-8 or binary file is not allowed: $relativePath"
    }
    if ($text -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') {
        throw "Binary control characters are not allowed: $relativePath"
    }
    if (-not $text.EndsWith("`n", [StringComparison]::Ordinal)) {
        throw "Text file must end with one newline: $relativePath"
    }
    if ($text.EndsWith("`n`n", [StringComparison]::Ordinal) -or
        $text.EndsWith("`r`n`r`n", [StringComparison]::Ordinal)) {
        throw "Text file must not end with a blank line: $relativePath"
    }
    if ($text.StartsWith('version https://git-lfs.github.com/spec/v1', [StringComparison]::Ordinal)) {
        throw "Git LFS pointers are not allowed in the governance seed: $relativePath"
    }
    if ($text.Contains($prohibitedFixedZone, [StringComparison]::Ordinal) -or
        $text.Contains($prohibitedDisplayLabelField, [StringComparison]::Ordinal) -or
        $text -match '(?i)\b480[- ]minute\b') {
        throw "Fixed-offset or manually maintained display-time authority is not allowed: $relativePath"
    }

    $lineNumber = 0
    foreach ($line in ($text -split "`r?`n")) {
        $lineNumber++
        if ($line -match '[ \t]+$') {
            throw "Trailing whitespace is not allowed in ${relativePath}:$lineNumber"
        }
        $match = [regex]::Match($line, $secretAssignmentPattern)
        if (-not $match.Success) {
            continue
        }
        $value = $match.Groups['value'].Value.Trim()
        if ($value -notmatch $safeReferencePattern) {
            throw "Secret-like assignment is not allowed in ${relativePath}:$lineNumber"
        }
    }
}

$workflowFiles = @($inventory | Where-Object { $_ -like '.github/workflows/*.yml' -or $_ -like '.github/workflows/*.yaml' })
foreach ($workflowFile in $workflowFiles) {
    $workflowText = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot $workflowFile)
    $usesMatches = [regex]::Matches($workflowText, '(?im)^\s*-?\s*uses:\s*([^\s#]+)')
    foreach ($usesMatch in $usesMatches) {
        $reference = $usesMatch.Groups[1].Value.Trim()
        if ($reference -notmatch '@[0-9a-fA-F]{40}$') {
            throw "GitHub Action references must use a full 40-character commit SHA: $reference"
        }
    }
    if ($workflowText -match '(?im)^\s*pull_request_target\s*:') {
        throw "pull_request_target is not allowed: $workflowFile"
    }
    if ($workflowText -notmatch '(?ms)^permissions:\s*\r?\n\s+contents:\s*read\s*$') {
        throw "Workflow must declare top-level read-only contents permission: $workflowFile"
    }
}

$inspectionWorkflow = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot '.github/workflows/inspect-upstream.yml'
)
$inspectionLines = @($inspectionWorkflow -split "`r?`n")
if ($inspectionWorkflow -match "`t") {
    throw 'The upstream inspection workflow must use spaces, not YAML tabs.'
}

$blockScalarIndent = -1
foreach ($line in $inspectionLines) {
    $indent = $line.Length - $line.TrimStart(' ').Length
    if ($blockScalarIndent -ge 0) {
        if ([string]::IsNullOrWhiteSpace($line) -or $indent -gt $blockScalarIndent) {
            continue
        }
        $blockScalarIndent = -1
    }
    if ($line -match '^\s*[^#][^:]*:\s*[>|][+-]?\s*(?:#.*)?$') {
        $blockScalarIndent = $indent
        continue
    }
    $withoutExpressions = [regex]::Replace($line, '\$\{\{.*?\}\}', '')
    if ($withoutExpressions -match '[\{\}\[\]]') {
        throw 'Flow-style YAML collections are not allowed in the upstream inspection workflow.'
    }
}

$onHeaders = @($inspectionLines | Where-Object {
    $_ -match '^(?:on|''on''|"on")\s*:'
})
if ($onHeaders.Count -ne 1 -or $onHeaders[0] -cne "'on':") {
    throw 'The upstream inspection workflow must contain one exact block-style on section.'
}
$onIndex = [Array]::IndexOf($inspectionLines, "'on':")
$onBlock = [Collections.Generic.List[string]]::new()
for ($index = $onIndex + 1; $index -lt $inspectionLines.Count; $index++) {
    $line = $inspectionLines[$index]
    if ($line -match '^\S') {
        break
    }
    if (-not [string]::IsNullOrWhiteSpace($line) -and $line -notmatch '^\s*#') {
        $onBlock.Add($line)
    }
}
$expectedOnBlock = @(
    '  workflow_dispatch:',
    '  schedule:',
    "    - cron: '17 22 3 * *'",
    '      timezone: Asia/Singapore'
)
if (($onBlock -join "`n") -cne ($expectedOnBlock -join "`n")) {
    throw 'The upstream inspection workflow must use the exact manual plus monthly Asia/Singapore schedule.'
}

$permissionHeaders = @($inspectionLines | Where-Object {
    $_ -match '^\s*(?:permissions|''permissions''|"permissions")\s*:'
})
if ($permissionHeaders.Count -ne 1 -or $permissionHeaders[0] -cne 'permissions:') {
    throw 'The upstream inspection workflow must contain one block-style permissions section.'
}
$permissionsIndex = [Array]::IndexOf($inspectionLines, 'permissions:')
$permissionsBlock = [Collections.Generic.List[string]]::new()
for ($index = $permissionsIndex + 1; $index -lt $inspectionLines.Count; $index++) {
    $line = $inspectionLines[$index]
    if ($line -match '^\S') {
        break
    }
    if (-not [string]::IsNullOrWhiteSpace($line) -and $line -notmatch '^\s*#') {
        $permissionsBlock.Add($line)
    }
}
if ($permissionsBlock.Count -ne 1 -or $permissionsBlock[0] -cne '  contents: read') {
    throw 'The upstream inspection workflow permission set must equal contents read only.'
}
if ($inspectionWorkflow -match '(?im)^\s*(?:environment|''environment''|"environment"|secrets|''secrets''|"secrets")\s*:') {
    throw 'The upstream inspection workflow must not bind an environment or secrets.'
}
if ($inspectionWorkflow -match '(?im)^\s*(?:git\s+push|gh\s+(?:pr|release)|docker\s+push)\b' -or
    $inspectionWorkflow -match '(?i)actions/(?:upload-artifact|cache)@') {
    throw 'The upstream inspection workflow must not push, open a PR/release, or publish/cache artifacts.'
}

$inspectionUses = @(
    [regex]::Matches($inspectionWorkflow, '(?im)^\s*-?\s*uses:\s*([^\s#]+)') |
        ForEach-Object { $_.Groups[1].Value.Trim() }
)
if (($inspectionUses -join "`n") -cne
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' -or
    $inspectionWorkflow -notmatch '(?m)^\s+fetch-depth:\s+1\s*$' -or
    $inspectionWorkflow -notmatch '(?m)^\s+persist-credentials:\s+false\s*$' -or
    $inspectionWorkflow -notmatch '(?m)^\s+ref:\s+\$\{\{ github\.sha \}\}\s*$') {
    throw 'The upstream inspection workflow checkout must use exact immutable v7.0.1 settings.'
}

function Assert-InspectionWorkflowExpressions {
    param([Parameter(Mandatory)][string]$WorkflowText)

    $expressions = @(
        [regex]::Matches($WorkflowText, '\$\{\{\s*(?<expression>.*?)\s*\}\}') |
            ForEach-Object { $_.Groups['expression'].Value.Trim() }
    )
    $expectedExpressions = @('github.ref', 'github.sha', 'github.sha')
    if (($expressions | Sort-Object) -join "`n" -cne
        (($expectedExpressions | Sort-Object) -join "`n")) {
        throw 'The upstream inspection workflow may use only the reviewed GitHub ref and exact repeated SHA expressions.'
    }
}

Assert-InspectionWorkflowExpressions -WorkflowText $inspectionWorkflow
$secretExpressionFixture = $inspectionWorkflow.Replace(
    '${{ github.ref }}',
    '${{ secrets.REGRESSION_FIXTURE }}'
)
$secretExpressionRejected = $false
try {
    Assert-InspectionWorkflowExpressions -WorkflowText $secretExpressionFixture
}
catch {
    $secretExpressionRejected = $true
}
if (-not $secretExpressionRejected) {
    throw 'The workflow-expression contract did not reject the secret-context fixture.'
}

$dependabotText = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot '.github/dependabot.yml'
)
$dependabotLines = @(
    $dependabotText -split "`r?`n" | Where-Object { $_ -cne '' }
)
$expectedDependabotLines = @(
    'version: 2',
    'updates:',
    '  - package-ecosystem: github-actions',
    '    directory: /',
    '    schedule:',
    '      interval: monthly',
    '      time: "22:43"',
    '      timezone: Asia/Singapore',
    '    target-branch: main',
    '    open-pull-requests-limit: 5'
)
if (($dependabotLines -join "`n") -cne ($expectedDependabotLines -join "`n")) {
    throw 'Dependabot must use the exact monthly Asia/Singapore schedule.'
}

$customizationsPath = Join-Path $repositoryRoot 'docs/operations/customizations.v1.json'
$customizations = Get-Content -Raw -LiteralPath $customizationsPath | ConvertFrom-Json
if ($customizations.schemaVersion -ne 1 -or
    $customizations.status -cne 'no-runtime-customizations-approved' -or
    @($customizations.plugins).Count -ne 0 -or
    @($customizations.themes).Count -ne 0 -or
    @($customizations.integrations).Count -ne 0) {
    throw 'The governance seed customization manifest must remain explicitly empty.'
}

$releaseEvidencePath = Join-Path $repositoryRoot 'docs/operations/release-evidence.v1.example.json'
$releaseEvidence = Get-Content -Raw -LiteralPath $releaseEvidencePath | ConvertFrom-Json
if ($releaseEvidence.schemaVersion -ne 1 -or
    $releaseEvidence.repository -cne 'Mochirii-Wushu/Mochirii-Forums' -or
    $null -ne $releaseEvidence.source.reviewedHeadCommit -or
    $null -ne $releaseEvidence.artifacts.packageOrImageDigest -or
    $null -ne $releaseEvidence.change.approvalReference -or
    $null -ne $releaseEvidence.rollback.invoked) {
    throw 'The release-evidence example must retain explicit incomplete placeholders.'
}

$scriptFiles = @($inventory | Where-Object { $_ -like 'scripts/*.ps1' })
foreach ($scriptFile in $scriptFiles) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repositoryRoot $scriptFile),
        [ref]$tokens,
        [ref]$parseErrors
    ) | Out-Null
    if ($parseErrors.Count -gt 0) {
        $messages = @($parseErrors | ForEach-Object { $_.Message })
        throw "PowerShell parsing failed for ${scriptFile}: $($messages -join '; ')"
    }
}

$provenanceVerifierText = Get-Content -Raw -LiteralPath (
    Join-Path $repositoryRoot 'scripts/verify-upstream-provenance.ps1'
)
$boundedDownloadCalls = @(
    [regex]::Matches($provenanceVerifierText, '(?m)Get-RemoteBytes -Client[^\r\n]+') |
        ForEach-Object { $_.Value }
)
if ($provenanceVerifierText -match 'GetByteArrayAsync' -or
    $provenanceVerifierText -notmatch 'ResponseHeadersRead' -or
    $boundedDownloadCalls.Count -ne 9 -or
    @($boundedDownloadCalls | Where-Object { $_ -notmatch '-MaxBytes\s+' }).Count -ne 0) {
    throw 'Every online provenance response must use the reviewed bounded streaming reader.'
}

& (Join-Path $repositoryRoot 'scripts/verify-upstream-provenance.ps1') `
    -RepositoryRoot $repositoryRoot

& (Join-Path $repositoryRoot 'scripts/test-upstream-policy.ps1')

& (Join-Path $repositoryRoot 'scripts/check-source-introduction.ps1')

& (Join-Path $repositoryRoot 'scripts/test-source-introduction.ps1')

$diffCheck = & git diff --check 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "git diff --check failed:`n$($diffCheck -join "`n")"
}

Write-Host "Repository contract passed for $($inventory.Count) allowlisted files."
