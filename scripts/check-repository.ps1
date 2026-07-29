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
    '.github/workflows/validate-repository.yml'
    '.gitignore'
    'AGENTS.md'
    'CODE_OF_CONDUCT.md'
    'CONTRIBUTING.md'
    'README.md'
    'SECURITY.md'
    'docs/adr/0001-clean-initialization-and-canonical-ownership.md'
    'docs/operations/CURRENT-STATE.md'
    'scripts/check-repository.ps1'
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

$diffCheck = & git diff --check 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "git diff --check failed:`n$($diffCheck -join "`n")"
}

Write-Host "Repository contract passed for $($inventory.Count) allowlisted files."
