[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$Online,
    [switch]$RequireCurrentMain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RemoteBytes {
    param(
        [Parameter(Mandatory)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][long]$MaxBytes
    )

    if ($MaxBytes -le 0) {
        throw 'The remote-response byte bound must be positive.'
    }

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $request = $null
        $response = $null
        $stream = $null
        $buffered = $null
        try {
            $request = [Net.Http.HttpRequestMessage]::new(
                [Net.Http.HttpMethod]::Get,
                $Uri
            )
            $response = $Client.SendAsync(
                $request,
                [Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()
            $response.EnsureSuccessStatusCode() | Out-Null

            $contentLength = $response.Content.Headers.ContentLength
            if ($null -ne $contentLength -and [long]$contentLength -gt $MaxBytes) {
                throw "Remote response exceeds the reviewed byte bound: $Uri"
            }

            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $buffered = [IO.MemoryStream]::new()
            $buffer = [byte[]]::new(8192)
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                if ($buffered.Length + $read -gt $MaxBytes) {
                    throw "Remote response exceeded the reviewed byte bound while streaming: $Uri"
                }
                $buffered.Write($buffer, 0, $read)
            }
            $download = $buffered.ToArray()
            Write-Output -NoEnumerate $download
            return
        }
        catch {
            if ($attempt -eq 3) {
                throw
            }
            Start-Sleep -Seconds $attempt
        }
        finally {
            if ($null -ne $buffered) {
                $buffered.Dispose()
            }
            if ($null -ne $stream) {
                $stream.Dispose()
            }
            if ($null -ne $response) {
                $response.Dispose()
            }
            if ($null -ne $request) {
                $request.Dispose()
            }
        }
    }
}

$resolvedRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$manifestPath = Join-Path $resolvedRoot 'docs/operations/upstream-provenance.v1.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$thirdPartyPath = Join-Path $resolvedRoot 'docs/operations/third-party-components.v1.json'
$thirdParty = Get-Content -Raw -LiteralPath $thirdPartyPath | ConvertFrom-Json
$identityPath = Join-Path $resolvedRoot 'docs/operations/forum-central-identity.consumer.v1.json'
$identity = Get-Content -Raw -LiteralPath $identityPath | ConvertFrom-Json

$expectedRepository = 'https://github.com/discourse/discourse_docker.git'
$expectedPaths = @(
    'LICENSE',
    'install-discourse',
    'discourse-setup',
    'launcher',
    'samples/standalone.yml'
)
if ($manifest.schemaVersion -ne 1 -or
    $manifest.upstream.repository -cne $expectedRepository -or
    $manifest.upstream.branch -cne 'main' -or
    $manifest.upstream.revision -cne 'a3028747c5b7774f49a3b110221d96ca2b3f340d' -or
    $manifest.upstream.revisionTree -cne '1a397a459ae60c588ed79ab5db1a225fe977caf0' -or
    $manifest.upstream.revisionCommitSignatureVerified -ne $true -or
    $manifest.upstream.revisionCommitSignatureReason -cne 'valid' -or
    $manifest.upstream.license -cne 'MIT' -or
    $manifest.upstream.reviewStatus -cne 'source-only-pin-not-approved-for-install') {
    throw 'The upstream provenance header does not match the reviewed contract.'
}

if ($manifest.driftObservation.observedAt -cne '2026-08-11' -or
    $manifest.driftObservation.mainRevision -cne 'e6d7b508b43f9610950166f53cb1be1bd78435a9' -or
    $manifest.driftObservation.mainTree -cne '720f6aa67199841469b76191baae55db849c2eec' -or
    $manifest.driftObservation.mainCommitSignatureVerified -ne $true -or
    $manifest.driftObservation.mainCommitSignatureReason -cne 'valid' -or
    $manifest.driftObservation.commitsAheadOfPin -ne 11 -or
    $manifest.driftObservation.commitsBehindPin -ne 0 -or
    $manifest.driftObservation.pinIsAncestor -ne $true -or
    $manifest.driftObservation.selectedForRuntime -ne $false -or
    $manifest.driftObservation.automaticPinUpdateAllowed -ne $false -or
    $manifest.driftObservation.materialChangesReviewed -ne $false -or
    $manifest.driftObservation.materialChangesInventoryComplete -ne $false -or
    $manifest.driftObservation.materialChangesScope -cne 'notable-non-exhaustive-compatibility-gates' -or
    $manifest.driftObservation.reviewStatus -cne 'drift-detected-review-required') {
    throw 'The recorded deployment-source drift is missing, stale, or promoted.'
}

$expectedMaterialChanges = @(
    '09493049db7e4873f3dcff1356249ccf879ca6ec|postgresql-18-dump-restore|three-database-sized-copies-free-space-and-isolated-restore-rehearsal'
    '7de2cf5c5a3c41ef7d2056e216190887e7b5f59a|postgresql-18-free-disk-calculation|capacity-calculation-review-and-measured-headroom'
    'ed9f680b0df1de28f062de1769d89d22b2644d1b|single-core-cpu-detection|one-core-install-and-rebuild-compatibility-test'
    '9a064388b76beb41527b7c7b650566a5f94075aa|postgresql-18-all-databases|multi-database-preservation-and-restore-rehearsal'
    'a4d4cb41aeb6266f8cfc84b88477435629317787|debian-trixie|operating-system-and-container-compatibility-review'
    'a2351299445cf4d8946e84c1e76343d151c223fa|ruby-3.4.10|plugin-and-build-compatibility-review'
    'dfdddb8505c71b4b3b5e6a741f4e90e4a9c9e0a7|debian-redis-package|runtime-data-log-and-restart-review'
    'e6d7b508b43f9610950166f53cb1be1bd78435a9|redis-log-directory|persistent-log-path-permissions-and-restart-review'
)
$actualMaterialChanges = @(
    $manifest.driftObservation.materialChanges |
        ForEach-Object { "$($_.commit)|$($_.area)|$($_.requiredGate)" }
)
if (($actualMaterialChanges -join "`n") -cne ($expectedMaterialChanges -join "`n")) {
    throw 'The reviewed material-drift gate inventory changed.'
}

$actualPaths = @($manifest.files | ForEach-Object { "$($_.path)" })
if (($actualPaths -join "`n") -cne ($expectedPaths -join "`n")) {
    throw 'The upstream provenance file inventory is not the reviewed allowlist.'
}
foreach ($file in $manifest.files) {
    if ($file.bytes -isnot [long] -and $file.bytes -isnot [int]) {
        throw "Invalid byte count for upstream evidence path: $($file.path)"
    }
    if ([long]$file.bytes -le 0 -or "$($file.sha256)" -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid hash evidence for upstream path: $($file.path)"
    }
}

$release = $thirdParty.supportedReleaseObservation
if ($thirdParty.schemaVersion -ne 1 -or
    $thirdParty.application.repository -cne 'https://github.com/discourse/discourse.git' -or
    $thirdParty.application.licenseSpdx -cne 'GPL-2.0-or-later' -or
    $release.releaseIndex -cne 'https://releases.discourse.org/' -or
    $release.releasePage -cne 'https://releases.discourse.org/changelog/v2026.7.1/' -or
    $release.tagUrl -cne 'https://github.com/discourse/discourse/tree/v2026.7.1' -or
    $release.tag -cne 'v2026.7.1' -or
    $release.tagObjectSha1 -cne '11c70a765e46c3229d66e108883fa2d33f5d0b81' -or
    $release.tagObjectType -cne 'tag' -or
    $release.tagSignatureStatus -cne 'unsigned' -or
    $release.peeledCommitSha1 -cne 'cbf996f65aae3da1843224aa624bcd9a225931ac' -or
    $release.peeledCommitTreeSha1 -cne '0aeceebe79c4d2da8cf0fab213514335c201bfa7' -or
    $release.peeledCommitSignatureStatus -cne 'unsigned' -or
    $release.selectedForRuntime -ne $false -or
    $release.compatibilityReviewed -ne $false) {
    throw 'The Discourse release observation does not distinguish its tag object, peeled commit, and runtime-selection state.'
}

$expectedCoreEvidencePaths = @(
    'LICENSE.txt',
    'COPYRIGHT.md',
    'README.md',
    'docs/SECURITY.md',
    'lib/version.rb'
)
$actualCoreEvidencePaths = @($thirdParty.application.evidenceFiles | ForEach-Object { "$($_.path)" })
if (($actualCoreEvidencePaths -join "`n") -cne ($expectedCoreEvidencePaths -join "`n")) {
    throw 'The Discourse core evidence file inventory changed.'
}
foreach ($file in $thirdParty.application.evidenceFiles) {
    if (($file.bytes -isnot [long] -and $file.bytes -isnot [int]) -or
        [long]$file.bytes -le 0 -or
        "$($file.sha256)" -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid core evidence for path: $($file.path)"
    }
}

$expectedTimeEvidencePaths = @(
    'config/application.rb',
    'plugins/discourse-local-dates/config/settings.yml',
    'plugins/discourse-local-dates/assets/javascripts/lib/format-local-date.js',
    'plugins/discourse-local-dates/assets/javascripts/discourse/components/modal/local-dates-create.gjs',
    'plugins/discourse-calendar/assets/javascripts/discourse/components/event-date.gjs'
)
$actualTimeEvidencePaths = @(
    $thirdParty.timeBehaviorObservation.evidenceFiles |
        ForEach-Object { "$($_.path)" }
)
if ($thirdParty.timeBehaviorObservation.coreCommit -cne $release.peeledCommitSha1 -or
    ($actualTimeEvidencePaths -join "`n") -cne ($expectedTimeEvidencePaths -join "`n")) {
    throw 'The pinned core time-behavior evidence inventory changed.'
}
foreach ($file in $thirdParty.timeBehaviorObservation.evidenceFiles) {
    if (($file.bytes -isnot [long] -and $file.bytes -isnot [int]) -or
        [long]$file.bytes -le 0 -or
        "$($file.sha256)" -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid pinned core time-behavior evidence for path: $($file.path)"
    }
}

$expectedIdentityEvidencePaths = @(
    'lib/discourse_connect_base.rb',
    'app/models/discourse_connect.rb',
    'app/controllers/session_controller.rb',
    'config/site_settings.yml'
)
$actualIdentityEvidencePaths = @(
    $identity.pinnedCoreEvidence.evidenceFiles |
        ForEach-Object { "$($_.path)" }
)
if ($identity.pinnedCoreEvidence.commit -cne $release.peeledCommitSha1 -or
    ($actualIdentityEvidencePaths -join "`n") -cne ($expectedIdentityEvidencePaths -join "`n")) {
    throw 'The pinned DiscourseConnect evidence inventory changed.'
}
foreach ($file in $identity.pinnedCoreEvidence.evidenceFiles) {
    if (($file.bytes -isnot [long] -and $file.bytes -isnot [int]) -or
        [long]$file.bytes -le 0 -or
        "$($file.sha256)" -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid pinned DiscourseConnect evidence for path: $($file.path)"
    }
}

if ($RequireCurrentMain -and -not $Online) {
    throw '-RequireCurrentMain also requires -Online.'
}

if ($Online) {
    $client = [Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(15)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Mochirii-Forums-Upstream-Verification/1.0')
    try {
        foreach ($file in $manifest.files) {
            $uri = "https://raw.githubusercontent.com/discourse/discourse_docker/$($manifest.upstream.revision)/$($file.path)"
            $bytes = Get-RemoteBytes -Client $client -Uri $uri -MaxBytes ([long]$file.bytes)
            $sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
            if ($bytes.Length -ne [long]$file.bytes -or $sha256 -cne "$($file.sha256)") {
                throw "Downloaded bytes do not match reviewed evidence: $($file.path)"
            }
        }

        $pinCommitUri = "https://api.github.com/repos/discourse/discourse_docker/git/commits/$($manifest.upstream.revision)"
        $pinCommitBytes = Get-RemoteBytes -Client $client -Uri $pinCommitUri -MaxBytes 131072
        $pinCommit = [Text.Encoding]::UTF8.GetString($pinCommitBytes) | ConvertFrom-Json
        if ($pinCommit.sha -cne $manifest.upstream.revision -or
            $pinCommit.tree.sha -cne $manifest.upstream.revisionTree -or
            $pinCommit.verification.verified -ne $manifest.upstream.revisionCommitSignatureVerified -or
            $pinCommit.verification.reason -cne $manifest.upstream.revisionCommitSignatureReason) {
            throw 'The official pinned deployment commit, tree, or signature does not match reviewed evidence.'
        }

        foreach ($file in $thirdParty.application.evidenceFiles) {
            $uri = "https://raw.githubusercontent.com/discourse/discourse/$($release.peeledCommitSha1)/$($file.path)"
            $bytes = Get-RemoteBytes -Client $client -Uri $uri -MaxBytes ([long]$file.bytes)
            $sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
            if ($bytes.Length -ne [long]$file.bytes -or $sha256 -cne "$($file.sha256)") {
                throw "Downloaded core bytes do not match reviewed evidence: $($file.path)"
            }
            if ($file.path -ceq 'lib/version.rb') {
                $versionText = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
                if ($versionText -notmatch '(?m)^\s*STRING = "2026\.7\.1"\s*$') {
                    throw 'The reviewed core version file does not declare version 2026.7.1.'
                }
            }
        }


        foreach ($file in $thirdParty.timeBehaviorObservation.evidenceFiles) {
            $uri = "https://raw.githubusercontent.com/discourse/discourse/$($release.peeledCommitSha1)/$($file.path)"
            $bytes = Get-RemoteBytes -Client $client -Uri $uri -MaxBytes ([long]$file.bytes)
            $sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
            if ($bytes.Length -ne [long]$file.bytes -or $sha256 -cne "$($file.sha256)") {
                throw "Downloaded core time-behavior bytes do not match reviewed evidence: $($file.path)"
            }
        }


        foreach ($file in $identity.pinnedCoreEvidence.evidenceFiles) {
            $uri = "https://raw.githubusercontent.com/discourse/discourse/$($release.peeledCommitSha1)/$($file.path)"
            $bytes = Get-RemoteBytes -Client $client -Uri $uri -MaxBytes ([long]$file.bytes)
            $sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
            if ($bytes.Length -ne [long]$file.bytes -or $sha256 -cne "$($file.sha256)") {
                throw "Downloaded DiscourseConnect bytes do not match reviewed evidence: $($file.path)"
            }
        }

        if ($RequireCurrentMain) {
            $headLine = @(& git ls-remote $expectedRepository refs/heads/main 2>$null)
            if ($LASTEXITCODE -ne 0 -or $headLine.Count -ne 1 -or
                $headLine[0] -notmatch '^(?<sha>[0-9a-f]{40})\s+refs/heads/main$') {
                throw 'Unable to read the official upstream main revision.'
            }
            if ($Matches['sha'] -cne $manifest.driftObservation.mainRevision) {
                throw 'Official upstream main moved beyond the recorded drift observation.'
            }

            $mainCommitUri = "https://api.github.com/repos/discourse/discourse_docker/git/commits/$($manifest.driftObservation.mainRevision)"
            $mainCommitBytes = Get-RemoteBytes -Client $client -Uri $mainCommitUri -MaxBytes 131072
            $mainCommit = [Text.Encoding]::UTF8.GetString($mainCommitBytes) | ConvertFrom-Json
            if ($mainCommit.sha -cne $manifest.driftObservation.mainRevision -or
                $mainCommit.tree.sha -cne $manifest.driftObservation.mainTree -or
                $mainCommit.verification.verified -ne $manifest.driftObservation.mainCommitSignatureVerified -or
                $mainCommit.verification.reason -cne $manifest.driftObservation.mainCommitSignatureReason) {
                throw 'The official observed deployment main commit, tree, or signature changed.'
            }

            $compareUri = "https://api.github.com/repos/discourse/discourse_docker/compare/$($manifest.upstream.revision)...$($manifest.driftObservation.mainRevision)"
            $compareBytes = Get-RemoteBytes -Client $client -Uri $compareUri -MaxBytes 8388608
            $compare = [Text.Encoding]::UTF8.GetString($compareBytes) | ConvertFrom-Json
            if ($compare.status -cne 'ahead' -or
                $compare.ahead_by -ne $manifest.driftObservation.commitsAheadOfPin -or
                $compare.behind_by -ne $manifest.driftObservation.commitsBehindPin -or
                $compare.total_commits -ne $manifest.driftObservation.commitsAheadOfPin -or
                $compare.base_commit.sha -cne $manifest.upstream.revision -or
                $compare.merge_base_commit.sha -cne $manifest.upstream.revision) {
                throw 'The official deployment-source comparison does not match the recorded drift relationship.'
            }
            $compareCommitSet = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal
            )
            foreach ($commit in @($compare.commits)) {
                [void]$compareCommitSet.Add("$($commit.sha)")
            }
            foreach ($materialChange in @($manifest.driftObservation.materialChanges)) {
                if (-not $compareCommitSet.Contains("$($materialChange.commit)")) {
                    throw "Recorded material drift commit is not in the official pin-to-main range: $($materialChange.commit)"
                }
            }
        }

        $releaseRepository = "$($thirdParty.application.repository)"
        $releaseRef = "refs/tags/$($release.tag)"
        $peeledReleaseRef = "$releaseRef^{}"
        $releaseLines = @(
            & git ls-remote --tags $releaseRepository $releaseRef $peeledReleaseRef 2>$null |
                ForEach-Object { "$_".Trim() } |
                Where-Object { $_ } |
                Sort-Object
        )
        $expectedReleaseLines = @(
            "$($release.tagObjectSha1)`t$releaseRef",
            "$($release.peeledCommitSha1)`t$peeledReleaseRef"
        ) | Sort-Object
        if ($LASTEXITCODE -ne 0 -or
            ($releaseLines -join "`n") -cne ($expectedReleaseLines -join "`n")) {
            throw 'The observed Discourse annotated tag object or peeled commit changed.'
        }

        $tagApiUri = "https://api.github.com/repos/discourse/discourse/git/tags/$($release.tagObjectSha1)"
        $tagBytes = Get-RemoteBytes -Client $client -Uri $tagApiUri -MaxBytes 131072
        $tagObject = [Text.Encoding]::UTF8.GetString($tagBytes) | ConvertFrom-Json
        if ($tagObject.tag -cne $release.tag -or
            $tagObject.object.type -cne 'commit' -or
            $tagObject.object.sha -cne $release.peeledCommitSha1 -or
            $tagObject.verification.verified -ne $false -or
            $tagObject.verification.reason -cne 'unsigned') {
            throw 'The official annotated tag object does not match the recorded unsigned tag evidence.'
        }

        $commitApiUri = "https://api.github.com/repos/discourse/discourse/git/commits/$($release.peeledCommitSha1)"
        $commitBytes = Get-RemoteBytes -Client $client -Uri $commitApiUri -MaxBytes 131072
        $commitObject = [Text.Encoding]::UTF8.GetString($commitBytes) | ConvertFrom-Json
        if ($commitObject.sha -cne $release.peeledCommitSha1 -or
            $commitObject.tree.sha -cne $release.peeledCommitTreeSha1 -or
            $commitObject.verification.verified -ne $false -or
            $commitObject.verification.reason -cne 'unsigned') {
            throw 'The official peeled commit or tree does not match the recorded unsigned commit evidence.'
        }
    }
    finally {
        $client.Dispose()
    }
}

$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
$manifestSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($manifestBytes)
).ToLowerInvariant()
Write-Host "Upstream provenance passed (manifest sha256: $manifestSha256)."
