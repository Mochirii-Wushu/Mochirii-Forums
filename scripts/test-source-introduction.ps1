[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$checker = Join-Path $repositoryRoot 'scripts/check-source-introduction.ps1'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'mochirii-forums-source-contract-' + [Guid]::NewGuid().ToString('N')
)

function Copy-Fixture {
    $operations = Join-Path $fixtureRoot 'docs/operations'
    New-Item -ItemType Directory -Path $operations -Force | Out-Null
    @(
        'source-introduction.v1.json',
        'runtime-config.v1.example.json',
        'backup-restore-contract.v1.json',
        'forum-central-identity.consumer.v1.json',
        'repository-capabilities.v1.json',
        'third-party-components.v1.json',
        'upstream-provenance.v1.json'
    ) | ForEach-Object {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot "docs/operations/$_") `
            -Destination (Join-Path $operations $_)
    }
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Mutate
    )

    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
    Copy-Fixture
    & $Mutate

    $rejected = $false
    try {
        & $checker -RepositoryRoot $fixtureRoot | Out-Null
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Source-introduction contract accepted prohibited fixture: $Name"
    }
}

try {
    Copy-Fixture
    & $checker -RepositoryRoot $fixtureRoot | Out-Null

    Assert-Rejected -Name 'source-imported' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/source-introduction.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.upstream.sourceImported = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'scalar-string-array-coercion' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.protocol.signatureAlgorithm = @('HMAC-SHA256')
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'empty-array-null-coercion' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/source-introduction.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.customizationBoundary.plugins = $null
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'source-authorization-string-coercion' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/source-introduction.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.providerMutationAuthorized = 'false'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'source-additive-deployment-authorization' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/source-introduction.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document | Add-Member -NotePropertyName deploymentAuthorized `
            -NotePropertyValue $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'vendored-core-enabled' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/source-introduction.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.historyPreservation.vendoredCoreAllowed = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'public-exposure-enabled' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.runtime.publicExposureEnabled = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'runtime-additive-deployment-approval' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.runtime | Add-Member -NotePropertyName publicDeploymentApproved `
            -NotePropertyValue $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'resolved-local-hostname' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.runtime.hostname = '127.0.0.1'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'shared-mount-drift' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.layout.containerPersistentPath = '/tmp/shared'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'installer-network-pipe-enabled' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.installer.directNetworkPipeExecutionAllowed = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'installer-inputs-claimed-pinned' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.installer.transitiveInputsPinned = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'insufficient-swap' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.resources.minimum.swapMiB = 1024
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'smtp-enabled-before-approval' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.runtime.mailEnabled = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'civil-timezone-drift' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.time.civilTimeZone = 'UTC'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'non-iana-display-timezone' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.time.displayTimeZone = 'Etc/GMT' + '-8'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'display-offset-not-derived-from-iana' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.time.displayOffsetDerivedFromIanaAtInstant = $false
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'timezone-verification-overclaim' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.time.runtimeVerified = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'timezone-supported-authority-overclaim' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.time.supportedSiteWideAuthorityIdentified = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'timezone-unreviewed-configuration-artifact' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.time.supportedConfigurationArtifact = 'unreviewed-time-config'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    foreach ($activationGate in @(
        'soleIanaTimeAuthorityImplemented',
        'soleIanaTimeAuthorityBrowserTested'
    )) {
        Assert-Rejected -Name "timezone-activation-overclaim-$activationGate" -Mutate {
            $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
            $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
            $document.activation.$activationGate = $true
            $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
        }
    }

    Assert-Rejected -Name 'runtime-activation-additive-gate' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.activation | Add-Member -NotePropertyName alternateTimeApproved `
            -NotePropertyValue $false
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'timezone-additive-display-authority' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.time | Add-Member -NotePropertyName alternateDisplayTimeZone `
            -NotePropertyValue 'UTC'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    foreach ($timeField in @(
        @{ Name = 'civil-timezone-array-shape'; Property = 'civilTimeZone'; Value = @('Asia/Singapore') }
        @{ Name = 'business-calendar-timezone-array-shape'; Property = 'businessCalendarTimeZone'; Value = @('Asia/Singapore') }
        @{ Name = 'display-timezone-array-shape'; Property = 'displayTimeZone'; Value = @('Asia/Singapore') }
        @{ Name = 'scheduler-timezone-array-shape'; Property = 'schedulerTimeZone'; Value = @('Asia/Singapore') }
        @{ Name = 'storage-timezone-array-shape'; Property = 'storageTimeZone'; Value = @('UTC') }
        @{ Name = 'protocol-timezone-array-shape'; Property = 'protocolTimeZone'; Value = @('UTC') }
    )) {
        Assert-Rejected -Name $timeField.Name -Mutate {
            $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
            $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
            $document.time.($timeField.Property) = $timeField.Value
            $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
        }
    }

    foreach ($runtimeVerifiedCase in @(
        @{ Name = 'timezone-verification-numeric-coercion'; Value = 0 }
        @{ Name = 'timezone-verification-string-coercion'; Value = 'false' }
        @{ Name = 'timezone-verification-array-coercion'; Value = @($false) }
    )) {
        Assert-Rejected -Name $runtimeVerifiedCase.Name -Mutate {
            $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
            $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
            $document.time.runtimeVerified = $runtimeVerifiedCase.Value
            $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
        }
    }

    Assert-Rejected -Name 'public-database-exposure' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.network.databasePublicExposureEnabled = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'workstation-runtime-dependency' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.workstationIndependence.workstationRuntimeDependencyAllowed = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'health-claimed-passed' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.health.passed = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'resolved-secret-placeholder' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.secrets.applicationSecret = 'resolved-regression-placeholder'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'unreviewed-core-revision' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/third-party-components.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.application.revision = '1111111111111111111111111111111111111111'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'unreviewed-supported-release-selection' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/third-party-components.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.supportedReleaseObservation.selectedForRuntime = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'unapproved-plugin' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/third-party-components.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.plugins = @(@{ repository = 'https://example.invalid/plugin.git' })
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'core-time-authority-overclaim' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/third-party-components.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.timeBehaviorObservation.siteWideDisplayAuthorityProvidedByCore = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'core-time-evidence-drift' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/third-party-components.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.timeBehaviorObservation.evidenceFiles[0].sha256 = '0' * 64
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'core-time-additive-authority-overclaim' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/third-party-components.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.timeBehaviorObservation | Add-Member `
            -NotePropertyName alternateAuthorityApproved -NotePropertyValue $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'core-time-evidence-additive-field' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/third-party-components.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.timeBehaviorObservation.evidenceFiles[0] | Add-Member `
            -NotePropertyName alternateSource -NotePropertyValue 'unreviewed'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-custom-core-plugin' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.protocol.customCorePluginAllowed = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-required-boolean-string-coercion' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.security.producerConstantTimeSignatureComparisonRequired = 'true'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-authorization-numeric-coercion' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.providerMutationAuthorized = 0
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-activation-string-coercion' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.activation.enabled = 'false'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-activation-extra-gate' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.activation | Add-Member -NotePropertyName unexpectedApproved -NotePropertyValue $false
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-privilege-field' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.responseEnvelope.payloadForbiddenFields = @('moderator')
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-consumer-enabled' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.consumerSettings.enableDiscourseConnect = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-payload-serialization-drift' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.protocol.payloadSerialization = 'application/json'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-duplicate-query-value-ambiguity' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.requestEnvelope.exactOneValuePerQueryKeyRequired = $false
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-extra-query-key-ambiguity' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.responseEnvelope.additionalQueryKeysAllowed = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'identity-logging-risk-overclaimed' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/forum-central-identity.consumer.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.security.pinnedConsumerGenericFailureMayLogDiagnostics = $false
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'private-free-ruleset-overclaim' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/repository-capabilities.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.enforcement.privateRepositoryRulesetsAssumed = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'capability-additive-provider-override' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/repository-capabilities.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.readback | Add-Member -NotePropertyName providerOverride `
            -NotePropertyValue 'allowed'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'private-workflow-usage-underclaim' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/repository-capabilities.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.usage.privateWorkflowRunsConsumeSharedActionsMinutes = $false
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'backup-without-uploads' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/backup-restore-contract.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.backup.applicationBackupIncludesUploadsRequired = $false
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'runnable-app-config' -Mutate {
        Set-Content -LiteralPath (Join-Path $fixtureRoot 'app.yml') `
            -Value 'regression fixture' -Encoding utf8
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

Write-Host 'Isolated source-introduction regression fixtures passed.'
