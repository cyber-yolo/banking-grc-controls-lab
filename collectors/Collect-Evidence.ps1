<#
.SYNOPSIS
  Collects control evidence from Microsoft Graph, Azure and Purview, read-only.

.DESCRIPTION
  Reads collectors/items.csv and, for each item, calls the source and writes a
  JSON envelope to evidence/runs/<UTC timestamp>/ (git-ignored). Writes a
  manifest with a SHA-256 hash of every file, so that a reviewer can check the
  evidence was not changed after collection.

  Read-only by design: Graph scopes are *.Read.*, Azure calls are GET, Purview
  cmdlets are Get-*. The script never changes configuration.

.EXAMPLE
  ./collectors/Collect-Evidence.ps1 -ResourceGroup rg-bgcl-grc -Workspace law-bgcl -WorkspaceId <workspace-customer-id>

.EXAMPLE
  ./collectors/Collect-Evidence.ps1 -Item ConditionalAccessPolicies,BreakGlassUsers -SkipAzure -SkipPurview
#>
[CmdletBinding()]
param(
    [string[]] $Item,
    [string]   $ResourceGroup,
    [string]   $Workspace,
    [string]   $WorkspaceId,
    [string]   $OutputRoot = 'evidence/runs',
    [switch]   $SkipGraph,
    [switch]   $SkipAzure,
    [switch]   $SkipPurview
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot  = Split-Path -Parent $PSScriptRoot
$items     = Import-Csv (Join-Path $PSScriptRoot 'items.csv') | Where-Object { $_.method -in 'graph', 'az', 'az-rest', 'kql', 'ipps' }
if ($Item) { $items = $items | Where-Object { $_.item -in $Item } }
if ($SkipGraph)   { $items = $items | Where-Object { $_.method -ne 'graph' } }
if ($SkipAzure)   { $items = $items | Where-Object { $_.method -notin 'az', 'az-rest', 'kql' } }
if ($SkipPurview) { $items = $items | Where-Object { $_.method -ne 'ipps' } }

$runId  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmZ')
$outDir = Join-Path $repoRoot (Join-Path $OutputRoot $runId)
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

function Save-Envelope {
    param($Row, $Value, [string] $Status = 'ok', [string] $ErrorText = $null)
    $envelope = [ordered]@{
        item         = $Row.item
        method       = $Row.method
        target       = $Row.target
        collected_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        status       = $Status
        error        = $ErrorText
        value        = @($Value)
    }
    $envelope | ConvertTo-Json -Depth 30 | Set-Content -Encoding utf8 -Path (Join-Path $outDir $Row.output)
}

function Get-GraphAll {
    param([string] $Path)
    $uri = "https://graph.microsoft.com$Path"
    $all = @()
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        if ($page.PSObject.Properties.Name -contains 'value') { $all += $page.value } else { $all += $page }
        $uri = if ($page.PSObject.Properties.Name -contains '@odata.nextLink') { $page.'@odata.nextLink' } else { $null }
    }
    return $all
}

function Expand-Target {
    param([string] $Text)
    $Text.Replace('{resource_group}', $ResourceGroup).Replace('{workspace}', $Workspace).Replace('{subscription}', $script:subscription)
}

# Sign-ins: interactive, delegated, read-only scopes taken from items.csv.
$graphItems = @($items | Where-Object method -eq 'graph')
if ($graphItems) {
    $scopes = $graphItems.permission | Sort-Object -Unique
    Connect-MgGraph -Scopes $scopes -NoWelcome
}
$azureItems = @($items | Where-Object { $_.method -in 'az', 'az-rest', 'kql' })
if ($azureItems) {
    $script:subscription = az account show --query id -o tsv
    if (-not $script:subscription) { throw 'Run az login first.' }
}
$ippsItems = @($items | Where-Object method -eq 'ipps')
if ($ippsItems) { Connect-IPPSSession -ShowBanner:$false }

foreach ($row in $items) {
    Write-Host "Collecting $($row.item) ($($row.method))"
    try {
        switch ($row.method) {
            'graph'   { $value = Get-GraphAll -Path $row.target }
            'az-rest' {
                $raw = az rest --method get --url (Expand-Target $row.target) -o json | ConvertFrom-Json
                $value = if ($raw.PSObject.Properties.Name -contains 'value') { $raw.value } else { $raw }
            }
            'az'      {
                $azArgs = (Expand-Target $row.target) -split ' '
                $value = az @azArgs -o json | ConvertFrom-Json
            }
            'kql'     {
                if (-not $WorkspaceId) { throw '-WorkspaceId is required for KQL items.' }
                $query = Get-Content -Raw (Join-Path $repoRoot $row.target)
                $value = az monitor log-analytics query --workspace $WorkspaceId --analytics-query $query -o json | ConvertFrom-Json
            }
            'ipps'    {
                $value = & $row.target | Select-Object * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName
            }
        }
        Save-Envelope -Row $row -Value $value
    }
    catch {
        Write-Warning "$($row.item): $($_.Exception.Message)"
        Save-Envelope -Row $row -Value @() -Status 'error' -ErrorText $_.Exception.Message
    }
}

# Manifest: what was collected, when, by which version of the repository.
$commit = (git -C $repoRoot rev-parse HEAD 2>$null)
$files = Get-ChildItem $outDir -File -Filter *.json | Where-Object Name -ne 'manifest.json' | ForEach-Object {
    [ordered]@{ file = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
}
[ordered]@{
    run_id        = $runId
    repo_commit   = $commit
    collector     = 'collectors/Collect-Evidence.ps1'
    operator_role = 'lab-maintainer'
    files         = @($files)
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 -Path (Join-Path $outDir 'manifest.json')

if ($graphItems) { Disconnect-MgGraph | Out-Null }
if ($ippsItems)  { Disconnect-ExchangeOnline -Confirm:$false }
Write-Host "Evidence written to $outDir"
Write-Host "Next: python tools/evaluate_controls.py --run $outDir"
