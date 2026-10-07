#Requires -Version 7
<#
.SYNOPSIS
    Per-PR smell detection: the scripted detectors over the files a PR adds or modifies,
    keeping only hits on lines it adds. No model, no vault, no catalogue quotes.
.DESCRIPTION
    The working tree at -RepoPath must be checked out at -Head: detection reads files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $RepoPath,
    [Parameter(Mandatory)] [string] $Base,
    [Parameter(Mandatory)] [string] $Head,
    [Parameter(Mandatory)] [string] $OutFile,
    [string[]] $Exclude = @('docs/**', '**/fixtures/**', '.github/ai-smells/**'),
    [string] $SmellsPath = (Join-Path $PSScriptRoot 'smells.json'),
    [string] $SkillRoot = $PSScriptRoot
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'detect.ps1')
. (Join-Path $PSScriptRoot 'pr-scope.ps1')

$RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path
$checkedOut = (& git -C $RepoPath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw "git rev-parse HEAD failed in $RepoPath" }
$headSha = (& git -C $RepoPath rev-parse $Head).Trim()
if ($LASTEXITCODE -ne 0) { throw "git rev-parse $Head failed in $RepoPath" }
if ($checkedOut -ne $headSha) { throw "working tree is at $checkedOut, not -Head $Head" }

$smells = @((Get-Content -LiteralPath $SmellsPath -Raw | ConvertFrom-Json).smells)
$names = @{}; foreach ($s in $smells) { $names[[string]$s.id] = [string]$s.name }
$info = Get-DiffLineInfo -RepoPath $RepoPath -Base $Base -Head $Head
$added = $info.Added
$files = @($added.Keys | Where-Object { -not (Test-PathExcluded $_ $Exclude) } | Sort-Object)

# Size-threshold smells: a hit on a PR-touched span is the PR's only if the PR pushed the
# measure past the threshold. A function that was already 150 lines and gained one more is
# not news; the same hit measured at the merge-base says so.
$sizeSmells = @('S30', 'S41')

function Get-HitKey($h) { "$($h.smell)|$($h.file)|$(([string]$h.text) -replace '\d+', '#')" }

$hits = @(); $coverage = @()
if ($files.Count) {
    $work = Join-Path ([IO.Path]::GetTempPath()) "ai-smells-$([guid]::NewGuid().ToString('N'))"
    try {
        $det = Invoke-SmellDetectors -TreePath $RepoPath -Catalogue ([pscustomobject]@{ Smells = $smells }) -SkillRoot $SkillRoot -OutDir $work -Pathspec $files -JscpdExclude $Exclude
        $coverage = @($det.Coverage)
        # Anchoring is exclusion-aware (a clone prefers a non-excluded side that has added
        # lines), so the exclusion filter runs ONCE, after it, not before it.
        $onPr = @($det.Hits |
            Where-Object { Test-HitOnAddedLines $_ $added $info.Deleted } |
            ForEach-Object { Get-AnchoredHit $_ $added $info.Deleted $Exclude } |
            Where-Object { $_ -and -not (Test-PathExcluded $_.file $Exclude) })

        $sized = @($onPr | Where-Object { $_.smell -in $sizeSmells })
        if ($sized.Count) {
            $baseTree = Join-Path $work 'base-tree'
            foreach ($file in @($sized.file | Sort-Object -Unique)) {
                $old = if ($info.Renames.ContainsKey($file)) { $info.Renames[$file] } else { $file }
                # PowerShell decodes native output with the console encoding; under a non-UTF-8
                # console a non-ASCII signature would reach the baseline detector altered and an
                # old S30 hit would read as new. Decode as UTF-8 for this capture only.
                $consoleEncoding = [Console]::OutputEncoding
                try {
                    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
                    $content = & git -C $RepoPath -c core.quotepath=false show "$($info.MergeBase):$old" 2>$null
                }
                finally { [Console]::OutputEncoding = $consoleEncoding }
                if ($LASTEXITCODE -ne 0) { continue } # absent at the merge-base: the PR created it
                $dest = Join-Path $baseTree $file
                New-Item -ItemType Directory -Force (Split-Path -Parent $dest) | Out-Null
                [IO.File]::WriteAllText($dest, ((@($content) -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
            }
            $baseKeys = [System.Collections.Generic.HashSet[string]]::new()
            if (Test-Path -LiteralPath $baseTree) {
                $sizeCatalogue = [pscustomobject]@{ Smells = @($smells | Where-Object { $_.id -in $sizeSmells -and $_.detector.kind -eq 'script' }) }
                $baseDet = Invoke-SmellDetectors -TreePath $baseTree -Catalogue $sizeCatalogue -SkillRoot $SkillRoot -OutDir (Join-Path $work 'base-out')
                foreach ($bh in $baseDet.Hits) { [void]$baseKeys.Add((Get-HitKey $bh)) }
            }
            $onPr = @($onPr | Where-Object { $_.smell -notin $sizeSmells -or -not $baseKeys.Contains((Get-HitKey $_)) })
        }

        $hits = @($onPr | ForEach-Object {
            $lines = [IO.File]::ReadAllLines((Join-Path $RepoPath $_.file))
            [ordered]@{
                smell    = $_.smell
                name     = $names[[string]$_.smell]
                file     = $_.file
                line     = [int]$_.line
                lineText = if ($_.line -ge 1 -and $_.line -le $lines.Count) { $lines[$_.line - 1].Trim() } else { '' }
                text     = $_.text
            }
        })
    }
    finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
$json = [ordered]@{ hits = $hits; coverage = $coverage } | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($OutFile, $json, [Text.UTF8Encoding]::new($false))
