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
$added = Get-AddedLines -RepoPath $RepoPath -Base $Base -Head $Head
$files = @($added.Keys | Where-Object { -not (Test-PathExcluded $_ $Exclude) } | Sort-Object)

$hits = @(); $coverage = @()
if ($files.Count) {
    $work = Join-Path ([IO.Path]::GetTempPath()) "ai-smells-$([guid]::NewGuid().ToString('N'))"
    try {
        $det = Invoke-SmellDetectors -TreePath $RepoPath -Catalogue ([pscustomobject]@{ Smells = $smells }) -SkillRoot $SkillRoot -OutDir $work -Pathspec $files
        $coverage = @($det.Coverage)
        $hits = @($det.Hits | Where-Object { -not (Test-PathExcluded $_.file $Exclude) -and (Test-HitOnAddedLines $_ $added) } | ForEach-Object { Get-AnchoredHit $_ $added } | Where-Object { -not (Test-PathExcluded $_.file $Exclude) } | ForEach-Object {
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
