#Requires -Version 7
<#
.SYNOPSIS
    Pure per-PR logic for audit-ai-quality's PR mode. Dot-source this file.
#>
$ErrorActionPreference = 'Stop'

function Get-AddedLines {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $RepoPath, [Parameter(Mandatory)] [string] $Base, [Parameter(Mandatory)] [string] $Head)
    # The fork point, not the base tip: base.sha moves when the base branch does, and a
    # two-dot diff from it would count the base's own new lines as the PR's.
    $mergeBase = (& git -C $RepoPath merge-base $Base $Head).Trim()
    if ($LASTEXITCODE -ne 0) { throw "git merge-base $Base $Head failed" }
    $diff = & git -C $RepoPath -c core.quotepath=false diff -U0 -M --diff-filter=AMR --no-color $mergeBase $Head
    if ($LASTEXITCODE -ne 0) { throw "git diff $mergeBase $Head failed" }
    $added = @{}
    $current = $null
    foreach ($line in $diff) {
        if ($line -match '^\+\+\+ b/(.+?)\t?$') { $current = $Matches[1]; $added[$current] = [System.Collections.Generic.HashSet[int]]::new(); continue }
        if ($current -and $line -match '^@@ -\S+ \+(\d+)(?:,(\d+))? @@') {
            $start = [int]$Matches[1]
            $count = if ($null -ne $Matches[2]) { [int]$Matches[2] } else { 1 }
            for ($i = 0; $i -lt $count; $i++) { [void]$added[$current].Add($start + $i) }
        }
    }
    return $added
}

function Test-PathExcluded {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path, [string[]] $Exclude)
    foreach ($glob in @($Exclude)) {
        $re = [regex]::Escape($glob) -replace '\\\*\\\*/', '(?:.*/)?' -replace '\\\*\\\*', '.*' -replace '\\\*', '[^/]*'
        if ($Path -match "^$re$") { return $true }
    }
    return $false
}

function Get-FirstAddedLine([hashtable] $Added, [string] $File, [int] $Start, [int] $Count) {
    # GitHub rejects a review comment on a line outside the diff, so anchor on an added one.
    if (-not $Added.ContainsKey($File)) { return $null }
    for ($l = $Start; $l -lt $Start + [Math]::Max($Count, 1); $l++) { if ($Added[$File].Contains($l)) { return $l } }
    return $null
}

function Test-RangeAdded([hashtable] $Added, [string] $File, [int] $Start, [int] $Count) {
    return $null -ne (Get-FirstAddedLine $Added $File $Start $Count)
}

function Test-HitOnAddedLines {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit, [Parameter(Mandatory)] [hashtable] $Added)
    if ($Hit.smell -eq 'S14' -and [string]$Hit.text -match '^duplicates (.+):(\d+) \((\d+) lines\)$') {
        $n = [int]$Matches[3]
        return (Test-RangeAdded $Added $Hit.file ([int]$Hit.line) $n) -or (Test-RangeAdded $Added $Matches[1] ([int]$Matches[2]) $n)
    }
    return Test-RangeAdded $Added $Hit.file ([int]$Hit.line) 1
}

function Get-AnchoredHit {
    # A clone hit is re-expressed on whichever side the PR added, with `line` the first added
    # line in that side's range (not the clone start, which may sit outside the diff).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit, [Parameter(Mandatory)] [hashtable] $Added)
    if ($Hit.smell -ne 'S14' -or [string]$Hit.text -notmatch '^duplicates (.+):(\d+) \((\d+) lines\)$') { return $Hit }
    $other = $Matches[1]; $otherLine = [int]$Matches[2]; $n = [int]$Matches[3]
    $own = Get-FirstAddedLine $Added $Hit.file ([int]$Hit.line) $n
    if ($null -ne $own) {
        $kept = $Hit.PSObject.Copy()
        $kept.line = $own
        return $kept
    }
    $theirs = Get-FirstAddedLine $Added $other $otherLine $n
    if ($null -eq $theirs) { return $Hit }
    $swapped = $Hit.PSObject.Copy()
    $swapped.file = $other
    $swapped.line = $theirs
    $swapped.text = "duplicates $($Hit.file):$($Hit.line) ($n lines)"
    return $swapped
}

function Get-SmellMarker {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit)
    $bytes = [Text.Encoding]::UTF8.GetBytes("$($Hit.file)`n$(([string]$Hit.lineText).Trim())")
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($bytes)).ToLowerInvariant()
    return "$($Hit.smell):$($hash.Substring(0, 12))"
}

function Get-MarkersFromBodies {
    [CmdletBinding()]
    param([string[]] $Body)
    return @($Body | ForEach-Object { [regex]::Matches([string]$_, '<!-- ai-smell:(\S+) -->') | ForEach-Object { $_.Groups[1].Value } })
}

function Get-LiveMarkers {
    # A nearby edit outdates a thread even when its line survives, and the gate ignores
    # outdated threads, so an outdated unresolved marker must not block a re-post.
    # Resolved threads keep their marker: a declined smell stays declined.
    [CmdletBinding()]
    param([object[]] $Thread)
    return Get-MarkersFromBodies @($Thread | Where-Object { $_.isResolved -or -not $_.isOutdated } | ForEach-Object { [string]$_.body })
}

function Select-NewSmellHits {
    [CmdletBinding()]
    param([object[]] $Hits, [string[]] $Existing, [int] $Cap = 25)
    $seen = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Existing))
    $new = @($Hits | Where-Object { $seen.Add((Get-SmellMarker $_)) })
    return @{ Post = @($new | Select-Object -First $Cap); Overflow = @($new | Select-Object -Skip $Cap) }
}

function Format-SmellThreadBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit)
    $detail = if (([string]$Hit.text).Trim() -and ([string]$Hit.text).Trim() -ne ([string]$Hit.lineText).Trim()) { "$(([string]$Hit.text).Trim())`n`n" } else { '' }
    return @"
**AI smell $($Hit.smell): $($Hit.name)**

$detail``````
$($Hit.lineText)
``````

Fix the line (this thread then goes outdated), or reply with the reason it stays and resolve the thread.

<!-- ai-smell:$(Get-SmellMarker $Hit) -->
"@
}