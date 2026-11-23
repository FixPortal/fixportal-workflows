#Requires -Version 7
<#
.SYNOPSIS
    Pure per-PR logic for audit-ai-quality's PR mode. Dot-source this file.
#>
$ErrorActionPreference = 'Stop'

function Format-SafeLogText {
    # A coverage reason can carry text from the PR (a file name). The Actions runner reads a log line
    # that starts with :: or ##[ as a workflow command, and a name with a line break can start one.
    # Control characters become spaces, so the text stays on its own line, and the command markers are
    # broken so they cannot parse wherever they land.
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string] $Text)
    return (($Text -replace '[\x00-\x1f\x7f]+', ' ') -replace '::', ': :') -replace '##\[', '## ['
}

function Format-SafeSummaryText {
    # The job summary is Markdown, so a file name or added line from the PR would render as a link,
    # image or heading there. Render it as one inline code span: first the log-safe form (one line, no
    # runner commands), then a fence one backtick longer than the longest backtick run inside, so
    # nothing in the text can end the span early.
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string] $Text)
    $safe = Format-SafeLogText $Text
    $longest = 0
    foreach ($run in [regex]::Matches($safe, '`+')) { if ($run.Length -gt $longest) { $longest = $run.Length } }
    $fence = '`' * ($longest + 1)
    return "$fence $safe $fence"
}

function Get-DiffLineInfo {
    # One merge-base diff yields three things the PR filter needs:
    #   Added    file -> set of added new-file line numbers
    #   Deleted  file -> set of N for each pure-deletion hunk `+N,0` (lines were removed
    #            between new-file lines N and N+1; no added line records that an empty
    #            catch was emptied)
    #   Renames  new path -> old path, so a base-side measurement finds the right file
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $RepoPath, [Parameter(Mandatory)] [string] $Base, [Parameter(Mandatory)] [string] $Head)
    # The fork point, not the base tip: base.sha moves when the base branch does, and a
    # two-dot diff from it would count the base's own new lines as the PR's.
    $mergeBase = (& git -C $RepoPath merge-base $Base $Head).Trim()
    if ($LASTEXITCODE -ne 0) { throw "git merge-base $Base $Head failed" }
    # Native output is decoded with [Console]::OutputEncoding; a legacy code page garbles a non-ASCII path.
    $consoleEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $diff = & git -C $RepoPath -c core.quotepath=false diff -U0 -M --diff-filter=AMR --no-color $mergeBase $Head
        $diffExit = $LASTEXITCODE
    }
    finally { [Console]::OutputEncoding = $consoleEncoding }
    if ($diffExit -ne 0) { throw "git diff $mergeBase $Head failed" }
    $added = @{}; $deleted = @{}; $renames = @{}
    $current = $null; $renameFrom = $null
    # Hunk bodies are skipped by their @@ line counts. Matching `+++ b/` anywhere switched the
    # current file on a body line, because an added line `++ b/x` reads in the diff as `+++ b/x`.
    $oldLeft = 0; $newLeft = 0
    foreach ($line in $diff) {
        if ($oldLeft -gt 0 -or $newLeft -gt 0) {
            if ($line.StartsWith('\')) { continue } # "\ No newline at end of file"
            switch ($(if ($line.Length) { $line[0] } else { ' ' })) {
                '+' { $newLeft-- }
                '-' { $oldLeft-- }
                default { $oldLeft--; $newLeft-- }
            }
            continue
        }
        if ($line.StartsWith('diff --git ')) { $current = $null; $renameFrom = $null; continue }
        if ($line -match '^rename from (.+)$') { $renameFrom = $Matches[1]; continue }
        if ($line -match '^rename to (.+)$') { if ($renameFrom) { $renames[$Matches[1]] = $renameFrom }; continue }
        if ($line -match '^\+\+\+ b/(.+?)\t?$') { $current = $Matches[1]; $added[$current] = [System.Collections.Generic.HashSet[int]]::new(); $deleted[$current] = [System.Collections.Generic.HashSet[int]]::new(); continue }
        if ($current -and $line -match '^@@ -\S+ \+(\d+)(?:,(\d+))? @@') {
            $start = [int]$Matches[1]
            $count = if ($null -ne $Matches[2]) { [int]$Matches[2] } else { 1 }
            $oldLeft = if ($line -match '^@@ -\d+,(\d+) ') { [int]$Matches[1] } else { 1 }
            $newLeft = $count
            if ($count -eq 0) { [void]$deleted[$current].Add($start) }
            for ($i = 0; $i -lt $count; $i++) { [void]$added[$current].Add($start + $i) }
        }
    }
    return @{ Added = $added; Deleted = $deleted; Renames = $renames; MergeBase = $mergeBase }
}

function Get-AddedLines {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $RepoPath, [Parameter(Mandatory)] [string] $Base, [Parameter(Mandatory)] [string] $Head)
    return (Get-DiffLineInfo -RepoPath $RepoPath -Base $Base -Head $Head).Added
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

function Get-HitSpan {
    # The lines a hit covers: scopeStart (the part of the span that IS the smell, e.g. S13's
    # catch clause inside a whole try statement) or the anchor line, through endLine.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit)
    $line = [int]$Hit.line
    $start = if ($Hit.scopeStart -and [int]$Hit.scopeStart -gt 0) { [int]$Hit.scopeStart } else { $line }
    $end = if ($Hit.endLine -and [int]$Hit.endLine -ge $start) { [int]$Hit.endLine } else { $start }
    return @{ Start = $start; End = $end }
}

function Get-DeletionPoint([hashtable] $Deleted, [string] $File, [int] $Start, [int] $End, [switch] $WholeFile) {
    # A pure-deletion hunk `+N,0` removed lines between N and N+1; it lies inside a span when
    # Start <= N < End. $null when there is none.
    if (-not $Deleted -or -not $Deleted.ContainsKey($File)) { return $null }
    if ($WholeFile) { $Start = 0; $End++ }
    $inside = @($Deleted[$File] | Where-Object { $_ -ge $Start -and $_ -lt $End } | Sort-Object)
    if ($inside.Count) { return [Math]::Max(1, [int]$inside[0]) } # A leading deletion has no preceding line; anchor on the first survivor.
    return $null
}

function Get-CloneOtherSpan {
    # Line count of a clone's SECOND location: its own end when the hit carries a usable one, else the
    # first location's count (jscpd's `lines` describes the first partner only).
    param($Hit, [int] $OtherLine, [int] $Count)
    $end = $Hit.PSObject.Properties['otherEndLine']
    if ($end -and $null -ne $end.Value -and [int]$end.Value -ge $OtherLine) { return [int]$end.Value - $OtherLine + 1 }
    return $Count
}

function Test-HitOnAddedLines {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit, [Parameter(Mandatory)] [hashtable] $Added, [hashtable] $Deleted)
    if ($Hit.smell -eq 'S14' -and [string]$Hit.text -match '^duplicates (.+):(\d+) \((\d+) lines\)$') {
        $n = [int]$Matches[3]
        $otherN = Get-CloneOtherSpan $Hit ([int]$Matches[2]) $n
        return (Test-RangeAdded $Added $Hit.file ([int]$Hit.line) $n) -or (Test-RangeAdded $Added $Matches[1] ([int]$Matches[2]) $otherN)
    }
    $span = Get-HitSpan $Hit
    if (Test-RangeAdded $Added $Hit.file $span.Start ($span.End - $span.Start + 1)) { return $true }
    # An empty catch made by DELETING the body adds no line anywhere: the PR still authored it.
    return $Hit.smell -in 'S13', 'S41' -and ($null -ne (Get-DeletionPoint $Deleted $Hit.file $span.Start $span.End -WholeFile:($Hit.smell -eq 'S41')))
}

function Get-AnchoredHit {
    # Re-expresses a hit on a line GitHub will accept a comment on (an added one, or for a
    # deletion the line just above it). A clone hit is moved to whichever side the PR added,
    # preferring a side that is not excluded; $null when no non-excluded side qualifies.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit, [Parameter(Mandatory)] [hashtable] $Added, [hashtable] $Deleted, [string[]] $Exclude)
    if ($Hit.smell -ne 'S14' -or [string]$Hit.text -notmatch '^duplicates (.+):(\d+) \((\d+) lines\)$') {
        $span = Get-HitSpan $Hit
        $first = Get-FirstAddedLine $Added $Hit.file $span.Start ($span.End - $span.Start + 1)
        if ($null -eq $first -and $Hit.smell -in 'S13', 'S41') { $first = Get-DeletionPoint $Deleted $Hit.file $span.Start $span.End -WholeFile:($Hit.smell -eq 'S41') }
        if ($null -eq $first -or $first -eq [int]$Hit.line) { return $Hit }
        $moved = $Hit.PSObject.Copy()
        $moved.line = $first
        return $moved
    }
    $other = $Matches[1]; $otherLine = [int]$Matches[2]; $n = [int]$Matches[3]
    $otherN = Get-CloneOtherSpan $Hit $otherLine $n
    $own = if (Test-PathExcluded $Hit.file $Exclude) { $null } else { Get-FirstAddedLine $Added $Hit.file ([int]$Hit.line) $n }
    if ($null -ne $own) {
        $kept = $Hit.PSObject.Copy()
        $kept.line = $own
        return $kept
    }
    $theirs = if (Test-PathExcluded $other $Exclude) { $null } else { Get-FirstAddedLine $Added $other $otherLine $otherN }
    if ($null -eq $theirs) { return $null }
    $swapped = $Hit.PSObject.Copy()
    $swapped.file = $other
    $swapped.line = $theirs
    # The swapped hit's "other" side is the original first location, whose span is its own line count.
    $swapped | Add-Member -NotePropertyName otherEndLine -NotePropertyValue ([int]$Hit.line + $n - 1) -Force
    if ($swapped.PSObject.Properties['endLine']) { $swapped.endLine = $otherLine + $otherN - 1 }
    $swapped.text = "duplicates $($Hit.file):$($Hit.line) ($n lines)"
    return $swapped
}

function Get-HitContext([string[]] $Lines, [int] $Line) {
    $anchor = $Lines[$Line - 1].Trim()
    for ($i = $Line - 2; $i -ge 0; $i--) {
        $candidate = $Lines[$i].Trim()
        if ($candidate -and $candidate -ne $anchor -and $candidate -notmatch '^[{};]+$') { return $candidate }
    }
    return ''
}

function Get-SmellMarker {
    # Context distinguishes identical anchors without shifting when a different occurrence is inserted above.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit)
    $occurrence = if ($Hit.occurrence) { [int]$Hit.occurrence } else { 0 }
    $key = "$($Hit.file)`n$(([string]$Hit.lineText).Trim())"
    if ($Hit.context) { $key += "`n$($Hit.context)" }
    if ($occurrence -gt 0) { $key += "`n#$occurrence" }
    $bytes = [Text.Encoding]::UTF8.GetBytes($key)
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($bytes)).ToLowerInvariant()
    return "$($Hit.smell):$($hash.Substring(0, 12))"
}

function Add-HitOccurrence {
    # shortcut: identical anchors with identical context still use position; use syntax identity if these recur.
    [CmdletBinding()]
    param([object[]] $Hits)
    $count = @{}
    foreach ($h in @($Hits)) {
        $key = "$($h.smell)`n$($h.file)`n$(([string]$h.lineText).Trim())"
        if ($h.context) { $key += "`n$($h.context)" }
        $n = if ($count.ContainsKey($key)) { $count[$key] } else { 0 }
        $count[$key] = $n + 1
        $copy = $h.PSObject.Copy()
        Add-Member -InputObject $copy -NotePropertyName occurrence -NotePropertyValue $n -Force
        $copy
    }
}

function Get-MarkersFromBodies {
    [CmdletBinding()]
    param([string[]] $Body)
    # Only the body's final line: the poster always ends with its marker, so a marker anywhere else
    # was written by someone else (or came in with embedded hit text).
    return @($Body | ForEach-Object {
        $last = ([string]$_).TrimEnd() -split '\r?\n' | Select-Object -Last 1
        if ($last -match '^\s*<!-- ai-smell:(\S+) -->$') { $Matches[1] }
    })
}

function Get-LiveMarkers {
    # A nearby edit outdates a thread even when its line survives, and the gate ignores
    # outdated threads, so an outdated unresolved marker must not block a re-post.
    # Resolved threads keep their marker: a declined smell stays declined.
    # -Author is the identity the poster runs as: any author can open a thread and paste a marker, so
    # only that identity's threads count. GraphQL reports a bot without the REST "[bot]" suffix. An
    # empty -Author (identity unknown) reads every thread, as before.
    [CmdletBinding()]
    param([object[]] $Thread, [string] $Author = '')
    $mine = $Author -replace '\[bot\]$', ''
    return Get-MarkersFromBodies @($Thread |
        Where-Object { $_.isResolved -or -not $_.isOutdated } |
        Where-Object { -not $mine -or (([string]$_.author) -replace '\[bot\]$', '') -eq $mine } |
        ForEach-Object { [string]$_.body })
}

function Select-NewSmellHits {
    [CmdletBinding()]
    param([object[]] $Hits, [string[]] $Existing, [int] $Cap = 25)
    $seen = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Existing))
    $new = @(Add-HitOccurrence $Hits | Where-Object { $seen.Add((Get-SmellMarker $_)) })
    return @{ Post = @($new | Select-Object -First $Cap); Overflow = @($new | Select-Object -Skip $Cap) }
}

function Format-CodeFence {
    # Hit text comes from the PR. Fenced, it renders as code, and the fence is longer than any
    # backtick run inside so the text cannot close it.
    [CmdletBinding()]
    param([AllowNull()] [string] $Text)
    $longest = ([regex]::Matches([string]$Text, '`+') | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $fence = '`' * [Math]::Max(3, [int]$longest + 1)
    return "$fence`n$Text`n$fence"
}

function Format-SmellThreadBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Hit)
    $detail = if (([string]$Hit.text).Trim() -and ([string]$Hit.text).Trim() -ne ([string]$Hit.lineText).Trim()) { "$(Format-CodeFence ([string]$Hit.text).Trim())`n`n" } else { '' }
    return @"
**AI smell $($Hit.smell): $($Hit.name)**

$detail$(Format-CodeFence ([string]$Hit.lineText))

Fix the line (this thread then goes outdated), or reply with the reason it stays and resolve the thread.

<!-- ai-smell:$(Get-SmellMarker $Hit) -->
"@
}
