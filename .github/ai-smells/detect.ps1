#Requires -Version 7
<#
.SYNOPSIS
    Scripted smell detection: semgrep (regex + AST rules), jscpd (clones), and the
    detectors/scripts/*.py scripts. Dot-source this file.
.DESCRIPTION
    Output is deterministic: hits sorted by smell, file, line, ids assigned after
    sorting. A tool that cannot run marks its smells 'not assessed' -- never zero --
    except semgrep, whose absence stops the run: every regex smell depends on it.
#>
$ErrorActionPreference = 'Stop'

$script:ExcludeDirs = @('bin', 'obj', 'node_modules', 'dist')
$script:ExcludeGlobs = @('*.g.cs', '*.designer.cs', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'packages.lock.json', '*.min.js', '*.min.css')
$script:LanguageByExtension = @{
    '.cs' = 'csharp'; '.ts' = 'typescript'; '.tsx' = 'typescript'; '.js' = 'javascript'; '.jsx' = 'javascript'
    '.mjs' = 'javascript'; '.cjs' = 'javascript'; '.py' = 'python'; '.go' = 'go'; '.java' = 'java'
    '.rs' = 'rust'; '.rb' = 'ruby'; '.kt' = 'kotlin'; '.swift' = 'swift'; '.cpp' = 'cpp'; '.c' = 'c'; '.ps1' = 'powershell'; '.psm1' = 'powershell'
}

function Split-ByLength([string[]] $Items, [int] $Budget) {
    # Windows caps a command line at 32K characters; a real repository's file list overflows it.
    $batches = [System.Collections.Generic.List[object]]::new()
    $batch = [System.Collections.Generic.List[string]]::new(); $length = 0
    foreach ($t in $Items) {
        if ($batch.Count -gt 0 -and $length + $t.Length + 3 -gt $Budget) { $batches.Add($batch.ToArray()); $batch.Clear(); $length = 0 }
        $batch.Add($t); $length += $t.Length + 3
    }
    if ($batch.Count -gt 0) { $batches.Add($batch.ToArray()) }
    return $batches.ToArray()
}

function Get-ScanFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $TreePath, [string[]] $Pathspec)
    # Batched: pr-detect passes every file a PR touches, and ~1000 paths overflowed the
    # command line before git started. Exclude pathspecs go in every batch, or a batch
    # holding only includes would list the excluded files.
    $excludeMagic = '^:(!|\^|\([^)]*\bexclude\b)'
    $exclude = @($Pathspec | Where-Object { $_ -match $excludeMagic })
    $include = @($Pathspec | Where-Object { $_ -and $_ -notmatch $excludeMagic })
    $budget = 24000 - (($exclude | ForEach-Object { $_.Length + 3 } | Measure-Object -Sum).Sum)
    $batches = @(Split-ByLength $include $budget)
    if (-not $batches.Count) { $batches = @('') }
    $listed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $ok = $true
    foreach ($b in $batches) {
        $spec = @(@($b) + $exclude | Where-Object { $_ })
        $gitArgs = @('-C', $TreePath, 'ls-files', '-z')
        if ($spec) { $gitArgs += @('--') + $spec }
        $raw = & git @gitArgs 2>$null
        if ($LASTEXITCODE -ne 0) { $ok = $false; break }
        foreach ($f in (($raw -join '') -split "`0")) { if ($f) { [void]$listed.Add($f) } }
    }
    if ($ok) {
        $files = @($listed)
    }
    elseif (-not (Test-Path -LiteralPath (Join-Path $TreePath '.git'))) {
        # Not a git tree (contract-test fixtures): enumerate the filesystem instead.
        $rootFull = (Resolve-Path -LiteralPath $TreePath).Path
        $files = @(Get-ChildItem -LiteralPath $rootFull -Recurse -File | ForEach-Object { [IO.Path]::GetRelativePath($rootFull, $_.FullName).Replace('\', '/') })
    }
    else { throw "git ls-files failed in $TreePath" }
    return @($files | Where-Object {
        $rel = $_
        $segments = $rel -split '/'
        if ($segments | Where-Object { $_ -in $script:ExcludeDirs }) { return $false }
        $leaf = $segments[-1]
        foreach ($g in $script:ExcludeGlobs) { if ($leaf -like $g) { return $false } }
        return $true
    } | Sort-Object)
}

function Get-SmellIdFromCheck([string] $CheckId) {
    $leaf = ($CheckId -split '\.')[-1]
    return ($leaf -split '-')[0]
}

function Test-ToolAvailable([string[]] $Command) {
    if (-not $Command -or $Command.Count -eq 0) { return $false }
    return [bool](Get-Command $Command[0] -ErrorAction SilentlyContinue)
}

function Get-SemgrepRuleFiles([string] $SkillRoot, [string] $RulePath) {
    # A catalogue smell names ONE rule file, but some smells (e.g. S13) have language
    # siblings named '<id>-*.yml' in the same directory (e.g. S13-ts.yml). Pass semgrep
    # the named rule plus every sibling so a catalogue naming only detectors/rules/S13.yml
    # still fires the TS/JS variant.
    $full = Join-Path $SkillRoot $RulePath
    $dir = Split-Path -Parent $full
    $base = [IO.Path]::GetFileNameWithoutExtension($full)
    $siblings = @(Get-ChildItem -LiteralPath $dir -Filter "$base-*.yml" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    return @($full) + $siblings
}

function Invoke-SmellDetectors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TreePath,
        [Parameter(Mandatory)] $Catalogue,
        [Parameter(Mandatory)] [string] $SkillRoot,
        [Parameter(Mandatory)] [string] $OutDir,
        [string[]] $Pathspec,
        [string] $SemgrepCommand = 'semgrep',
        [AllowEmptyCollection()] [string[]] $JscpdCommand = @('npx', '--yes', 'jscpd@4.0.5'),
        [string] $PythonCommand = (@('python3', 'python') | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } | Select-Object -First 1)
    )
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $TreePath = (Resolve-Path -LiteralPath $TreePath).Path
    $files = @(Get-ScanFiles -TreePath $TreePath -Pathspec $Pathspec)
    $raw = [System.Collections.Generic.List[object]]::new()
    $coverage = [System.Collections.Generic.List[object]]::new()
    $tools = @{}

    $present = @($files | ForEach-Object { $script:LanguageByExtension[[IO.Path]::GetExtension($_).ToLowerInvariant()] } | Where-Object { $_ } | Sort-Object -Unique)
    $smells = @($Catalogue.Smells)

    # --- semgrep: every regex + semgrep rule in ONE pass ---------------------------
    $semgrepSmells = @($smells | Where-Object { $_.detector.kind -in 'regex', 'semgrep' })
    if ($semgrepSmells.Count -gt 0) {
        if (-not (Get-Command $SemgrepCommand -ErrorAction SilentlyContinue)) {
            throw "semgrep ('$SemgrepCommand') is required and was not found. Install it (pip install semgrep) - regex and AST smells cannot be assessed without it."
        }
        $tools['semgrep'] = ((& $SemgrepCommand --version) | Select-Object -First 1).Trim()
        $configArgs = @($semgrepSmells | ForEach-Object { $sid = $_.id; Get-SemgrepRuleFiles -SkillRoot $SkillRoot -RulePath $_.detector.rule } | ForEach-Object { '--config'; $_ })
        $targets = @($files | ForEach-Object { Join-Path $TreePath $_ })
        # Explicit targets, not the tree root: a directory scan would apply semgrep's own
        # default ignores (tests/, among others) and diverge from Get-ScanFiles. Batched
        # because one invocation over a real repository overflows the Windows 32K
        # command line ("The filename or extension is too long" on a large repository).
        $budget = 24000 - (($configArgs | ForEach-Object { $_.Length + 3 } | Measure-Object -Sum).Sum)
        foreach ($b in @(Split-ByLength $targets $budget)) {
            $json = & $SemgrepCommand scan @configArgs --json --metrics=off --quiet --no-git-ignore --disable-version-check @b 2>$null | Out-String
            foreach ($r in @((ConvertFrom-Json $json).results)) {
                $rel = [IO.Path]::GetRelativePath($TreePath, $r.path).Replace('\', '/')
                $text = ([string]$r.extra.lines).Trim()
                # Logged-out semgrep masks the matched lines as "requires login"; read them from the file.
                if ($text -eq 'requires login') {
                    $end = if ($r.end.line) { [int]$r.end.line } else { [int]$r.start.line }
                    $text = (([IO.File]::ReadAllLines($r.path))[([int]$r.start.line - 1)..($end - 1)] -join "`n").Trim()
                }
                $raw.Add([pscustomobject]@{ smell = (Get-SmellIdFromCheck $r.check_id); file = $rel; line = [int]$r.start.line; text = $text; detector = "semgrep@$($tools['semgrep'])" })
            }
        }
        foreach ($s in $semgrepSmells) {
            $langs = @($s.languages)
            # No files scanned means nothing assessed: add no entry, as for a language that is not present.
            if ($langs -contains 'any') { if ($files.Count) { $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'assessed'; reason = '' }) }; continue }
            foreach ($l in $present) {
                if ($s.id -eq 'S13' -and $l -eq 'powershell') { continue } # Assessed by the PowerShell parser below.
                if ($langs -contains $l) { $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'assessed'; reason = $l }) }
                else { $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'not assessed'; reason = "no rule for $l" }) }
            }
        }
    }

    # Semgrep has no PowerShell AST. Parse catch bodies with the runtime's parser.
    if (@($semgrepSmells | Where-Object id -eq 'S13').Count -and $present -contains 'powershell') {
        $parseFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($rel in @($files | Where-Object { [IO.Path]::GetExtension($_).ToLowerInvariant() -in '.ps1', '.psm1' })) {
            $tokens = $null; $parseErrors = $null
            try { $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $TreePath $rel), [ref]$tokens, [ref]$parseErrors) }
            catch { $parseFailures.Add($rel); continue }
            if ($parseErrors.Count) { $parseFailures.Add($rel); continue }
            foreach ($clause in @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CatchClauseAst] }, $true))) {
                if ($clause.Body.Statements.Count -or $clause.Body.Traps.Count) { continue }
                $raw.Add([pscustomobject]@{ smell = 'S13'; file = $rel; line = $clause.Extent.StartLineNumber; text = $clause.Extent.Text.Trim(); detector = "powershell-parser@$($PSVersionTable.PSVersion)" })
            }
        }
        $tools['powershell-parser'] = [string]$PSVersionTable.PSVersion
        $coverage.Add([pscustomobject]@{ smell = 'S13'; status = $(if ($parseFailures.Count) { 'not assessed' } else { 'assessed' }); reason = $(if ($parseFailures.Count) { "powershell parse failed: $($parseFailures -join ', ')" } else { 'powershell' }) })
    }

    # --- jscpd: clone smells --------------------------------------------------------
    foreach ($s in @($smells | Where-Object { $_.detector.kind -eq 'clone' })) {
        if (-not (Test-ToolAvailable $JscpdCommand)) {
            $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'not assessed'; reason = 'jscpd unavailable' }); continue
        }
        $report = Join-Path $OutDir 'jscpd'
        $ignoreDirs = $script:ExcludeDirs + @('.git', '.vs', '.firecrawl', 'TestResults')
        # jscpd matches ignore globs against absolute paths, so each is rooted at the tree:
        # a bare '**/.claude/worktrees/**' also matched the tree's own ancestors and ignored
        # every file when the audit ran from a worktree checkout.
        # ponytail: tree path is not glob-escaped; a root containing [ ] { } * ? would misparse.
        $treeGlob = $TreePath.Replace('\', '/').TrimEnd('/')
        $ignore = (@($ignoreDirs | ForEach-Object { "**/$_/**" }) + @($script:ExcludeGlobs | ForEach-Object { "**/$_" }) + @('**/docs/sources/**', '**/.claude/worktrees/**') | ForEach-Object { "$treeGlob/$_" }) -join ','
        $formats = ($script:LanguageByExtension.Values | Sort-Object -Unique) -join ','
        # jscpd's Windows glob finds zero files when the root uses backslashes.
        & $JscpdCommand[0] @($JscpdCommand | Select-Object -Skip 1) --silent --reporters json --output ($report.Replace('\', '/')) --min-lines 8 --max-lines 10000 --max-size 1mb --format $formats --ignore $ignore ($TreePath.Replace('\', '/')) 2>$null | Out-Null
        $jsonPath = Join-Path $report 'jscpd-report.json'
        if (-not (Test-Path -LiteralPath $jsonPath)) {
            $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'not assessed'; reason = "jscpd ran but wrote no report (exit $LASTEXITCODE)" }); continue
        }
        $tools['jscpd'] = $JscpdCommand[-1]
        foreach ($d in @((Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json).duplicates)) {
            if ($d.firstFile.name -eq $d.secondFile.name) { continue } # S14 is cross-file duplication.
            $first = [IO.Path]::GetRelativePath($TreePath, $d.firstFile.name).Replace('\', '/')
            $second = [IO.Path]::GetRelativePath($TreePath, $d.secondFile.name).Replace('\', '/')
            $raw.Add([pscustomobject]@{ smell = $s.id; file = $first; line = [int]$d.firstFile.start; text = "duplicates ${second}:$($d.secondFile.start) ($($d.lines) lines)"; detector = "jscpd@$($tools['jscpd'])" })
        }
        $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'assessed'; reason = '' })
    }

    # --- scripts ----------------------------------------------------------------------
    foreach ($s in @($smells | Where-Object { $_.detector.kind -eq 'script' })) {
        $scriptPath = Join-Path $SkillRoot $s.detector.rule
        if (-not $PythonCommand) { $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'not assessed'; reason = 'python unavailable' }); continue }
        $listPath = Join-Path $OutDir "files-$($s.id).txt"
        Set-Content -LiteralPath $listPath -Value $files -Encoding utf8NoBOM
        $out = & $PythonCommand $scriptPath --root $TreePath --files $listPath --smell $s.id 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'not assessed'; reason = "script exited ${LASTEXITCODE}: $($out.Trim() -split "`n" | Select-Object -Last 1)" }); continue }
        $result = $out | ConvertFrom-Json
        foreach ($h in @($result.hits)) { $raw.Add([pscustomobject]@{ smell = $s.id; file = $h.file; line = [int]$h.line; text = [string]$h.text; detector = "script:$(Split-Path -Leaf $scriptPath)" }) }
        $coverage.Add([pscustomobject]@{ smell = $s.id; status = $result.status; reason = [string]$result.reason })
    }

    foreach ($s in @($smells | Where-Object { $_.detector.kind -eq 'judgment' })) {
        $coverage.Add([pscustomobject]@{ smell = $s.id; status = 'judgment'; reason = '' })
    }

    $sorted = @($raw | Sort-Object smell, file, line, text)
    $i = 0
    $hits = @(foreach ($h in $sorted) { $i++; [pscustomobject][ordered]@{ id = ('h{0:D4}' -f $i); smell = $h.smell; file = $h.file; line = $h.line; text = $h.text; detector = $h.detector } })
    $lines = @($hits | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 3 })
    [IO.File]::WriteAllText((Join-Path $OutDir 'hits.jsonl'), (($lines -join "`n") + $(if ($lines) { "`n" } else { '' })))
    $coverage | ConvertTo-Json -Depth 3 -AsArray | Set-Content -LiteralPath (Join-Path $OutDir 'coverage.json') -Encoding utf8NoBOM

    return [pscustomobject]@{ Hits = $hits; Coverage = @($coverage); Tools = $tools }
}
