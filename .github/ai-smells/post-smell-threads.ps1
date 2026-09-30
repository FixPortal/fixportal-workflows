#Requires -Version 7
<#
.SYNOPSIS
    Post pr-detect.ps1's hits as PR review threads, skipping hits already posted on a
    current or resolved thread. Needs GH_TOKEN with pull-requests: write. Individual post
    failures are warnings. Exits 1 only if listing existing threads fails, or there was at
    least one hit to post and every post failed. Never because of hits.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $HitsPath,
    [Parameter(Mandatory)] [string] $Repo,
    [Parameter(Mandatory)] [int] $Pr,
    [Parameter(Mandatory)] [string] $HeadSha,
    [int] $Cap = 25
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'pr-scope.ps1')

$result = Get-Content -LiteralPath $HitsPath -Raw | ConvertFrom-Json
$owner, $name = $Repo.Split('/')
$query = 'query($owner:String!,$name:String!,$number:Int!,$endCursor:String){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100,after:$endCursor){pageInfo{hasNextPage endCursor} nodes{isResolved isOutdated comments(first:1){nodes{body}}}}}}}'
$raw = @(gh api graphql --paginate -f query=$query -F owner=$owner -F name=$name -F number=$Pr --jq '.data.repository.pullRequest.reviewThreads.nodes[] | {isResolved, isOutdated, body: .comments.nodes[0].body} | tojson')
if ($LASTEXITCODE -ne 0) { throw "could not list review threads on $Repo#$Pr" }
$pick = Select-NewSmellHits -Hits @($result.hits) -Existing (Get-LiveMarkers @($raw | ConvertFrom-Json)) -Cap $Cap

$failed = 0
foreach ($h in $pick.Post) {
    gh api -X POST "repos/$Repo/pulls/$Pr/comments" -f body="$(Format-SmellThreadBody $h)" -f commit_id=$HeadSha -f path=$($h.file) -F line=$($h.line) -f side=RIGHT | Out-Null
    if ($LASTEXITCODE -ne 0) { $failed++; Write-Warning "could not post $($h.smell) at $($h.file):$($h.line)" }
}
if ($pick.Overflow.Count) {
    gh pr comment $Pr -R $Repo --body "ai-smells: $($pick.Overflow.Count) further hit(s) beyond the $Cap-thread cap. They are listed in this run's job summary and will be posted on the next push." | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'could not post the overflow comment' }
}

if ($env:GITHUB_STEP_SUMMARY) {
    $summary = @("## ai-smells", "", "$(@($result.hits).Count) hit(s) on added lines; $($pick.Post.Count) new thread(s) posted.")
    $gaps = @($result.coverage | Where-Object status -eq 'not assessed')
    if ($gaps) { $summary += @('', '**Not assessed** (a detector could not run; not the same as clean):') + @($gaps | ForEach-Object { "- $($_.smell): $($_.reason)" }) }
    if ($pick.Overflow.Count) { $summary += @('', '**Over the cap:**') + @($pick.Overflow | ForEach-Object { "- $($_.smell) $($_.file):$($_.line) $($_.lineText)" }) }
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary
}
if ($pick.Post.Count -gt 0 -and $failed -eq $pick.Post.Count) { exit 1 }
