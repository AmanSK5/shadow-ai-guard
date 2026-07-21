<#
.SYNOPSIS
  AI Guard endpoint collector for Windows.

  Reads AI tool configuration files from the logged-on user's profile and
  reports which account domain each tool is signed into, plus installed IDE
  extensions and MCP server configurations. Which identifiers to look for
  come from the receiver's /registry/collector at runtime, so a new AI tool
  is a registry merge request rather than a script edit plus an Intune
  re-paste. The Windows sibling of
  endpoint/macos/ai-guard-collector.sh - same finding schema, same receiver,
  same design rules learned there:

    * Resolve the LOGGED-ON user's profile. Intune remediations run as
      SYSTEM, whose own profile contains nothing - the Windows version of
      the Jamf /var/root bug that silently produced an empty pilot.
    * Fail loudly. A collector that swallows POST errors across a fleet
      produces a healthy-looking dashboard and false confidence.
    * Throttle info findings to one report per day; warns (personal
      accounts) and never-seen findings report on every run.
    * Report the account DOMAIN, never the mailbox name. The question is
      whether a managed device uses a personal account, not who someone is.

.NOTES
  Deployed via Intune Proactive Remediation (detection script). Exits 1 when
  anything warn-severity was found or a POST failed, so remediation status
  in the Intune console doubles as a fleet health/attention view.

  Configuration is baked in below rather than parameterised: remediation
  scripts take no arguments.
#>

# ------------------------------------------------------------------ config --
$ReceiverBase    = 'https://ai-guard.example.com'   # your receiver's public ingest URL
$Token           = '__RECEIVER_TOKEN__'   # replace before upload, or wire to a secure retrieval
$CorporateDomains = @('example.com')   # accounts on these domains are 'work'; all others warn as personal

$StateDir  = 'C:\ProgramData\ai-guard'
$StateFile = Join-Path $StateDir 'reported.state.json'
$Breadcrumb = Join-Path $StateDir 'last_scan.txt'
$InfoReportIntervalHours = 24

$Endpoint = ''
if ($ReceiverBase) { $Endpoint = ($ReceiverBase.TrimEnd('/')) + '/report' }

# ------------------------------------------------- resolve the real user --
# Remediations run as SYSTEM. The signed-in user's profile is where the AI
# tool configs live. Owner of the explorer.exe process is the reliable
# answer; fall back to the most recently written real profile.
function Get-ConsoleUserProfile {
    try {
        $owner = (Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" |
                  Select-Object -First 1 |
                  Invoke-CimMethod -MethodName GetOwner -ErrorAction Stop)
        if ($owner.User) {
            $prof = Join-Path 'C:\Users' $owner.User
            if (Test-Path $prof) { return @{ User = $owner.User; Home = $prof } }
        }
    } catch { }
    $candidate = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users','defaultuser0') } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($candidate) { return @{ User = $candidate.Name; Home = $candidate.FullName } }
    return $null
}

$Console = Get-ConsoleUserProfile
if (-not $Console) {
    # No user profile: loginwindow-equivalent state. Nothing to scan; exit
    # clean so an unattended machine is not a red remediation.
    Write-Output 'ai-guard: no logged-on user profile found, skipping'
    exit 0
}
$UserHome = $Console.Home
$ConsoleUser = $Console.User

$Serial = ''
try { $Serial = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber.Trim() } catch { }
if (-not $Serial) { $Serial = $env:COMPUTERNAME }

$Now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$NowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

# --------------------------------------------------------------- throttle --
$StateOld = @{}
if (Test-Path $StateFile) {
    try {
        (Get-Content $StateFile -Raw | ConvertFrom-Json).psobject.Properties |
            ForEach-Object { $StateOld[$_.Name] = [int64]$_.Value }
    } catch { $StateOld = @{} }
}
$StateNew = @{}
$script:Posted = 0
$script:Suppressed = 0
$script:PostFailures = 0
$script:WarnCount = 0
$script:ParseFailures = 0
$SummaryParts = New-Object System.Collections.Generic.List[string]

function Get-Domain([string]$email) {
    if ($email -and $email.Contains('@')) { return $email.Split('@')[-1].ToLower() }
    return ''
}

# Extract a single string field value without parsing the whole file. Used
# for configs that are not safely whole-file parseable (see .claude.json).
# Returns the first match's value, or ''.
function Get-JsonStringField {
    param([string]$Path, [string]$Field)
    $m = Select-String -Path $Path -Pattern ('"' + [regex]::Escape($Field) + '"\s*:\s*"([^"]*)"') -List
    if ($m -and $m.Matches.Count -gt 0) { return $m.Matches[0].Groups[1].Value }
    return ''
}

# Collect the KEYS under an "mcpServers" object without whole-file parsing
# (see Get-JsonStringField for why). Walks the object character by character
# tracking brace depth and string state, so it works whether the config is
# pretty-printed or written on a single line. Returns a sorted comma-joined
# string, or ''.
function Get-McpServerNames {
    param([string]$Path)
    $text = Get-Content $Path -Raw
    $m = [regex]::Match($text, '"mcpServers"\s*:\s*\{')
    if (-not $m.Success) { return '' }
    $i = $m.Index + $m.Length
    $depth = 1; $inStr = $false; $esc = $false; $capturing = $false
    $cur = ''; $names = @()
    while ($i -lt $text.Length -and $depth -gt 0) {
        $c = $text[$i]
        if ($inStr) {
            if ($esc) { $esc = $false }
            elseif ($c -eq '`\') { $esc = $true }
            elseif ($c -eq '"') {
                $inStr = $false
                if ($capturing) {
                    # Only a key if the next non-space character is a colon.
                    $j = $i + 1
                    while ($j -lt $text.Length -and [char]::IsWhiteSpace($text[$j])) { $j++ }
                    if ($j -lt $text.Length -and $text[$j] -eq ':') { $names += $cur }
                    $capturing = $false
                }
            }
            elseif ($capturing) { $cur += $c }
        }
        else {
            if ($c -eq '"') { $inStr = $true; if ($depth -eq 1) { $capturing = $true; $cur = '' } }
            elseif ($c -eq '{') { $depth++ }
            elseif ($c -eq '}') { $depth-- }
        }
        $i++
    }
    if ($names.Count -gt 0) { return (($names | Sort-Object) -join ',') }
    return ''
}

function Send-Finding {
    param([string]$Surface, [string]$Tool, [string]$Account, [string]$Evidence)

    $severity = 'info'
    if ($Account -and ($CorporateDomains -notcontains $Account.ToLower())) {
        $severity = 'warn'
        $script:WarnCount++
    }

    if ($Account) { $SummaryParts.Add("$Tool($Account)") } else { $SummaryParts.Add($Tool) }

    $key = "$Surface|$Tool|$Account"
    if ($severity -eq 'info' -and $StateOld.ContainsKey($key)) {
        if (($NowEpoch - $StateOld[$key]) -lt ($InfoReportIntervalHours * 3600)) {
            $StateNew[$key] = $StateOld[$key]
            $script:Suppressed++
            return
        }
    }
    $StateNew[$key] = $NowEpoch

    $payload = @{
        tool = $Tool; surface = $Surface; os = 'windows'
        account_domain = $Account; device = $Serial; user = $ConsoleUser
        evidence = $Evidence; severity = $severity; reported_at = $Now
        source = 'collector-windows'
    } | ConvertTo-Json -Compress

    if (-not $Endpoint) {
        Write-Output "ai-guard FLAG (no endpoint set): $payload"
        return
    }
    try {
        Invoke-RestMethod -Uri $Endpoint -Method Post -TimeoutSec 10 `
            -Headers @{ Authorization = "Bearer $Token" } `
            -ContentType 'application/json' -Body $payload -ErrorAction Stop | Out-Null
        $script:Posted++
    } catch {
        $code = 'ERR'
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        Write-Output "ai-guard POST failed: HTTP $code for $Tool -> $Endpoint"
        $script:PostFailures++
    }
}

# --------------------------------------------------------------- registry --

# Which extension IDs, config paths and MCP files belong to which tool comes
# from the receiver at runtime. It used to be hardcoded here, which meant a
# new AI tool needed a script edit and an Intune re-paste on every machine,
# while the registry that should have owned that list was already maintained
# by merge request. A new tool is now a registry MR only.
function Get-CollectorRegistry {
    if ($env:AIGUARD_REGISTRY_FILE) {
        return (Get-Content $env:AIGUARD_REGISTRY_FILE -Raw | ConvertFrom-Json)
    }
    if (-not $ReceiverBase) { return $null }
    return Invoke-RestMethod -Uri (($ReceiverBase.TrimEnd('/')) + '/registry/collector') `
        -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 15 -ErrorAction Stop
}

$Registry = $null
try { $Registry = Get-CollectorRegistry } catch {
    Write-Output "ai-guard: registry fetch failed ($($_.Exception.Message))"
}
if (-not $Registry) {
    # An empty scan looks exactly like a clean machine. Refuse instead.
    Write-Output 'ai-guard: refusing to scan without an identifier list'
    exit 1
}

# One finding per surface+tool per run: a tool can match several identifiers
# (both Copilot extension IDs, a config path AND an install directory).
$script:Seen = @{}
function Send-FindingOnce {
    param([string]$Surface, [string]$Tool, [string]$Account, [string]$Evidence)
    $key = "$Surface|$Tool"
    if ($script:Seen.ContainsKey($key)) { return }
    $script:Seen[$key] = $true
    Send-Finding -Surface $Surface -Tool $Tool -Account $Account -Evidence $Evidence
}

function Join-UserPath { param([string]$Rel) Join-Path $UserHome ($Rel -replace '/', '\') }

# Decode a JWT payload and pull one claim. Regex rather than ConvertFrom-Json
# for the same reason as Get-JsonStringField: never whole-file parse input we
# do not control.
function Get-JwtClaim {
    param([string]$Jwt, [string]$Claim)
    try {
        $b64 = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
        $m = [regex]::Match($json, '"' + [regex]::Escape($Claim) + '"\s*:\s*"([^"]*)"')
        if ($m.Success) { return $m.Groups[1].Value }
    } catch { }
    return ''
}

# ------------------------------------------------------------------ scans --

# cli: tools that store an account identity in a config file. The registry
# says where the file is and how to read it.
foreach ($t in $Registry.cli) {
    if (-not $t.account_json_path) { continue }   # presence-only tools: desktop scan
    $f = Join-UserPath $t.account_json_path
    if (Test-Path $f) {
        try {
            $email = ''
            if ($t.account_json_keys) {
                # The last key in the path is the field name. Extracted
                # line-wise, never whole-file parsed: .claude.json carries
                # per-project keys that differ only in drive-letter case and
                # .NET rejects those as duplicates.
                $email = Get-JsonStringField -Path $f -Field $t.account_json_keys[-1]
            } elseif ($t.account_jwt_path) {
                $jwt = Get-JsonStringField -Path $f -Field $t.account_jwt_path[-1]
                if ($jwt) { $email = Get-JwtClaim -Jwt $jwt -Claim $t.account_jwt_claim }
            }
            Send-FindingOnce -Surface 'cli' -Tool $t.tool -Account (Get-Domain $email) `
                -Evidence "~/$($t.account_json_path)"
        } catch {
            Write-Output "ai-guard PARSE-FAILED: $($t.tool) $f ($($_.Exception.Message))"
            $script:ParseFailures++
        }
    } else {
        foreach ($c in $t.config_paths) {
            if (Test-Path (Join-UserPath $c)) {
                Send-FindingOnce -Surface 'cli' -Tool $t.tool -Account '' -Evidence "~/$c"
                break
            }
        }
    }
}

# ide: extension directories are named "<extension.id>-<version>". Cursor is a
# VS Code fork and uses the same IDs. chrome/edge IDs in the registry are
# browser extensions and are deliberately not read here.
foreach ($pair in @(@('.vscode\extensions', 'vscode'), @('.cursor\extensions', 'cursor'))) {
    $dir = Join-Path $UserHome $pair[0]
    if (-not (Test-Path $dir)) { continue }
    $subs = Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue
    foreach ($t in $Registry.ide) {
        foreach ($ext in $t.extension_ids.vscode) {
            foreach ($sub in $subs) {
                if ($sub.Name -like "$ext-*") {
                    Send-FindingOnce -Surface 'ide' -Tool $t.tool -Account '' `
                        -Evidence "$($pair[1])/$($sub.Name)"
                }
            }
        }
    }
}

# desktop: installed applications and local runtimes. Intune inventory also
# reports Windows desktop apps, but on a ~24h cycle; this is same-run.
$ProgramDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)},
                 (Join-Path $UserHome 'AppData\Local\Programs')) | Where-Object { $_ }
foreach ($t in $Registry.desktop) {
    foreach ($name in $t.app_names) {
        if ($name -like '*.app') { continue }   # macOS bundle name
        foreach ($base in $ProgramDirs) {
            if (Test-Path (Join-Path $base $name)) {
                Send-FindingOnce -Surface 'desktop' -Tool $t.tool -Account '' -Evidence "$name installed"
            }
        }
    }
}
foreach ($t in $Registry.cli) {
    if ($t.account_json_path) { continue }
    foreach ($c in $t.config_paths) {
        if (Test-Path (Join-UserPath $c)) {
            Send-FindingOnce -Surface 'desktop' -Tool $t.tool -Account '' -Evidence "~/$c"
            break
        }
    }
}

# mcp: which MCP servers each tool has wired in.
foreach ($m in $Registry.mcp) {
    if ($m.os -notin @('any', 'windows')) { continue }
    $f = Join-UserPath $m.path
    if (-not (Test-Path $f)) { continue }
    try {
        $names = Get-McpServerNames -Path $f
        if ($names) {
            Send-FindingOnce -Surface 'mcp' -Tool "$($m.tool)-mcp:$names" -Account '' `
                -Evidence "$($m.path) mcpServers"
        }
    } catch {
        Write-Output "ai-guard PARSE-FAILED: mcp $f ($($_.Exception.Message))"
        $script:ParseFailures++
    }
}

# ---------------------------------------------------------------- summary --
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$StateNew | ConvertTo-Json | Set-Content $StateFile -Encoding UTF8

$postStatus = "posted=$Posted suppressed=$Suppressed"
if ($PostFailures -gt 0) { $postStatus = "POST-FAILED=$PostFailures $postStatus" }
if ($ParseFailures -gt 0) { $postStatus = "PARSE-FAILED=$ParseFailures $postStatus" }
if (-not $Endpoint) { $postStatus = 'print-only' }
$summary = if ($SummaryParts.Count -eq 0) { 'none' } else { $SummaryParts -join '; ' }
"$summary [$postStatus] ($Now)" | Set-Content $Breadcrumb -Encoding UTF8
Write-Output "ai-guard: $summary [$postStatus]"

# Remediation semantics: exit 1 = "needs attention" in the Intune console.
# Warn findings and broken reporting both qualify.
if ($PostFailures -gt 0 -or $WarnCount -gt 0 -or $ParseFailures -gt 0) { exit 1 }
exit 0