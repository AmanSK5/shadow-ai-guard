<#
.SYNOPSIS
  AI Guard endpoint collector for Windows.

  Reads AI tool configuration files from the logged-on user's profile and
  reports which account domain each tool is signed into, plus installed IDE
  extensions and MCP server configurations. Which identifiers to look for
  come from the receiver's /registry/collector at runtime, so a new AI tool
  is a registry entry - defined in the portal, or by merge request - rather
  than a script edit plus an Intune
  re-paste. The Windows sibling of
  endpoint/macos/ai-guard-collector.sh - same finding schema, same receiver,
  same design rules learned there:

    * Resolve the LOGGED-ON user's profile. Intune remediations run as
      SYSTEM, whose own profile contains nothing - the Windows version of
      the Jamf /var/root bug that silently produced an empty pilot.
    * Fail loudly. A collector that swallows POST errors across a fleet
      produces a healthy-looking dashboard and false confidence.
    * Throttle info findings to one report per day and warn findings
      (personal accounts) to one per hour. A personal account is a
      persistent state, not an event, so repeating it at every check-in
      adds volume without adding information. Never-seen findings report
      immediately at any severity, so an account switch still surfaces on
      the next run.
    * Report the account domain in account_domain; the console username is
      sent in the user field. Both are already known to IT through the MDM.

.NOTES
  Deployed via Intune Proactive Remediation (detection script). Exits 1 when
  anything warn-severity was found or a POST failed, so remediation status
  in the Intune console doubles as a fleet health/attention view.

  Configuration is baked in below rather than parameterised: remediation
  scripts take no arguments. The one switch it does take is not
  configuration: -FunctionsOnly loads the functions and stops before the
  scans, so the path containment logic can be tested without running a
  collection. Intune never passes it.
#>

param([switch]$FunctionsOnly)

# ------------------------------------------------------------------ config --
$ReceiverBase    = 'https://ai-guard.example.com'   # your receiver's public ingest URL
$Token           = '__RECEIVER_TOKEN__'   # replace before upload, or wire to a secure retrieval.
                                          # Either the shared token, or an enrollment token (aige_...)
                                          # from a managed-mode receiver: on first run the machine
                                          # enrolls, stores its own device credential in ProgramData,
                                          # and uses that from then on. Swapping the shared token for
                                          # an enrollment token here is the whole migration.
$CorporateDomains = @('example.com')   # accounts on these domains are 'work'; all others warn as personal.
                                       # A receiver that serves config.corp_domains in /registry/collector
                                       # overrides this at runtime; the constant is the fallback.

$StateDir  = 'C:\ProgramData\ai-guard'
$StateFile = Join-Path $StateDir 'reported.state.json'
$Breadcrumb = Join-Path $StateDir 'last_scan.txt'
# This machine's own credential, once enrolled with a managed-mode receiver.
# ACL-restricted to SYSTEM and Administrators: it is this device's identity.
$CredFile = Join-Path $StateDir 'device.cred'
# Reported at enrollment and on every report, so the receiver's inventory can
# answer "which script version does the fleet actually run".
$CollectorVersion = '2.0.0'
$InfoReportIntervalHours = 24
$WarnReportIntervalHours = 1

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
    } catch {
        # Ordinary: no interactive session, or explorer.exe is not running.
        # The profile below is a real answer, not a guess of last resort, so
        # this is noted rather than reported.
        Write-Verbose "console user lookup failed: $($_.Exception.Message)"
    }
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

# device carries the serial: immutable, and what Jamf, Intune, SentinelOne and
# most RMMs key on. device_name carries the hostname, which is what a human
# recognises and what platforms with no serial can still join on. The dashboard
# prefers device_name and falls back to device, so a collector that sends only
# the serial shows a serial where the scanners show a name.
$DeviceName = $env:COMPUTERNAME

$Serial = ''
try {
    $Serial = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber.Trim()
} catch {
    # Said out loud, because the fallback below changes what every finding
    # from this machine is keyed on. One device reporting a hostname where
    # the rest report serials reads as a deliberate difference rather than a
    # failed WMI query, and it splits that device into two on any dashboard
    # that groups by device.
    Write-Output "ai-guard: serial lookup failed ($($_.Exception.Message)), using COMPUTERNAME"
}
if (-not $Serial) { $Serial = $DeviceName }

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
# The plural is correct: this returns every server named in the config, not
# one. Renaming it to satisfy the rule would make the name less true than the
# warning it silences, so the rule is suppressed instead. The attribute
# belongs inside the function, above param: PowerShell rejects it in front of
# the declaration.
function Get-McpServerNames {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Returns every server named in the config, not one.')]
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

    # Throttle by severity: info daily, warn hourly. A key with no previous
    # timestamp falls through regardless, so new findings are never delayed.
    $key = "$Surface|$Tool|$Account"
    $intervalHours = if ($severity -eq 'warn') { $WarnReportIntervalHours } else { $InfoReportIntervalHours }
    if ($StateOld.ContainsKey($key)) {
        if (($NowEpoch - $StateOld[$key]) -lt ($intervalHours * 3600)) {
            $StateNew[$key] = $StateOld[$key]
            $script:Suppressed++
            return
        }
    }

    $payload = @{
        tool = $Tool; surface = $Surface; os = 'windows'
        account_domain = $Account; device = $Serial; device_name = $DeviceName
        user = $ConsoleUser
        evidence = $Evidence; severity = $severity; reported_at = $Now
        source = 'collector-windows'
    } | ConvertTo-Json -Compress

    if (-not $Endpoint) {
        Write-Output "ai-guard FLAG (no endpoint set): $payload"
        # Print-only: preserve old timestamp if one exists, but don't advance it.
        if ($StateOld.ContainsKey($key)) { $StateNew[$key] = $StateOld[$key] }
        return
    }
    try {
        Invoke-RestMethod -Uri $Endpoint -Method Post -TimeoutSec 10 `
            -Headers @{ Authorization = "Bearer $Token"
                        'X-AiGuard-Agent-Version' = $CollectorVersion } `
            -ContentType 'application/json' -Body $payload -ErrorAction Stop | Out-Null
        $script:Posted++
        $StateNew[$key] = $NowEpoch
    } catch {
        $code = 'ERR'
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        Write-Output "ai-guard POST failed: HTTP $code for $Tool -> $Endpoint"
        $script:PostFailures++
        # Keep the old timestamp so the finding retries next run.
        if ($StateOld.ContainsKey($key)) { $StateNew[$key] = $StateOld[$key] }
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

# Skipped under -FunctionsOnly: fetching a registry is work, and the refusal
# below would exit the caller's session before the functions further down
# were ever defined.
# ------------------------------------------------------------ enrollment --
# Managed mode. A stored device credential wins; an enrollment token
# (aige_...) is exchanged for one on first run; anything else is today's
# behaviour exactly. The prefix is the whole switch: the operator changes the
# $Token constant from the shared token to an enrollment token when ready.
if (-not $FunctionsOnly) {
    if (Test-Path $CredFile) {
        $stored = (Get-Content $CredFile -Raw -ErrorAction SilentlyContinue)
        if ($stored) { $stored = $stored.Trim() }
        if ($stored -and $stored.StartsWith('aigd_')) { $Token = $stored }
    }
    if ($Token.StartsWith('aige_') -and $ReceiverBase) {
        if (-not (Test-Path $StateDir)) {
            New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
        }
        $enrollBody = @{
            platform = 'windows'; serial = $Serial
            hostname = $DeviceName; agent_version = $CollectorVersion
        } | ConvertTo-Json -Compress
        try {
            $r = Invoke-RestMethod -Uri (($ReceiverBase.TrimEnd('/')) + '/enroll') `
                -Method Post -TimeoutSec 15 `
                -Headers @{ Authorization = "Bearer $Token" } `
                -ContentType 'application/json' -Body $enrollBody -ErrorAction Stop
            try {
                Set-Content -Path $CredFile -Value $r.device_token -NoNewline -ErrorAction Stop
            } catch {
                # Loud and fatal, like an enrollment refusal: the receiver
                # just minted this device a credential, and losing it here
                # means every run enrolls again - device churn in the fleet
                # view and, once a run reports, a 409 that blocks the fix for
                # an hour. Exiting before the scan keeps this device silent,
                # so a correctly privileged run supersedes it immediately.
                Write-Output "ai-guard: enrolled, but cannot write $CredFile (run as SYSTEM or elevated?)"
                Write-Output 'ai-guard: refusing to scan - the credential would be lost and every run would re-enroll'
                exit 1
            }
            # The state dir inherits ProgramData's ACL, which lets ordinary
            # users read. A device credential must not be readable by the
            # people whose AI accounts it reports on - so an ACL that cannot
            # be restricted means the file must not stay behind either.
            icacls $CredFile /inheritance:r /grant 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Remove-Item $CredFile -Force -ErrorAction SilentlyContinue
                Write-Output "ai-guard: enrolled, but could not restrict $CredFile to SYSTEM/Administrators"
                Write-Output 'ai-guard: refusing to scan - a device credential readable by every user is worse than none'
                exit 1
            }
            $Token = $r.device_token
            Write-Output "ai-guard: enrolled, device credential stored in $CredFile"
        } catch {
            # Loud and fatal: an enrollment token cannot report findings, so
            # carrying on would 401 every POST and look like a clean machine.
            # A 409 means a device with this serial is actively reporting -
            # revoke it on the receiver first. A 401 usually means the token
            # expired: mint a fresh one and update this script in Intune.
            $code = 'ERR'
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            Write-Output "ai-guard: enrollment failed (HTTP $code)"
            Write-Output 'ai-guard: refusing to scan - an enrollment token cannot report findings'
            exit 1
        }
    }
}

$Registry = $null
if (-not $FunctionsOnly) {
    try { $Registry = Get-CollectorRegistry } catch {
        Write-Output "ai-guard: registry fetch failed ($($_.Exception.Message))"
    }
    if (-not $Registry) {
        # An empty scan looks exactly like a clean machine. Refuse instead.
        Write-Output 'ai-guard: refusing to scan without an identifier list'
        if ($Token.StartsWith('aigd_')) {
            Write-Output "ai-guard: this machine's device credential may have been revoked;"
            Write-Output "ai-guard: delete $CredFile and supply a valid enrollment token to re-enroll"
        }
        exit 1
    }

    # Corporate domains can arrive with the registry: the receiver serves
    # config.corp_domains in the payload just fetched when it has CORP_DOMAINS
    # set. The served list wins over the constant above, because a list
    # changed once on the receiver reaches the fleet on its next run rather
    # than waiting on an Intune re-paste; the constant stays as the fallback,
    # so a receiver serving nothing changes nothing. Lowercased to match the
    # severity check, which lowercases the account side.
    if ($Registry.PSObject.Properties['config'] -and $Registry.config.corp_domains) {
        $CorporateDomains = @($Registry.config.corp_domains | ForEach-Object { "$_".ToLower() })
        Write-Output "ai-guard: corporate domains from receiver: $($CorporateDomains -join ',')"
    }
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

# Registry-supplied paths are documented as relative to the user's profile,
# but the collector runs as SYSTEM and the registry arrives over the network,
# so the value is treated as input rather than configuration. Absolute paths,
# drive letters, parent traversal and control characters return $null and the
# caller skips that entry.
#
# Skipped rather than fatal: aborting would let one poisoned path switch off
# detection everywhere, which suits an attacker better than being ignored.
function Test-SafeRelativePath {
    param([string]$Rel)
    if ([string]::IsNullOrWhiteSpace($Rel)) { return $false }
    if ($Rel.Length -gt 256) { return $false }
    if ($Rel -match '^[\\/]' -or $Rel -match '^[A-Za-z]:') { return $false }
    if ($Rel -match '\.\.') { return $false }
    if ($Rel -match '[\x00-\x1f]') { return $false }
    return $true
}


# Get-LinkTarget <item> - where a reparse point points, or $null.
#
# Hard links are deliberately not followed. A hard link is not a redirect:
# both names are equally the file, and resolving one to the other would move
# an ordinary file to some unrelated path, possibly outside the profile, for
# no reason. Windows PowerShell exposes LinkType; PowerShell 6 and later
# expose LinkTarget, which is already null for a hard link.
function Get-LinkTarget {
    param($Item)
    if (-not $Item) { return $null }
    $type = $null
    if ($Item.PSObject.Properties['LinkType']) { $type = $Item.LinkType }
    if ($type -and $type -ne 'SymbolicLink' -and $type -ne 'Junction') { return $null }
    if ($Item.PSObject.Properties['LinkTarget'] -and $Item.LinkTarget) {
        return $Item.LinkTarget
    }
    if ($Item.PSObject.Properties['Target'] -and $Item.Target) {
        return @($Item.Target)[0]
    }
    return $null
}

# Resolve-PhysicalPath <path> - the path with every reparse point resolved.
#
# Walks the path a component at a time, because a junction partway along is
# invisible from the end of it: Get-Item on the final file reports no link,
# and GetFullPath only tidies the text. So
#
#   C:\Users\alice\AppData\Roaming\Claude   -> junction outside the profile
#   C:\Users\alice\AppData\Roaming\Claude\config.json
#
# reads as a path inside the profile while the file is somewhere else. The
# macOS and Linux collectors get this free from pwd -P; Windows has no
# equivalent that works on both Windows PowerShell and PowerShell 7, so the
# walk is done here.
#
# Following a link starts the walk again from the root rather than carrying
# on from where the link was. The target has parents of its own, and any of
# them can be a junction:
#
#   C:\Users\alice\a   -> link to C:\Users\alice\b\sub
#   C:\Users\alice\b   -> junction outside the profile
#
# Continuing from the target would land on C:\Users\alice\b\sub\config.json,
# which reads as inside the profile and is not.
function Resolve-PhysicalPath {
    param([string]$Path, [int]$Hops = 0)
    if (-not $Path) { return $null }
    if ($Hops -gt 40) { return $null }   # a link loop, or someone being clever

    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if (-not $root) { return $null }

    $current = $root
    $parts = $full.Substring($root.Length).Split(
        [char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $current = Join-Path $current $parts[$i]
        if (-not (Test-Path -LiteralPath $current)) { return $null }

        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        $target = Get-LinkTarget $item
        if ($target) {
            if (-not [IO.Path]::IsPathRooted($target)) {
                $target = Join-Path (Split-Path -Parent $current) $target
            }
            if ($i + 1 -lt $parts.Count) {
                $rest = $parts[($i + 1)..($parts.Count - 1)] -join '\'
                $target = Join-Path $target $rest
            }
            return Resolve-PhysicalPath -Path $target -Hops ($Hops + 1)
        }
    }
    [IO.Path]::GetFullPath($current)
}

# Resolve-UnderHome <path> - the real path if it stays inside the profile,
# $null if it does not.
#
# Test-SafeRelativePath rejects a registry value that tries to escape. This
# catches the other half: a path that looks fine but resolves elsewhere,
# because a junction or symlink on the machine points out of the profile. The
# collector runs as SYSTEM, so following one reads a file the user could not.
#
# Links are resolved rather than refused. Redirected profile folders are
# ordinary on managed Windows, and refusing to follow any of them would drop
# real findings to prevent an unlikely one.
function Resolve-UnderHome {
    param([string]$Path)
    $real = Resolve-PhysicalPath $Path
    if (-not $real) { return $null }

    # Resolved once and kept: the profile is physically resolved too, or a
    # machine whose whole profile is redirected would fail every check. The
    # trailing separator stops a sibling directory whose name merely starts
    # the same way from passing.
    if (-not $script:UserHomeResolved) {
        $profileRoot = Resolve-PhysicalPath $UserHome
        if (-not $profileRoot) {
            $profileRoot = [IO.Path]::GetFullPath($UserHome)
        }
        $script:UserHomeResolved = $profileRoot.TrimEnd('\') + '\'
    }
    if ($real.StartsWith($script:UserHomeResolved, [StringComparison]::OrdinalIgnoreCase)) {
        return $real
    }
    return $null
}

function Join-UserPath {
    param([string]$Rel)
    if (-not (Test-SafeRelativePath $Rel)) {
        Write-Output "ai-guard REFUSED: registry path not relative to profile"
        return $null
    }
    $joined = Join-Path $UserHome ($Rel -replace '/', '\')
    # Not every caller is about to read the file; some only test
    # existence. Resolve when it exists so the containment check applies
    # to what would actually be opened, and hand back the joined path
    # otherwise so a missing file stays missing rather than a refusal.
    if (Test-Path -LiteralPath $joined) {
        return (Resolve-UnderHome $joined)
    }
    $joined
}

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
    } catch {
        # A token that will not decode means a finding with no account
        # domain, which the caller already reports as presence only. Noted
        # for anyone debugging why a tool shows up without an account.
        Write-Verbose "jwt claim '$Claim' could not be read: $($_.Exception.Message)"
    }
    return ''
}

# Stop here when only the functions were wanted. Dot-sourcing the whole
# script otherwise runs a collection, and the exit calls further down would
# end the caller's session.
if ($FunctionsOnly) { return }

# ------------------------------------------------------------------ scans --

# cli: tools that store an account identity in a config file. The registry
# says where the file is and how to read it.
foreach ($t in $Registry.cli) {
    if (-not $t.account_json_path) { continue }   # presence-only tools: desktop scan
    $f = Join-UserPath $t.account_json_path
    if (-not $f) { continue }
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
            $cp = Join-UserPath $c
            if ($cp -and (Test-Path $cp)) {
                Send-FindingOnce -Surface 'cli' -Tool $t.tool -Account '' -Evidence "~/$c"
                break
            }
        }
    }
}

# ide: extension directories are named "<extension.id>-<version>". Cursor is a
# VS Code fork and uses the same IDs. chrome/edge IDs in the registry are
# browser extensions and are read in the browser section below.
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

# browser: installed browser extensions, matched by extension id against the
# registry. Presence is the finding: an AI extension reads pages without
# anything being pasted. Chrome and Brave install from the Chrome store, so
# both match chrome ids; Edge installs from both stores, so it matches both.
$BrowserRoots = @(
    @{ Path = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data';               Label = 'Chrome'; Kinds = @('chrome') },
    @{ Path = Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'; Label = 'Brave';  Kinds = @('chrome') },
    @{ Path = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data';              Label = 'Edge';   Kinds = @('chrome', 'edge') }
)
foreach ($b in $BrowserRoots) {
    if (-not (Test-Path $b.Path)) { continue }
    $profiles = Get-ChildItem $b.Path -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
    foreach ($p in $profiles) {
        $extDir = Join-Path $p.FullName 'Extensions'
        if (-not (Test-Path $extDir)) { continue }
        $installed = @((Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue).Name)
        if (-not $installed) { continue }
        foreach ($t in $Registry.ide) {
            foreach ($kind in $b.Kinds) {
                foreach ($id in $t.extension_ids.$kind) {
                    if ($installed -contains $id) {
                        Send-FindingOnce -Surface 'browser' -Tool $t.tool -Account '' `
                            -Evidence "$($b.Label)/$($p.Name) extension $id"
                    }
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
        $cp = Join-UserPath $c
        if ($cp -and (Test-Path $cp)) {
            Send-FindingOnce -Surface 'desktop' -Tool $t.tool -Account '' -Evidence "~/$c"
            break
        }
    }
}

# mcp: which MCP servers each tool has wired in.
foreach ($m in $Registry.mcp) {
    if ($m.os -notin @('any', 'windows')) { continue }
    $f = Join-UserPath $m.path
    if (-not $f) { continue }
    if (-not (Test-Path $f)) { continue }
    try {
        $names = Get-McpServerNames -Path $f
        if ($names) {
            # The tool is the tool. The server list is evidence, not
            # identity: folding it into the name made every distinct
            # combination of servers a separate tool, so a machine with
            # figma and context7 looked unrelated to a machine with figma
            # alone. About twenty two near-identical rows where there
            # should have been three.
            Send-FindingOnce -Surface 'mcp' -Tool "$($m.tool)-mcp" -Account '' `
                -Evidence "$($m.path) mcpServers: $names"
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