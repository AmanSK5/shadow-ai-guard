<#
    ai-guard browser extension: install and configure on Windows.

    Deploy as an Intune platform script (Devices > Scripts and remediations >
    Platform scripts). Settings that matter:

        Run this script using the logged on credentials   No
        Enforce script signature check                    No
        Run script in 64 bit PowerShell Host              Yes

    The first must be No: every key here is under HKLM and a user context
    cannot write them. The third should be Yes. HKLM\SOFTWARE\Policies is one
    of the keys shared between the 32 and 64 bit registry views rather than
    redirected, so a 32 bit host would probably work, and "probably" is not
    worth carrying on a fleet-wide policy.

    This does what two Jamf payloads do on macOS. Chromium browsers read the
    install policy from the browser's own policy key and the managed config
    from a 3rdparty subkey, and neither is expressible as an Intune ADMX
    setting: the 3rdparty path is arbitrary registry defined by the
    extension's own managed schema, not a Chrome policy. So it is a script.

    A script is also the only way to get the device identifier right.
    %COMPUTERNAME% in a .reg file is a literal string to Chrome, not an
    environment variable, and even expanded it would be the hostname. Every
    other source keys a device on its hardware serial, and one that sends a
    hostname splits that machine into two on any view that groups by device.

    Idempotent. Safe to re-run, and re-running is how a changed token reaches
    a machine that was already configured.
#>

# SupportsShouldProcess on the script itself, so -WhatIf reaches the helpers
# below: $WhatIfPreference propagates to functions called in the same session,
# but only because the caller declared it. Run it before a fleet rollout:
#
#     .\Deploy-AiGuardExtension.ps1 -WhatIf
#
# and it prints every key it would write and writes none of them.
[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- config --
# Replace all three. EXTENSION_ID is the 32 character id Chrome derives from
# the manifest key: read it from chrome://extensions on a machine that already
# has it, not from anywhere else.
$ExtensionId = 'REPLACE_WITH_EXTENSION_ID'
$UpdatesXml  = 'https://REPLACE_WITH_HOST/updates.xml'
$Endpoint    = 'https://REPLACE_WITH_HOST/report'
$AuthToken   = 'REPLACE_WITH_TOKEN'

$AllowedDomains = @('example.com')
$PasteGuardMode = 'warn'
$ClassificationMarkings = @(
    'Client Confidential'
    'Internal Confidential'
    'Internal Use Only'
    'Strictly Confidential'
    'Commercial in Confidence'
)

# Chromium browsers on Windows, by policy root. All three read the same
# schema, so they differ only in where the policy lives.
#
# Writing policy for a browser that is not installed is harmless: the key sits
# unread until someone installs it, at which point the extension arrives with
# it. That is the right default for a fleet where any of the three might be
# installed later.
#
# Firefox is not here. It does not read extension policy from these keys, it
# needs the Mozilla-signed .xpi rather than a .crx, and its managed storage is
# keyed on the gecko id rather than the 32 character Chrome id. See
# Deploy-AiGuardExtensionFirefox.ps1.
$Browsers = @{
    'Chrome' = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    'Edge'   = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    'Brave'  = 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
}

# ------------------------------------------------------------ device id --
# Serials that are not serials. OEMs ship these in the BIOS field on machines
# that were never given one, and they are worse than a hostname: a hostname
# splits one machine into two, whereas fifty machines all reporting
# "To Be Filled By O.E.M." collapse into one device and the other forty nine
# disappear from every count.
$BogusSerials = @(
    'to be filled by o.e.m.'
    'to be filled by oem'
    'default string'
    'system serial number'
    'not specified'
    'not applicable'
    'none'
    'invalid'
    'o.e.m.'
    '0'
    '123456789'
)

function Get-DeviceIdentifier {
    $serial = ''
    try {
        $serial = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber
        if ($null -ne $serial) { $serial = $serial.Trim() }
    } catch {
        Write-Host "ai-guard: serial lookup failed ($($_.Exception.Message))"
    }

    if (-not $serial -or $BogusSerials -contains $serial.ToLower()) {
        # Said out loud, because this changes what every finding from this
        # machine is keyed on. One device reporting a hostname where the rest
        # report serials reads as a deliberate difference rather than a
        # placeholder BIOS, and it is worth someone seeing in the Intune
        # script output.
        Write-Host "ai-guard: BIOS serial is '$serial', using COMPUTERNAME instead"
        return $env:COMPUTERNAME
    }
    return $serial
}

# --------------------------------------------------------------- helpers --
function Set-RegValue {
    <#
        SupportsShouldProcess so the script can be dry-run. This writes policy
        that applies to every browser on the machine, and being able to see
        what it would do before it does it is worth four lines:

            .\Deploy-AiGuardExtension.ps1 -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param($Path, $Name, $Value)
    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", 'Set registry value')) { return }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value `
        -PropertyType String -Force | Out-Null
}

function ConvertTo-Hashtable {
    <#
        A hashtable from either a PSCustomObject or a hashtable.

        ConvertFrom-Json returns a PSCustomObject, whose properties are the JSON
        keys. A freshly created @{} is a hashtable, whose .PSObject.Properties
        are the .NET collection's own members: IsFixedSize, Count, Keys,
        SyncRoot and the rest. Enumerating the second as though it were the
        first copies all of them into the policy.
    #>
    param($Object)
    $out = @{}
    if ($null -eq $Object) { return $out }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) { $out[$k] = $Object[$k] }
        return $out
    }
    foreach ($p in $Object.PSObject.Properties) { $out[$p.Name] = $p.Value }
    return $out
}


function Get-ExtensionSettings {
    <#
        The existing ExtensionSettings for a browser, as a hashtable.

        Read-modify-write, for the same reason the Firefox script does it: this
        one value holds every extension's configuration, so writing ours
        wholesale removes anything another policy put there. The Firefox script
        had this from the start because a real machine turned out to have
        SentinelOne's extension in that value; the Chromium script did not, and
        overwrote it.

        Unparseable existing content stops the script rather than being
        replaced, because silently discarding a policy we cannot read is the
        failure this is meant to prevent.
    #>
    param($Root)
    if (-not (Test-Path $Root)) { return @{} }
    $raw = (Get-ItemProperty -Path $Root -Name 'ExtensionSettings' -ErrorAction SilentlyContinue).ExtensionSettings
    if (-not $raw) { return @{} }
    try {
        return ConvertTo-Hashtable ($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Write-Host "ai-guard: existing ExtensionSettings at $Root is not valid JSON, refusing to overwrite it"
        throw
    }
}


function ConvertTo-JsonArray {
    <#
        A JSON array, even when there is one element.

        `@('a') | ConvertTo-Json` returns the string "a", not ["a"], because the
        pipeline unwraps a single-element array before ConvertTo-Json ever sees
        it. The managed schema declares allowedDomains as an array and the
        extension checks Array.isArray, so a scalar is discarded and the
        built-in fallback list is used instead.

        That failure is silent and looks like success: one corporate domain
        configured, and the extension quietly running on its own defaults. It
        was found by reading the registry after a deployment, not by anything
        going wrong.

        The unary comma wraps the value in an outer array so the pipeline has
        something to unwrap, and PowerShell 5.1 is what Intune runs, so -AsArray
        is not available.
    #>
    param([string[]]$Items)
    if ($null -eq $Items -or $Items.Count -eq 0) { return '[]' }
    if ($Items.Count -eq 1) { return ConvertTo-Json @(, $Items[0]) -Compress }
    return ConvertTo-Json $Items -Compress
}


function Get-ForcelistIndex {
    <#
        The index to write this extension's forcelist entry at.

        The forcelist is a set of numbered values, and the numbers are just
        slots. Hardcoding "1" is how a script evicts whatever another policy
        already force-installed there, which on a managed fleet is somebody
        else's extension disappearing with no error and no obvious cause.

        Returns the existing index if this extension is already listed, so
        re-running updates in place rather than adding a duplicate. Otherwise
        the lowest free number.

        Write-Host rather than Write-Output for the progress line.
        PowerShell collects everything a function writes to the output
        stream as its return value, so a message here would come back
        alongside the value. A -WhatIf run caught exactly that: the
        forcelist value name came out as
        "ai-guard: forcelist indexes 1 in use, taking 2 2".
    #>
    param($Path)
    if (-not (Test-Path $Path)) { return '1' }

    $existing = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $used = @()
    foreach ($prop in $existing.PSObject.Properties) {
        if ($prop.Name -notmatch '^\d+$') { continue }   # PSPath and friends
        if ($prop.Value -like "$ExtensionId;*" -or $prop.Value -eq $ExtensionId) {
            Write-Host "ai-guard: already at forcelist index $($prop.Name), updating in place"
            return $prop.Name
        }
        $used += [int]$prop.Name
    }

    $i = 1
    while ($used -contains $i) { $i++ }
    if ($i -ne 1) { Write-Host "ai-guard: forcelist indexes $($used -join ', ') in use, taking $i" }
    return "$i"
}


$DeviceId = Get-DeviceIdentifier
Write-Output "ai-guard: device identifier = $DeviceId"

# ExtensionSettings is what makes a browser poll a self-hosted updates.xml for
# NEW versions. The forcelist alone installs the extension and then never
# updates it, which is a fleet frozen on whatever version it first received.

foreach ($name in $Browsers.Keys) {
    $root = $Browsers[$name]

    # Install
    Set-RegValue "$root\ExtensionInstallForcelist" `
        (Get-ForcelistIndex "$root\ExtensionInstallForcelist") `
        "$ExtensionId;$UpdatesXml"
    $settings = Get-ExtensionSettings $root
    $settings[$ExtensionId] = @{
        installation_mode   = 'force_installed'
        update_url          = $UpdatesXml
        override_update_url = $true
    }
    Set-RegValue $root 'ExtensionSettings' ($settings | ConvertTo-Json -Compress -Depth 10)

    # Config. Lists are JSON strings: the managed storage schema declares them
    # as arrays and the registry has no array type Chrome will read here.
    $policy = "$root\3rdparty\extensions\$ExtensionId\policy"
    Set-RegValue $policy 'reportEndpoint'   $Endpoint
    Set-RegValue $policy 'authToken'        $AuthToken
    Set-RegValue $policy 'deviceIdentifier' $DeviceId
    Set-RegValue $policy 'pasteGuardMode'   $PasteGuardMode
    Set-RegValue $policy 'allowedDomains'         (ConvertTo-JsonArray $AllowedDomains)
    Set-RegValue $policy 'classificationMarkings' (ConvertTo-JsonArray $ClassificationMarkings)

    Write-Output "ai-guard: configured $name"
}

Write-Output "ai-guard: done. The extension appears after the browser restarts."
exit 0