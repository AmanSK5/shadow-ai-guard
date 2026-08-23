<#
    ai-guard browser extension: install and configure on Firefox for Windows.

    Separate from the Chromium script because almost nothing is shared. Firefox
    needs the Mozilla-signed .xpi rather than a .crx, installs from the file
    directly rather than polling an update manifest, keys managed storage on
    the gecko id rather than the 32 character Chrome id, and stores policy as
    JSON in a single registry value rather than as individual values.

    Deploy as an Intune platform script alongside the Chromium one. Same
    settings:

        Run this script using the logged on credentials   No
        Enforce script signature check                    No
        Run script in 64 bit PowerShell Host              Yes

    Firefox reads enterprise policy from one of three places, in order:
    HKLM\SOFTWARE\Policies\Mozilla\Firefox, a policies.json next to the
    binary, or the same key under HKCU. This writes the HKLM key, which
    survives a Firefox reinstall where policies.json does not.

    Idempotent, and deliberately a read-modify-write: another policy may
    already own ExtensionSettings or 3rdparty, and clobbering it would silently
    remove someone else's extension.
#>

# SupportsShouldProcess on the script itself, so -WhatIf reaches the helpers
# below: $WhatIfPreference propagates to functions called in the same session,
# but only because the caller declared it. Run it before a fleet rollout:
#
#     .\Deploy-AiGuardExtensionFirefox.ps1 -WhatIf
#
# and it prints every key it would write and writes none of them.
[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- config --
# GeckoId must match browser_specific_settings.gecko.id in the manifest.
# XpiUrl is the SIGNED .xpi returned by addons.mozilla.org, not the one you
# built: Firefox refuses unsigned extensions on release builds.
$GeckoId   = 'REPLACE_WITH_GECKO_ID'
$XpiUrl    = 'https://REPLACE_WITH_HOST/ai-guard-1.0.0.xpi'
$Endpoint  = 'https://REPLACE_WITH_HOST/report'
$AuthToken = 'REPLACE_WITH_TOKEN'

$AllowedDomains = @('example.com')
$PasteGuardMode = 'warn'
$ClassificationMarkings = @(
    'Client Confidential'
    'Internal Confidential'
    'Internal Use Only'
    'Strictly Confidential'
    'Commercial in Confidence'
)

$FirefoxPolicies = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'

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
        Write-Host "ai-guard: BIOS serial is '$serial', using COMPUTERNAME instead"
        return $env:COMPUTERNAME
    }
    return $serial
}

# --------------------------------------------------------------- helpers --
function ConvertTo-Hashtable {
    <#
        A hashtable from either a PSCustomObject or a hashtable.

        This exists because the two arrive by different routes and only one of
        them can be enumerated with .PSObject.Properties. ConvertFrom-Json
        returns a PSCustomObject, whose properties are the JSON keys. A freshly
        created @{} is a hashtable, whose .PSObject.Properties are the .NET
        collection's own members: IsFixedSize, Count, IsSynchronized,
        IsReadOnly, Keys, Values, SyncRoot.

        Enumerating a hashtable that way copied all seven into the policy, so a
        machine with no existing 3rdparty value ended up with an Extensions
        object containing "Count": 0 alongside the real entry. It only happened
        on first install, which is why a merge tested against existing JSON did
        not show it.
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


function Get-JsonPolicy {
    <#
        The existing value of a JSON policy, as a hashtable, or an empty one.

        Read-modify-write rather than overwrite. ExtensionSettings and 3rdparty
        are single values holding every extension's configuration, so writing
        ours wholesale would remove any other extension the organisation
        deploys. Unparseable existing content is left alone and reported:
        replacing something we cannot read is how a working policy disappears.

        Write-Host rather than Write-Output for the progress line.
        PowerShell collects everything a function writes to the output
        stream as its return value, so a message here would come back
        alongside the value. A -WhatIf run caught exactly that: the
        forcelist value name came out as
        "ai-guard: forcelist indexes 1 in use, taking 2 2".
    #>
    param($Path, $Name)
    if (-not (Test-Path $Path)) { return @{} }
    $raw = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if (-not $raw) { return @{} }
    try {
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Host "ai-guard: existing $Name is not valid JSON, refusing to overwrite it"
        throw
    }
    return ConvertTo-Hashtable $obj
}

function Set-JsonPolicy {
    <#
        SupportsShouldProcess so the script can be dry-run. This rewrites a
        policy value that holds every extension's configuration, so seeing what
        it would write before it writes it is worth having:

            .\Deploy-AiGuardExtensionFirefox.ps1 -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param($Path, $Name, $Value)
    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", 'Set policy value')) { return }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name `
        -Value ($Value | ConvertTo-Json -Compress -Depth 10) `
        -PropertyType String -Force | Out-Null
}

$DeviceId = Get-DeviceIdentifier
Write-Output "ai-guard: device identifier = $DeviceId"

# Policies must be switched on at all, or every setting below is ignored.
if ($PSCmdlet.ShouldProcess($FirefoxPolicies, 'Enable enterprise policies')) {
    if (-not (Test-Path $FirefoxPolicies)) {
        New-Item -Path $FirefoxPolicies -Force | Out-Null
    }
    New-ItemProperty -Path $FirefoxPolicies -Name 'EnterprisePoliciesEnabled' `
        -Value 1 -PropertyType DWord -Force | Out-Null
}

# ---- install ----
# install_url, not update_url. Firefox installs from the .xpi and then polls
# the manifest's own gecko.update_url for new versions, so there is no
# override_update_url equivalent and none is needed.
$settings = Get-JsonPolicy $FirefoxPolicies 'ExtensionSettings'
$settings[$GeckoId] = @{
    installation_mode = 'force_installed'
    install_url       = $XpiUrl
    updates_disabled  = $false
}
Set-JsonPolicy $FirefoxPolicies 'ExtensionSettings' $settings

# ---- config ----
# Managed storage lives under 3rdparty > Extensions > the GECKO id. The Chrome
# 32 character id is a different string for the same extension and will not
# work here.
$thirdParty = Get-JsonPolicy $FirefoxPolicies '3rdparty'
$extensions = ConvertTo-Hashtable $thirdParty['Extensions']
$extensions[$GeckoId] = @{
    reportEndpoint         = $Endpoint
    authToken              = $AuthToken
    deviceIdentifier       = $DeviceId
    pasteGuardMode         = $PasteGuardMode
    allowedDomains         = $AllowedDomains
    classificationMarkings = $ClassificationMarkings
}
$thirdParty['Extensions'] = $extensions
Set-JsonPolicy $FirefoxPolicies '3rdparty' $thirdParty

Write-Output "ai-guard: configured Firefox"
Write-Output "ai-guard: done. Check about:policies on the device after a restart."
exit 0