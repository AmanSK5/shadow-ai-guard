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
        Write-Output "ai-guard: serial lookup failed ($($_.Exception.Message))"
    }

    if (-not $serial -or $BogusSerials -contains $serial.ToLower()) {
        # Said out loud, because this changes what every finding from this
        # machine is keyed on. One device reporting a hostname where the rest
        # report serials reads as a deliberate difference rather than a
        # placeholder BIOS, and it is worth someone seeing in the Intune
        # script output.
        Write-Output "ai-guard: BIOS serial is '$serial', using COMPUTERNAME instead"
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

$DeviceId = Get-DeviceIdentifier
Write-Output "ai-guard: device identifier = $DeviceId"

# ExtensionSettings is what makes a browser poll a self-hosted updates.xml for
# NEW versions. The forcelist alone installs the extension and then never
# updates it, which is a fleet frozen on whatever version it first received.
$ExtensionSettings = @{
    $ExtensionId = @{
        installation_mode   = 'force_installed'
        update_url          = $UpdatesXml
        override_update_url = $true
    }
} | ConvertTo-Json -Compress -Depth 5

foreach ($name in $Browsers.Keys) {
    $root = $Browsers[$name]

    # Install
    Set-RegValue "$root\ExtensionInstallForcelist" '1' "$ExtensionId;$UpdatesXml"
    Set-RegValue $root 'ExtensionSettings' $ExtensionSettings

    # Config. Lists are JSON strings: the managed storage schema declares them
    # as arrays and the registry has no array type Chrome will read here.
    $policy = "$root\3rdparty\extensions\$ExtensionId\policy"
    Set-RegValue $policy 'reportEndpoint'   $Endpoint
    Set-RegValue $policy 'authToken'        $AuthToken
    Set-RegValue $policy 'deviceIdentifier' $DeviceId
    Set-RegValue $policy 'pasteGuardMode'   $PasteGuardMode
    Set-RegValue $policy 'allowedDomains' `
        ($AllowedDomains | ConvertTo-Json -Compress)
    Set-RegValue $policy 'classificationMarkings' `
        ($ClassificationMarkings | ConvertTo-Json -Compress)

    Write-Output "ai-guard: configured $name"
}

# The forcelist index. "1" is used above; if a browser already has forcelist
# entries from another policy, this overwrites entry 1. Check before rollout:
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist'
# and move to the next free index if 1 is taken.

Write-Output "ai-guard: done. The extension appears after the browser restarts."
exit 0