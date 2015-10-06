<#
  .SYNOPSIS
    Removes specified host name from hosts file
#>
Function Remove-Host {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$HostName
    )

    Write-Host "Removing $HostName from host file."
    $fileLocation = "$Env:windir\System32\drivers\etc\hosts"
    $content = Get-Content $fileLocation
    $newLines = @()

    foreach ($line in $content) {
        $bits = [regex]::Split($line, "\s+")
        if ($bits.count -ge 2) {
            if ($bits[1] -ne $HostName) {
                $newLines += $line
            }
        } else {
            $newLines += $line
        }
    }

    # Write file
    Clear-Content $fileLocation
    foreach ($line in $newLines) {
        $line | Out-File -encoding ASCII -append $fileLocation
    }
}

<#
  .SYNOPSIS
    Adds host and IP entry to hosts file
#>
Function Add-Host {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        [Parameter(Mandatory=$true)]
        [string]$HostName,
        [bool]$Retry = $true
    )

    $marker = "# Fake:$HostName"
    $fileLocation = "$Env:windir\System32\drivers\etc\hosts"
    $newHostEntry = "$IPAddress`t$HostName`t$marker"

    if (Select-String -Simple $marker $fileLocation) {
        Write-Host "Marker found in host file."
        Remove-Host -HostName $HostName

        # Let's not retry in case we have an infinite loop here
        if ($Retry -eq $true) {
            Add-Host -IPAddress $IPAddress -HostName $HostName -Retry $false
        }
    } else {
        Write-Host "Adding $IPAddress $HostName to the host file."

        # Powershell will not add a ENTER if there was none before...
        # So let's just make sure and add one ourself
        # Doing a Select -last 1 never returns the last empty line if it's empty
        # -Raw is only in powershell 3.0 while -Delimiter is available in 2.0. It's nice to support 2.0
        # Add-Content will add one more space
        if (!((Get-Content $fileLocation -Delimiter "~##DOESNOTEXIST##~") -imatch "`r`n$")) {
            Add-Content -Path $fileLocation -Value "`r`n"
        }

        Add-Content -Path $fileLocation -Value $newHostEntry
    }
}

<#
  .SYNOPSIS
    Determines if executing script under credientials that have admin priviliges
#>
Function Test-IsAdmin {
    Try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
        Return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } Catch {
        Throw "Failed to determine if the current user has elevated privileges. The error was: '{0}'." -f $_
    }
}

<#
  .SYNOPSIS
    Overrides proxy settings for a given domain
#>
Function Update-ProxyOverrideSetting {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteExtensionHost,
        [Parameter(Mandatory=$false)]
        [bool]$Remove = $false
    )

    $ProxyOverrideRegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $ProxyOverrideRegistryValue = "ProxyOverride"
    $ProxyOverrideRegistryKey = Get-ItemProperty $ProxyOverrideRegistryPath
    if ($ProxyOverrideRegistryKey.$ProxyOverrideRegistryValue)
    {
        $CurrentProxyOverride = ($ProxyOverrideRegistryKey | Select-Object -ExpandProperty $ProxyOverrideRegistryValue)
    }

    Try {

        # check if the domain is already in the proxy overrides
        $proxyOverrideMatches = Select-String -Pattern $RemoteExtensionHost -InputObject $CurrentProxyOverride

        if ($Remove) {
            if ($proxyOverrideMatches -ne $null) {
                Write-Host "Removing host '$RemoteExtensionHost' from proxy override list."
                $ValueToWrite = $CurrentProxyOverride.Replace($RemoteExtensionHost, "")

                Set-ItemProperty -Path $ProxyOverrideRegistryPath -Name $ProxyOverrideRegistryValue -Value $ValueToWrite
            } else {
                Write-Host "Host '$RemoteExtensionHost' does not exist in the proxy override list."
            }
        } else {
            if ($proxyOverrideMatches -eq $null) {
                Write-Host "Adding host '$RemoteExtensionHost' to proxy override list."
                $ValueToWrite = $RemoteExtensionHost

                # if there are other values separate with a semi-colon
                if ($CurrentProxyOverride) {
                    $ValueToWrite = $ValueToWrite + ";" + $CurrentProxyOverride
                }

                Set-ItemProperty -Path $ProxyOverrideRegistryPath -Name $ProxyOverrideRegistryValue -Value $ValueToWrite
            } else {
                Write-Host "Host '$RemoteExtensionHost' is already in proxy override list."
            }
        }
    } Catch {
        Throw "Failed to configure proxy override list. The error was: '{0}'." -f $_
    }
}

#******************************************************************************
# Script body
# Execution begins here
#******************************************************************************

if (!(Test-IsAdmin)) {
    Write-Host "You must run this setup in an elevated window."
    exit
}
$a = 12345
$ibizaTestHost = "10.123.171.113"
$stbPortalHost = "onestb.cloudapp.net"

Write-Host "Uninstalling known host entries"
Remove-Host -HostName $stbPortalHost
Update-ProxyOverrideSetting -RemoteExtensionHost $stbPortalHost -Remove $true
Add-Host -IPAddress $ibizaTestHost -HostName $stbPortalHost
Update-ProxyOverrideSetting -RemoteExtensionHost $stbPortalHost