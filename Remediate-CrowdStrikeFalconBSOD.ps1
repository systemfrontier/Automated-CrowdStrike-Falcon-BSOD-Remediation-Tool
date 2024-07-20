#Requires -Version 5.1

param(
	[string]$ComputerName
)

<#
	.SYNOPSIS
	Automated remediation tool for the CrowdStrike Falcon update BSOD issue
	
	.DESCRIPTION
	Remediation steps based on https://www.crowdstrike.com/blog/statement-on-falcon-content-update-for-windows-hosts/
	
	.PARAMETER ComputerName
	The hostname or IP address of a Windows computer
	
	.EXAMPLE
	.\Remediate-CrowdStrikeFalconBSOD.ps1 -ComputerName labdbs01

	.LINK
	https://github.com/systemfrontier/Automated-CrowdStrike-Falcon-BSOD-Remediation-Tool/

	
	.NOTES
	Relies on WmiExec function from https://github.com/OneScripter/WmiExec
	Run as an administrator for the target machine.
	Can be run en masse using System Frontier.

	==============================================
	Version:	1.0
	Author:		Jay Adams, Noxigen LLC
	Created:	2024-07-20
	Copyright:	Noxigen LLC. All rights reserved.

	Create secure GUIs for PowerShell with System Frontier.
	https://systemfrontier.com/
	==============================================
#>

# If running the script from multiple execution hosts, you'll want to make this a UNC path.
# Be sure the account running the script has write access.
$loggingShare = ".\logs"

if ((Test-Path -Path $loggingShare -PathType Container) -eq $false) {
	New-Item -Path $loggingShare -ItemType Directory -Force	| Out-Null
}

# A flag file is created in the logging folder whenever a target machine has 
# successfully been remediated
$remediationFlagFile = "$loggingShare\$ComputerName.flag"
$retryAttempts = 60
$retryWaitSeconds = 5
$rebootTimeoutSeconds = 300

$crowdStrikePath = '$env:windir\system32\drivers\CrowdStrike\'
$crowdStrikeFileFilter = 'C-00000291*.sys'

function Write-Log ($message) {
	[string]$out = "{0}`t{1}`t{2}" -f (Get-Date).ToString("yyyy-MM-dd hh:mm:ss"), $ComputerName, $message

	Write-Output $out
}

[bool]$remediated = (Test-Path -Path $remediationFlagFile -PathType Leaf)

if ($remediated) {
	Write-Log "The target machine has already been remediated"
	exit
}

Write-Log "========================================"
Write-Log "CrowdStrike Falcon BSOD remediation tool"
Write-Log "========================================"
Write-Log "Copyright (c) Noxigen LLC. All rights reserved."
Write-Log "Use at your own risk. Absolutely no warranties."
Write-Log ""

Write-Log "Waiting until target machine is online in case of BSOD reboots"
$rebootStart = Get-Date

for ($i = 0; $i -lt $retryAttempts; $i++) {
	$os = $null

	if ((New-TimeSpan -Start $rebootStart -End (Get-Date)).Seconds -gt $rebootTimeoutSeconds) {
		Write-Log "Timed out waiting for target machine to be online"
		exit
	} else {
		try {
			$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop

			Write-Log "Online"
			break
		}
		catch {
			Write-Log "(Offline) Reason: $($PSItem.Exception.Message)"
			Write-Log "Retrying in $retryWaitSeconds second(s)..."
			
			Start-Sleep -Seconds $retryWaitSeconds
		}
	}
}

$badFiles = .\WmiExec.ps1 -ComputerName $ComputerName `
	-Command "Get-ChildITem -Path $crowdStrikePath -Filter $crowdStrikeFileFilter -File -Name" -Silent

$badFileCount = [regex]::Matches($badFiles, ".sys").Count

Write-Log "Found $badFileCount relevant files"

if ([string]::IsNullOrWhiteSpace($badFiles) -eq $false -and $badFileCount -gt 0) {

	Write-Log "Enabling safe boot with networking"
	$safebootResult = .\WmiExec.ps1 -ComputerName $ComputerName -Command 'bcdedit /set `{current`} safeboot network' -Silent

	if ($safebootResult -match "The operation completed successfully") {
		try {
			if ($null -ne $os) {
				$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
			}
			
			[datetime]$previousBootUp = ([wmi]'').ConvertToDateTime($os.LastBootUpTime)
		}
		catch {
			Write-Log "WMI error. Reason: $($PSItem.Exception.Message)"
			exit
		}
		
		Write-Log "Rebooting..."
		[datetime]$rebootStart = Get-Date
		
		$os | Invoke-WMIMethod -name Win32Shutdown -ArgumentList @(6) | Out-Null

		Start-Sleep -Seconds 10

		$backOnline = $false

		for ($i = 0; $i -lt $retryAttempts; $i++) {
			$os = $null

			if ((New-TimeSpan -Start $rebootStart -End (Get-Date)).Seconds -gt $rebootTimeoutSeconds) {
				Write-Log "Timed out waiting on reboot"
				exit
			} else {
				try {
					$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
					
					[datetime]$lastBootUp = ([wmi]'').ConvertToDateTime($os.LastBootUpTime)
				}
				catch {
					Write-Log "(Offline) Reason: $($PSItem.Exception.Message)"
				}

				if ($lastBootUp -ne [datetime]::Empty -and ($lastBootUp -gt $previousBootUp)) {
					Write-Log "Online"
					$backOnline = $true
					break
				} else {
					Write-Log "Retrying in $retryWaitSeconds second(s)..."
					Start-Sleep -Seconds $retryWaitSeconds
				}
			}
		}

		if ($backOnline) {
			Write-Log "Deleting files..."
			.\WmiExec.ps1 -ComputerName $ComputerName `
				-Command "Remove-Item -Path $crowdStrikePath\* -Include $crowdStrikeFileFilter -Force" -Silent
			
			$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop

			Write-Log "Setting normal boot mode"
			.\WmiExec.ps1 -ComputerName $ComputerName -Command 'bcdedit /deletevalue `{default`} safeboot' -Silent

			Write-Log "Rebooting..."
			$os | Invoke-WMIMethod -name Win32Shutdown -ArgumentList @(6) | Out-Null

			Start-Sleep -Seconds 10

			$backOnline = $false

			for ($i = 0; $i -lt $retryAttempts; $i++) {
				$os = $null

				if ((New-TimeSpan -Start $rebootStart -End (Get-Date)).Seconds -gt $rebootTimeoutSeconds) {
					Write-Log "Timed out waiting on reboot"
					exit
				} else {
					try {
						$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
						
						[datetime]$lastBootUp = ([wmi]'').ConvertToDateTime($os.LastBootUpTime)
					}
					catch {
						Write-Log "(Offline) Reason: $($PSItem.Exception.Message)"
					}

					if ($lastBootUp -ne [datetime]::Empty -and ($lastBootUp -gt $previousBootUp)) {
						Write-Log "Online"
						$backOnline = $true
						break
					} else {
						Write-Log "Retrying in $retryWaitSeconds second(s)..."
						Start-Sleep -Seconds $retryWaitSeconds
					}
				}
			}
		}

		if ($backOnline) {
			# Check if files are really gone
			$badFiles = .\WmiExec.ps1 -ComputerName $ComputerName `
				-Command "Get-ChildITem -Path $crowdStrikePath -Filter $crowdStrikeFileFilter -File -Name" -Silent
			
			$badFileCount = [regex]::Matches($badFiles, ".sys").Count

			Write-Log "Found $badFileCount relevant files"

			if ($badFileCount -eq 0) {
				Write-Log "Remediation successful"

				New-Item -ItemType File -Path $remediationFlagFile | Out-Null
				exit
			}
		}
	}
} else {
	Write-Log "Relevant CrowdStrike files not found"
	
	New-Item -ItemType File -Path $remediationFlagFile | Out-Null
	exit
}

#Write-Log "Remediation failed"
