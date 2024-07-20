# Automated CrowdStrike Falcon BSOD Remediation Tool
A PowerShell script to automatically remediate Windows computers affected by the CrowdStrike Falcon update BSOD issue.
Remediation steps performed are based on guidance from here: https://www.crowdstrike.com/blog/statement-on-falcon-content-update-for-windows-hosts/

## Before you run it
* The script should be run with Windows PowerShell 5.1 as an administrator.
* Ensure both files are in the same directory.
* Note that this method won't work if BitLocker prevents automatic boot into Windows.

## Usage example
`.\Remediate-CrowdStrikeFalconBSOD.ps1 -ComputerName labdbs01`
