# Automated CrowdStrike Falcon BSOD Remediation Tool
A PowerShell script to automatically remediate Windows computers affected by the CrowdStrike Falcon update BSOD issue.
Remediation steps performed are based on guidance from here: https://www.crowdstrike.com/blog/statement-on-falcon-content-update-for-windows-hosts/

## Usage example
.\Remediate-CrowdStrikeFalconBSOD.ps1 -ComputerName labdbs01
