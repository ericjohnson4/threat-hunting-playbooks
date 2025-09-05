# PowerShell Script

<# 
T1110 Brute Force validation (safe lab generator)
Generates multiple failed network logons (Security EventID 4625)

Notes:
- Run in an elevated PowerShell session on the target VM.
- Targets the local SMB IPC$ share to avoid touching remote hosts.
#>

$target = "\\127.0.0.1\IPC$"
$user   = ".\bogususer"          # non-existent account (keeps it safe)
$bad    = "WrongP@ssw0rd!"       # intentionally wrong password

# How many attempts to generate (adjust if you want a bigger/smaller burst)
$attempts = 15

1..$attempts | ForEach-Object {
  cmd /c "net use $target /user:$user $bad" | Out-Null
  Start-Sleep -Milliseconds 300
}

# Clean up any lingering connection (usually none since auth failed)
cmd /c "net use $target /delete" | Out-Null

Write-Host "Generated $attempts failed logon attempts against $target" -ForegroundColor Green

