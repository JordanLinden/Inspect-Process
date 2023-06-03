# Inspect-Process
# Version 1.0
# Search a given process for loaded modules with invalid signatures

# Jordan Linden @https://github.com/JordanLinden
# 02 Jun 2023

# Disclaimer: This script is not production-ready. Use at your own risk.


Param(
    [int]$processId = $null,
    [switch]$help = $false
)

$Banner = "`nInspect-Process v1.0 - Search a given process for loaded modules with invalid signatures"
$Banner += "`nCreated by Jordan Linden"
$Banner += "`nhttps://github.com/JordanLinden`n"

Write-Host $Banner

function showHelp {
    Write-Host "`nDESCRIPTION:"
    Write-Host "    Inspect-Process v1.0"
    Write-Host "    Author: Jordan Linden"
    
    $desc = "`n    Provide a running process ID and get back any loaded modules with invalid signatures"
    Write-Host $desc
    
    Write-Host "`nOPTIONS:"
    Write-Host "    processId - PID of a valid running process"
    Write-Host "         help - display this help menu"
    Write-Host "              - type switch"
    Write-Host "              - [default: false]"
    Write-Host "`n"
}

if ($help) {
    showHelp
    return
}

if (-not $processId) {
    [int]$processId = Read-Host -prompt 'Enter a valid Process ID'
}

function verifyModules($modules) {
    $result = @()
    $foundCnt = 0
    
    Foreach ($module in $modules) {
        $percent = [math]::Round((($modules.IndexOf($module)/$modules.Count)*100),0)
        $progress = @{
            Activity = "Verifying modules loaded by Process ID: $processId"
            Status = "$percent% Complete:"
            PercentComplete = $percent
        }
        
        Write-Progress @progress -id 1
        
        if (-not ((Get-AuthenticodeSignature $module.FileName).Status -eq 'Valid')) {
            $sha256Hash = Get-FileHash $module.FileName | Select -Expand Hash
            
            $moduleInfo = [ordered]@{
                Module  = $module.moduleName
                Path    = $module.FileName
                Address = "0x{0:X8}" -f $module.BaseAddress.ToInt64()
                SHA256  = $sha256Hash
            }
            
            $result += ($moduleInfo)
            $foundCnt++
        }
    }
    return $result,$foundCnt
}

try {
    $modules = Get-Process -id $processId -ea Stop | Select -Expand Modules -ea SilentlyContinue
} catch {
    Throw
}

$result,$foundCnt = verifyModules($modules)

Write-Host "`nProcess ID $processId results:" -f White
if ($foundCnt -gt 0) {
    Write-Host "$foundCnt invalid signature(s) found`n" -f DarkYellow
} else {
    Write-Host "No invalid signatures found`n"
}

foreach ($h in $result) {
    "Invalid signature for module $($h.Module)"
    "-"*74
    foreach ($i in $h.GetEnumerator()) {
        if ($i.Name -ne "Module") {
            "$($i.Name)$(' '*(8-($i.Name.Length))): $($i.Value)"
        }
    }
    "`n"
}
