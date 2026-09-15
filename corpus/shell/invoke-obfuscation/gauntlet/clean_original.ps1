function Get-SystemInfo {
    param([string]$ComputerName = $env:COMPUTERNAME)
    $os = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName
    $cpu = Get-WmiObject Win32_Processor -ComputerName $ComputerName
    $caption = $os.Caption
    $cores = $cpu.NumberOfCores
    Write-Host "Host: $ComputerName"
    Write-Host "OS: $caption"
    Write-Host "Cores: $cores"
    return [PSCustomObject]@{ Host=$ComputerName; OS=$caption; Cores=$cores }
}
Get-SystemInfo
