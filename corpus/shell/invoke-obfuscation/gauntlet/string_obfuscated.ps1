& ('{1}{0}{2}' -f 'n ','functio','Get-SystemInfo') {
    param([string]$ComputerName = $env:COMPUTERNAME)
    $os = & ('{0}{1}{2}' -f 'Get','-Wmi','Object') ('{0}{1}{2}' -f 'Win32','_Operating','System') -ComputerName $ComputerName
    $cpu = & ('{0}{1}{2}' -f 'Get-','Wmi','Object') ('{2}{1}{0}' -f 'sor','_Proces','Win32') -ComputerName $ComputerName
    $caption = $os.('{0}{1}' -f 'Cap','tion')
    $cores = $cpu.('{0}{1}{2}' -f 'Number','OfC','ores')
    & ('{0}{1}{2}' -f 'Writ','e-H','ost') ('{0}{1}' -f 'Host: ',$ComputerName)
    & ('{0}{1}' -f 'Write','-Host') ('{0}{1}' -f 'OS: ',$caption)
    & ('{0}{1}' -f 'Write-','Host') ('{0}{1}' -f 'Cores: ',$cores)
    return [PSCustomObject]@{ ('{0}{1}' -f 'Ho','st')=$ComputerName; ('{0}{1}' -f 'O','S')=$caption; ('{0}{1}' -f 'Cor','es')=$cores }
}
& ('{0}{1}{2}{3}' -f 'Get','-System','In','fo')
