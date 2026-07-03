.("{0}{1}"-f'fu','nction') Get-SystemInfo {
    param([s`tring]$ComputerName = $env:COMPUTERNAME)
    $os = .("{2}{0}{1}" -f 'bje','ct','Get-WmiO') ("{0}{1}{2}{3}" -f 'Wi','n32_','Opera','tingSystem') -ComputerName $ComputerName
    $cpu = .("{0}{1}{2}" -f 'Get','-Wmi','Object') ("{0}{1}{2}{3}" -f 'Win32','_','Proce','ssor') -ComputerName $ComputerName
    $cap`tion = $os.C`aption
    $co`res = $cpu.NumberOfC`ores
    .("{1}{0}" -f 'ost','Write-H') ("{0}{1}{2}" -f 'Host: ',$ComputerName,'')
    .("{0}{1}{2}" -f 'Wr','ite-','Host') ("{0}{1}" -f 'OS: ',$caption)
    .("{0}{1}" -f 'Write','-Host') ("{0}{1}" -f 'Cores: ',$cores)
    return [PSCustomObject]@{ Host=$ComputerName; OS=$caption; Cores=$cores }
}
.("{1}{0}{2}" -f 't-','Ge','SystemInfo')
