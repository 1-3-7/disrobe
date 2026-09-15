function Add-Two { param([int]$a,[int]$b) return ($a + $b) }; Write-Output (Add-Two -a 3 -b 4); Write-Output "secret-token-value"
