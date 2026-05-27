
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'


enum HelloMood {
    Calm = 0
    Excited = 1
    Suspicious = 2
}

enum FileKind {
    Script
    Library
    Manifest
    Archive
}


class GreetingTemplate {
    [string]$Prefix
    [string]$Suffix
    [HelloMood]$Mood
    hidden [int]$Version = 1
    static [int]$InstanceCount = 0

    GreetingTemplate() {
        $this.Prefix = 'hello'
        $this.Suffix = 'world'
        $this.Mood = [HelloMood]::Calm
        [GreetingTemplate]::InstanceCount++
    }

    GreetingTemplate([string]$prefix, [string]$suffix) {
        $this.Prefix = $prefix
        $this.Suffix = $suffix
        $this.Mood = [HelloMood]::Calm
        [GreetingTemplate]::InstanceCount++
    }

    [string] Render() {
        $sep = switch ($this.Mood) {
            ([HelloMood]::Calm) { ' ' }
            ([HelloMood]::Excited) { '! ' }
            ([HelloMood]::Suspicious) { '... ' }
            default { ' ' }
        }
        return "$($this.Prefix)$sep$($this.Suffix)"
    }

    [string] ToString() {
        return $this.Render()
    }
}

class Animal {
    [string]$Name
    [int]$Legs

    Animal([string]$name, [int]$legs) {
        $this.Name = $name
        $this.Legs = $legs
    }

    [string] Speak() {
        return "$($this.Name) speaks"
    }
}

class Dog : Animal {
    Dog([string]$name) : base($name, 4) { }

    [string] Speak() {
        return "$($this.Name) barks"
    }
}

class TypedDictionary {
    [System.Collections.Generic.Dictionary[string, int]]$Counts

    TypedDictionary() {
        $this.Counts = [System.Collections.Generic.Dictionary[string, int]]::new()
    }

    [void] Bump([string]$key) {
        if ($this.Counts.ContainsKey($key)) {
            $this.Counts[$key]++
        }
        else {
            $this.Counts[$key] = 1
        }
    }
}


function Get-ProcessByPid {
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    [OutputType([System.Diagnostics.Process])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById', Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 65535)]
        [int]$ProcessId,

        [Parameter(Mandatory, ParameterSetName = 'ByName', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z0-9._-]+$')]
        [string]$Name,

        [Parameter()]
        [ValidateSet('Wide', 'Compact', 'Json')]
        [string]$View = 'Wide',

        [Parameter()]
        [ValidateScript({ $_ -ge 0 -and $_ -le 100 })]
        [int]$MinCpuPercent = 0
    )
    begin {
        $accumulator = [System.Collections.Generic.List[psobject]]::new()
    }
    process {
        $procs = if ($PSCmdlet.ParameterSetName -eq 'ById') {
            Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        }
        else {
            Get-Process -Name $Name -ErrorAction SilentlyContinue
        }
        foreach ($p in $procs) {
            $accumulator.Add($p)
        }
    }
    end {
        switch ($View) {
            'Json' { $accumulator | ConvertTo-Json -Depth 3 }
            'Compact' { $accumulator | Select-Object Id, ProcessName }
            default { $accumulator }
        }
    }
}

function Invoke-WithSplat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter()][hashtable]$Extra = @{}
    )
    $defaults = @{
        Filter      = '*.ps1'
        Recurse     = $true
        ErrorAction = 'SilentlyContinue'
    }
    $merged = $defaults.Clone()
    foreach ($k in $Extra.Keys) {
        $merged[$k] = $Extra[$k]
    }
    Get-ChildItem -Path $Path @merged
}

function Test-PipelineBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Input,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Tag = 'default'
    )
    process {
        [pscustomobject]@{
            Input = $Input
            Tag   = $Tag
            Hash  = ($Input.GetHashCode())
        }
    }
}


$standardHash = @{
    'one'   = 1
    'two'   = 2
    'three' = 3
}

$orderedHash = [ordered]@{
    'first'  = 'alpha'
    'second' = 'beta'
    'third'  = 'gamma'
}

$nestedHash = @{
    'user'    = @{
        'name'  = 'admin'
        'roles' = @('reader', 'writer', 'owner')
    }
    'limits'  = [ordered]@{
        'cpu'    = 4
        'memory' = 8192
    }
    'active'  = $true
}


$legacyList = [System.Collections.ArrayList]::new()
[void]$legacyList.Add('a')
[void]$legacyList.Add('b')

$typedList = [System.Collections.Generic.List[int]]::new()
$typedList.Add(1)
$typedList.Add(2)
$typedList.AddRange([int[]](3..5))

$queue = [System.Collections.Generic.Queue[string]]::new()
$queue.Enqueue('first')
$queue.Enqueue('second')

$stack = [System.Collections.Generic.Stack[int]]::new()
$stack.Push(10)
$stack.Push(20)


$singleHere = @'
This is a single-quoted here-string.
No $variable expansion, no `escape sequences.
End sentinel below.
'@

$doubleHere = @"
This is a double-quoted here-string for `"$($standardHash['one'])`".
Variables expand: $($nestedHash.user.name)
Tab between cols:`tafter-tab
"@

$multiLineCmd = @"
Get-ChildItem -Path C:\Windows -Filter *.dll |
    Where-Object Length -gt 1MB |
    Sort-Object Length -Descending |
    Select-Object -First 5
"@


$row = 'Name: {0,-20} Id: {1,6:D} Cpu: {2,8:N2}' -f 'svchost', 1234, 12.567
$padded = '{0:00000}-{1:X8}' -f 42, 0xCAFEBABE
$money = '{0:C2}' -f 1234.5


function Get-LineKind {
    param([string]$Line)
    switch -Wildcard ($Line) {
        '# *' { return 'comment' }
        'function *' { return 'function-def' }
        'class *' { return 'class-def' }
        'param(*' { return 'param-block' }
        '*=*' { return 'assignment' }
        default { return 'other' }
    }
}

function Get-LineKindRegex {
    param([string]$Line)
    switch -Regex ($Line) {
        '^\s*#' { return 'comment' }
        '^\s*function\s+\w+' { return 'function-def' }
        '^\s*class\s+\w+' { return 'class-def' }
        '^\s*param\s*\(' { return 'param-block' }
        '^\s*\$\w+\s*=' { return 'assignment' }
        default { return 'other' }
    }
}

function Get-NumericBucket {
    param([int]$N)
    switch ($N) {
        { $_ -lt 0 } { return 'negative' }
        0 { return 'zero' }
        { $_ -gt 0 -and $_ -lt 10 } { return 'small' }
        { $_ -ge 10 -and $_ -lt 100 } { return 'medium' }
        default { return 'large' }
    }
}


function Invoke-WithProtection {
    [CmdletBinding()]
    param([scriptblock]$Body)
    try {
        $result = & $Body
        return @{ Ok = $true; Value = $result }
    }
    catch [System.IO.FileNotFoundException] {
        return @{ Ok = $false; Reason = 'missing-file'; Error = $_.Exception.Message }
    }
    catch [System.UnauthorizedAccessException] {
        return @{ Ok = $false; Reason = 'denied'; Error = $_.Exception.Message }
    }
    catch {
        return @{ Ok = $false; Reason = 'unknown'; Error = $_.Exception.Message }
    }
    finally {
        Write-Verbose 'Invoke-WithProtection complete'
    }
}

function Invoke-WithTrap {
    trap [System.DivideByZeroException] {
        Write-Warning 'caught div by zero'
        continue
    }
    trap {
        Write-Warning "caught generic: $($_.Exception.Message)"
        continue
    }
    $a = 10
    $b = 0
    $result = $a / $b
    return $result
}


function Start-ParallelComputation {
    [CmdletBinding()]
    param([int[]]$Inputs)
    $jobs = foreach ($n in $Inputs) {
        Start-Job -ScriptBlock {
            param($x)
            Start-Sleep -Milliseconds 10
            $x * $x
        } -ArgumentList $n
    }
    $results = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    return $results
}

function Invoke-InRunspacePool {
    [CmdletBinding()]
    param([scriptblock]$ScriptBlock, [object[]]$Items, [int]$MaxThreads = 4)
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $pool.Open()
    $handles = foreach ($item in $Items) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ScriptBlock).AddArgument($item)
        [pscustomobject]@{ Shell = $ps; Async = $ps.BeginInvoke() }
    }
    $results = foreach ($h in $handles) {
        $h.Shell.EndInvoke($h.Async)
        $h.Shell.Dispose()
    }
    $pool.Close()
    $pool.Dispose()
    return $results
}


$ScriptModule = New-Module -Name HelloAdHoc -ScriptBlock {
    function Get-Salutation { 'hello from ad-hoc module' }
    function Set-Salutation([string]$Value) { $script:Greeting = $Value }
    Export-ModuleMember -Function Get-Salutation, Set-Salutation
} -AsCustomObject

function Use-DotSource {
    param([string]$Path)
    if (Test-Path -Path $Path) {
        . $Path
    }
}


filter Square {
    $_ * $_
}

function Get-Top {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][int]$Item,
        [int]$Take = 3
    )
    begin { $list = [System.Collections.Generic.List[int]]::new() }
    process { $list.Add($Item) }
    end {
        $list | Sort-Object -Descending | Select-Object -First $Take
    }
}


$piped = 1..5 | Square | Where-Object { $_ -gt 4 } | Get-Top -Take 2


function Get-OsInfo {
    [CmdletBinding()]
    param()
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        Get-CimInstance -ClassName Win32_OperatingSystem
    }
    elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        Get-WmiObject -Class Win32_OperatingSystem
    }
}

function Get-ShellApplication {
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace('C:\')
    return $folder
}


function Get-RunOnceEntries {
    [CmdletBinding()]
    param()
    $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    if (Test-Path $path) {
        Get-ItemProperty -Path $path
    }
}

function Get-FileAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Get-Acl -Path $Path | Select-Object Owner, Group, Sddl
}

[type[]]$accelerators = @(
    [string], [int], [long], [bool], [double], [decimal], [datetime], [timespan],
    [guid], [scriptblock], [hashtable], [psobject], [pscustomobject], [regex],
    [version], [uri]
)


function Read-FirstBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Count = 16
    )
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $buffer = [byte[]]::new($Count)
        $read = $stream.Read($buffer, 0, $Count)
        return $buffer[0..($read - 1)]
    }
    finally {
        $stream.Dispose()
    }
}

function Write-AtomicFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    $temp = "$Path.tmp.$([guid]::NewGuid().ToString('N'))"
    try {
        Set-Content -Path $temp -Value $Content -Encoding UTF8 -NoNewline
        Move-Item -Path $temp -Destination $Path -Force
    }
    catch {
        if (Test-Path $temp) {
            Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}


function Get-Configuration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key)
    if ($script:Configuration -and $script:Configuration.ContainsKey($Key)) {
        return $script:Configuration[$Key]
    }
    return $null
}

function Set-Configuration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][object]$Value
    )
    if (-not $script:Configuration) {
        $script:Configuration = @{}
    }
    if ($PSCmdlet.ShouldProcess($Key, 'Set configuration value')) {
        $script:Configuration[$Key] = $Value
    }
}

function Remove-Configuration {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Key)
    if ($PSCmdlet.ShouldProcess($Key, 'Remove configuration value')) {
        if ($script:Configuration -and $script:Configuration.ContainsKey($Key)) {
            $script:Configuration.Remove($Key)
        }
    }
}


function Format-Greeting {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $template = '{0}, {1}!'
    return $template -f 'hello', $Name
}

$tokens = 'one,two,three,four,five' -split ','
$joined = $tokens -join '|'
$replaced = 'hello world' -replace 'world', 'shell'
$matches = 'abc123def456' -match '(\d+)'
$selectMatch = 'abc123def456' | Select-String -Pattern '\d+' -AllMatches


function Get-EncodedCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
    return [Convert]::ToBase64String($bytes)
}

function Get-DecodedCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EncodedCommand)
    $bytes = [Convert]::FromBase64String($EncodedCommand)
    return [System.Text.Encoding]::Unicode.GetString($bytes)
}

$encoded = Get-EncodedCommand -Command 'Write-Host "hello world"'
$decoded = Get-DecodedCommand -EncodedCommand $encoded


$bigInt = [bigint]::Parse('123456789012345678901234567890')
$signed = -[int]::MaxValue
$nan = [double]::NaN
$inf = [double]::PositiveInfinity
$now = Get-Date
$utc = [datetime]::UtcNow
$ts = New-TimeSpan -Days 1 -Hours 2 -Minutes 3


$ls_alias = Get-Alias -Name ls -ErrorAction SilentlyContinue
$gci_explicit = Get-Command -Name Get-ChildItem


function Throw-Custom {
    [CmdletBinding()]
    param([string]$Message)
    $exception = [System.InvalidOperationException]::new($Message)
    $errorId = 'CustomError'
    $category = [System.Management.Automation.ErrorCategory]::InvalidOperation
    $record = [System.Management.Automation.ErrorRecord]::new($exception, $errorId, $category, $null)
    throw $record
}


function Get-ProcessViaWmi {
    [CmdletBinding()]
    param()
    Get-WmiObject -Class Win32_Process | Select-Object -First 5
}


function Main {
    [CmdletBinding()]
    param()
    $g = [GreetingTemplate]::new('hello', 'world')
    $g.Mood = [HelloMood]::Excited
    Write-Host $g.Render()
    $dict = [TypedDictionary]::new()
    $dict.Bump('a')
    $dict.Bump('a')
    $dict.Bump('b')
    return $dict.Counts
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($PSCommandPath) {
        Main
    }
}


function Test-ModernOperators {
    [CmdletBinding()]
    param([object]$Value, [object]$Other)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $nullish = $Value ?? $Other ?? 'fallback'
        $cond = $Value ? 'truthy' : 'falsy'
        $coalesceAssign = $Value
        $coalesceAssign ??= $Other
        return @{
            Nullish        = $nullish
            Conditional    = $cond
            CoalesceAssign = $coalesceAssign
        }
    }
    return $null
}

function Invoke-PipelineChain {
    [CmdletBinding()]
    param([string[]]$Commands)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $script = ($Commands -join ' && ')
        $sb = [scriptblock]::Create($script)
        return & $sb
    }
}

function Invoke-ParallelForeach {
    [CmdletBinding()]
    param([int[]]$Inputs, [int]$Throttle = 4)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $sb = {
            param($x)
            $x * $x
        }
        return $Inputs | ForEach-Object -Parallel { & $using:sb $_ } -ThrottleLimit $Throttle
    }
    return $Inputs | ForEach-Object { $_ * $_ }
}


function Get-Resource {
    [CmdletBinding(DefaultParameterSetName = 'ByPath')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByPath', Position = 0)]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'ByUri')]
        [uri]$Uri,

        [Parameter(Mandatory, ParameterSetName = 'ByLiteralBytes')]
        [byte[]]$Bytes
    )
    dynamicparam {
        $dict = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        if ($PSBoundParameters.ContainsKey('Path')) {
            $attrColl = [System.Collections.ObjectModel.Collection[Attribute]]::new()
            $attr = [System.Management.Automation.ParameterAttribute]::new()
            $attr.ParameterSetName = 'ByPath'
            $attrColl.Add($attr)
            $param = [System.Management.Automation.RuntimeDefinedParameter]::new('Encoding', [string], $attrColl)
            $dict['Encoding'] = $param
        }
        return $dict
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'ByPath' { return @{ Source = 'Path'; Value = $Path } }
            'ByUri' { return @{ Source = 'Uri'; Value = $Uri.AbsoluteUri } }
            'ByLiteralBytes' { return @{ Source = 'Bytes'; Length = $Bytes.Length } }
        }
    }
}


function Invoke-Steppable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Body, [object[]]$Items)
    $stepper = $Body.GetSteppablePipeline()
    $stepper.Begin($true)
    try {
        foreach ($i in $Items) {
            $stepper.Process($i)
        }
    }
    finally {
        $stepper.End()
    }
}


$record = [pscustomobject][ordered]@{
    PSTypeName = 'Hello.Record'
    Id         = [guid]::NewGuid()
    Created    = [datetime]::UtcNow
    Payload    = @{
        Greeting = 'hello world'
        Tags     = @('greeting', 'sample', 'edge-case')
    }
}

Update-TypeData -TypeName 'Hello.Record' -MemberType ScriptMethod -MemberName 'Render' -Value {
    "[{0}] {1}" -f $this.Id, $this.Payload.Greeting
} -ErrorAction SilentlyContinue


Set-Variable -Name 'AppName' -Value 'disrobe-edge' -Option ReadOnly -Force
Set-Variable -Name 'AppVersion' -Value '1.0.0' -Option Constant -Force -ErrorAction SilentlyContinue


$here = $PSScriptRoot
$current = $MyInvocation.MyCommand.Path


function Connect-Endpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Host,
        [Parameter(Position = 1)][int]$Port = 443,
        [Parameter()][int]$TimeoutSeconds = 30
    )
    return "{0}:{1} t={2}s" -f $Host, $Port, $TimeoutSeconds
}

$endpointArgs = @{
    Host           = 'api.example.com'
    Port           = 8443
    TimeoutSeconds = 60
}
$endpointResult = Connect-Endpoint @endpointArgs
$positionalSplat = @('cache.example.com', 6379)
$endpointResultPos = Connect-Endpoint @positionalSplat


$caseSensitiveEq = 'HELLO' -ceq 'hello'
$caseInsensitiveEq = 'HELLO' -ieq 'hello'
$wildcardLike = 'hello world' -like 'hello *'
$regexMatch = 'hello123' -match '^[a-z]+(\d+)$'
$containsTest = @(1, 2, 3) -contains 2
$inTest = 2 -in @(1, 2, 3)
$notInTest = 99 -notin @(1, 2, 3)
$bandResult = 0b1100 -band 0b1010
$borResult = 0b1100 -bor 0b1010
$bxorResult = 0b1100 -bxor 0b1010
$shlResult = 1 -shl 4
$shrResult = 16 -shr 2


$fmtDate = '{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)
$fmtFloat = '{0:F4}' -f [math]::PI
$fmtPct = '{0:P2}' -f 0.123456
$fmtCustom = '{0:000-000}' -f 123456
$fmtScientific = '{0:E2}' -f 1234567.89
$fmtMulti = '{0,10:N0} | {1,-15} | {2:HH:mm}' -f 1234567, 'right-padded', (Get-Date)


[Flags()] enum Permission {
    None    = 0
    Read    = 1
    Write   = 2
    Execute = 4
    All     = 7
}

function Test-Permission {
    [CmdletBinding()]
    param([Permission]$Granted, [Permission]$Required)
    return ($Granted -band $Required) -eq $Required
}

$grantedPerms = [Permission]::Read -bor [Permission]::Write
$hasWrite = Test-Permission -Granted $grantedPerms -Required ([Permission]::Write)


function ConvertTo-TypedArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][type]$ElementType
    )
    $arr = [array]::CreateInstance($ElementType, $Items.Length)
    for ($i = 0; $i -lt $Items.Length; $i++) {
        $arr[$i] = $Items[$i]
    }
    return , $arr
}

$intArray = ConvertTo-TypedArray -Items @(1, 2, 3) -ElementType ([int])
$stringArray = ConvertTo-TypedArray -Items @('a', 'b', 'c') -ElementType ([string])


function Get-TypeMembers {
    [CmdletBinding()]
    param([Parameter(Mandatory)][type]$Type)
    return [pscustomobject]@{
        Type        = $Type.FullName
        Methods     = $Type.GetMethods().Name | Sort-Object -Unique
        Properties  = $Type.GetProperties().Name | Sort-Object -Unique
        IsAbstract  = $Type.IsAbstract
        IsInterface = $Type.IsInterface
    }
}

$stringMembers = Get-TypeMembers -Type ([string])


workflow Sync-Folder {
    param([string[]]$Sources, [string]$Destination)
    foreach -parallel ($source in $Sources) {
        InlineScript {
            Copy-Item -Path $using:source -Destination $using:Destination -Recurse -Force
        }
    }
}


function Suppress-Output {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param()
    [void](Get-Process | Out-Null)
    $null = Get-Service
}


$emailRegex = [regex]::new('^[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}$', [System.Text.RegularExpressions.RegexOptions]::Compiled)
function Test-Email {
    [CmdletBinding()]
    param([string]$Address)
    return $emailRegex.IsMatch($Address)
}
$validEmails = @('a@b.co', 'user.name+tag@example.com', 'no-at-sign', '@nouser.com') |
    Where-Object { Test-Email $_ }


function Stop-Gracefully {
    [CmdletBinding()]
    param([int]$Code = 0)
    [Environment]::Exit($Code)
}


$jsonDoc = @{
    metadata = @{
        version    = '2.1.0'
        author     = 'edge-case-author'
        tags       = @('a', 'b', 'c')
        created    = '2026-05-25T00:00:00Z'
        nullField  = $null
        boolTrue   = $true
        boolFalse  = $false
        intField   = 42
        floatField = 3.14159
    }
    items    = @(
        @{ id = 1; name = 'first'; nested = @{ depth = 'one' } }
        @{ id = 2; name = 'second'; nested = @{ depth = 'two' } }
        @{ id = 3; name = 'third'; nested = @{ depth = 'three' } }
    )
}
$serialized = $jsonDoc | ConvertTo-Json -Depth 10 -Compress
$roundTrip = $serialized | ConvertFrom-Json


function Get-Sha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
    }
    finally {
        $sha.Dispose()
    }
}

function New-RandomBytes {
    [CmdletBinding()]
    param([int]$Length = 32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $buffer = [byte[]]::new($Length)
        $rng.GetBytes($buffer)
        return $buffer
    }
    finally {
        $rng.Dispose()
    }
}

$sha = Get-Sha256Hex -Text 'hello world'
$randBytes = New-RandomBytes -Length 16


function Invoke-RestSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [hashtable]$Headers = @{},
        [string]$Method = 'GET',
        [object]$Body = $null
    )
    $args = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $Headers
    }
    if ($Body) {
        $args['Body'] = ($Body | ConvertTo-Json -Depth 6)
        $args['ContentType'] = 'application/json'
    }
    try {
        return Invoke-RestMethod @args
    }
    catch [System.Net.WebException] {
        Write-Warning "WebException: $($_.Exception.Message)"
        return $null
    }
}


function Wait-AnyTask {
    [CmdletBinding()]
    param([System.Threading.Tasks.Task[]]$Tasks, [int]$TimeoutMs = 5000)
    $cts = [System.Threading.CancellationTokenSource]::new($TimeoutMs)
    try {
        $idx = [System.Threading.Tasks.Task]::WaitAny($Tasks, $cts.Token)
        return $Tasks[$idx]
    }
    finally {
        $cts.Dispose()
    }
}


function Show-Help {

    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Topic)
    Get-Help $Topic
}


Register-ArgumentCompleter -CommandName Get-Configuration -ParameterName Key -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    if ($null -ne $script:Configuration) {
        $script:Configuration.Keys |
            Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
    }
}

