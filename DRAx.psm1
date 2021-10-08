<#
  == Directory and Resources Administrator eXtension ==
  Dependencies:
    NetIQ DRA PowerShellExtensions.
  ToDo:
    View properties of users, groups, and computers.
    Add version control and security measures.
  BUG!:
    using namespace does not import correctly. Access control has to be full name.
#>

using namespace System.IO;
using namespace System.Security.AccessControl;

function New-DRAx {
  param(
    [string]$configPath
  )
  $DRAx = [drax]::new().initialize($configPath, $null, $true)
  return $DRAx
}

enum DRAxAction
{
  Add = 0
  Get = 1
  Rem = 2
  Set = 3
}

enum DRAxClass
{
  Default    = 0
  AdminGroup = 1
  AdminUser  = 2
  Group      = 3
  User       = 4
  Computer   = 5
}

enum DRAxEmailRights
{
  SendAs       = 0
  SendOnBehalf = 1
  FullAccess   = 2
}

enum LogLevel
{
  ERR = 0
  WRN = 1
  INF = 2
  DBG = 3
}

class Logging : System.IDisposable
{
  [loglevel]$LogLevel = [loglevel]::DBG
  
  hidden [string]$LogPath
  hidden [string]$LogName = '_Default_.log'
  hidden [bool]$UseInitTime
  hidden [string]$FormatDateTime = " ] {0:yyyy-MM-ddTHHmmss.ffff} {1}: {2}"
  hidden [string]$FormatTimeSpan = " ] {0} {1}: {2}"
  hidden [datetime]$InitTime
  hidden [streamwriter]$LogStream
  
  Logging() { }

  Logging([string]$logPath)
  {
    $this.newLogStream($logPath)
  }

  [object] Initialize()
  {
    $this.InitTime = [datetime]::Now
    $this.UseInitTime = $true
    return $this
  }

  [object] Initialize([string]$logPath)
  {
    $this.newLogStream($logPath)
    return $this.initialize()
  }

  hidden [void] NewLogStream([string]$logPath)
  {
    $this.LogPath = $logPath
    try {
      if (!$this.LogStream -or !$this.LogStream.BaseStream.Handle) {
         if (![directory]::exists($this.LogPath)) {
           [directory]::createDirectory($this.LogPath)
         }
         if (![file]::exists("$($this.LogPath)$($this.LogName)")) {
           $this.LogStream = [file]::create("$($this.LogPath)$($this.LogName)")
         }
         else {
           $this.LogStream = [streamwriter]::new("$($this.LogPath)$($this.LogName)", $true)
         }
       }
    }
    catch {
      if ($this.LogStream) {
        $this.LogStream.dispose()
      }
    }
  }

  [void] ToErr([string]$msg, [string]$src)
  {
    if ($this.LogLevel -ge 0) {
      $this.toConsole([loglevel]::ERR, $msg, $src)
    }
    $this.toStream([loglevel]::ERR, $msg, $src)
  }
  
  [void] ToWrn([string]$msg, [string]$src)
  {
    if ($this.LogLevel -ge 1) {
      $this.toConsole([loglevel]::WRN, $msg, $src)
    }
    $this.toStream([loglevel]::WRN, $msg, $src)
  }
  
  [void] ToInf([string]$msg, [string]$src)
  {
    if ($this.LogLevel -ge 2) {
      $this.toConsole([loglevel]::INF, $msg, $src)
    }
    $this.toStream([loglevel]::INF, $msg, $src)
  }
  
  [void] ToDbg([string]$msg, [string]$src)
  {
    if ($this.LogLevel -ge 3) {
      $this.toConsole([loglevel]::DBG, $msg, $src)
    }
    $this.toStream([loglevel]::DBG, $msg, $src)
  }

  hidden [void] ToConsole([loglevel]$lvl, [string]$msg, [string]$src)
  {
    [console]::write("[ ")
    [console]::ForegroundColor = $this.toColor($lvl)
    [console]::write($lvl.toString())
    [console]::resetColor()
    if ($this.useInitTime) {
      [console]::writeLine($this.FormatTimeSpan, ([datetime]::Now - $this.InitTime).toString(), $src, $msg)
    }
    else {
      [console]::writeLine($this.FormatDateTime, [datetime]::Now.toLocalTime(), $src, $msg)      
    }
  }

  hidden [void] ToStream([loglevel]$lvl, [string]$msg, [string]$src)
  {
    if (![string]::isNullOrWhiteSpace($this.LogPath)) {
      $this.LogStream.writeLine("[ $($lvl.toString())$($this.FormatDateTime)", [datetime]::Now.toLocalTime(), $src, $msg)
      $this.LogStream.flush()
    }
  }

  hidden [string] ToColor([loglevel]$lvl)
  {
    switch ($lvl) {
      ([loglevel]::ERR) { return [consolecolor]::Red    }
      ([loglevel]::WRN) { return [consolecolor]::Yellow }
      ([loglevel]::INF) { return [consolecolor]::Cyan   }
      ([loglevel]::DBG) { return [consolecolor]::Green  }
    }
    return [console]::ForegroundColor
  }

  [void] Dispose()
  {
    try {
      $this.LogPath = [string]::Empty
      if ($this.LogStream) {
        $this.logStream.close()
        $this.logStream.dispose()
      }
      [gc]::collect()
    }
    finally {
      [gc]::suppressFinalize($this)
    }
  }
}

class DRAx : Logging
{
  [string]$Domain
  [string]$Server
  [object]$Servers
  [object]$Containers
  [object]$Attributes

  hidden [string]$hDomain = $env:USERDNSDOMAIN
  hidden [string]$hModulePath = 'C:\Program Files (x86)\NetIQ\DRA Extensions\modules\NetIQ.DRA.PowerShellExtensions'
  hidden [string]$hModuleName = 'NetIQ.DRA.PowerShellExtensions'
  hidden [int]$hPort = 8755
  hidden [int]$hLogLevel
  hidden [consolecolor]$PromptHeader   = [consolecolor]::DarkYellow
  hidden [consolecolor]$SectionHeader  = [consolecolor]::Gray
  hidden [consolecolor]$SectionContent = [consolecolor]::DarkGray

  hidden [system.collections.arraylist]$Permissions
  hidden [system.collections.arraylist]$GroupedObjects

  DRAx()
  {
    
  }

  [drax] Initialize()
  {
    try {
      return $this.initialize($null, $null, $true)
    }
    catch {
      throw $_
    }
  }

  [drax] Initialize2()
  {
    try {
      return $this.initialize('C:\_\Projects\DRAx\DRAx_v3\DRAx.json', $null, $true)
    }
    catch {
      throw $_
    }
  }

  [drax] Initialize([string]$configPath, [string]$modulePath, [bool]$findOptimalServer)
  {
    try {
      #$modulePath -ne [string]::isNullOrEmpty
      if ($modulePath) {
        Import-Module -name $modulePath -errorAction 'Stop'
      }
      else {
        if (!(Get-Module -name 'NetIQ.DRA.PowerShellExtensions' -listAvailable)) {
          throw "Failed to import module > $($this.hModuleName)"
        }
        Import-Module -name 'NetIQ.DRA.PowerShellExtensions' -errorAction 'Stop'
      }
      if ($configPath) {
        if (!$this.import($configPath)) {
          throw "Failed to import `"$($configPath)`""
        }
      }
      else {
        if (!$this.import("$($PsScriptRoot)\DRAx.json")) {
          throw "Failed to import `"$($PsScriptRoot)\DRAx.json`""
        }
      }
      if ($findOptimalServer) {
        $this.Server = $this.findServer()
      }
      return $this
    }
    catch {
      throw $_
    }
  }

  [bool] Import([string]$path)
  {
    if ([system.io.file]::exists($path)) {
      $Config = [system.io.file]::readAllText($path) | ConvertFrom-Json
      $this.Attributes = $Config.Attributes
      $this.Domain     = $Config.Domain
      $this.Containers = $Config.Containers
      $this.Servers    = $Config.Servers
      return $true
    }
    return $false
  }

  hidden [string] FindServer()
  {
    foreach ($Server in ($this.Servers | Sort-Object -property 'Priority').getEnumerator().Server) {
      if ($this.testServer($Server)) {
        return $Server
      }
    }
    return $null
  }

  hidden [bool] TestServer([string]$name)
  {
    try {
      Get-DRAServerInfo -draRestServer "$($name).$($this.Domain)" -errorAction 'Stop'
      return $true
    }
    catch {
      return $false
    }
  }

  [hashtable] GetSplat()
  {
    return @{
      DRARestServer = "$($this.Server).$($this.Domain)"
      Domain = "$($this.Domain)"
      ErrorAction = 'Stop'
    }
  }

  ###############################
  ##### Interaction Section #####
  ###############################

  [object] EnterConsole()
  {
    do {
      [console]::clear()
      $R0 = $this.console(@{'Select Category' = @(
        '1: Quick Actions',
        '2: Computer(s)',
        '3: Distro(s)/Group(s)',
        '4: User(s)/OrgAcct(s)',
        '5: File System Actions',
        '0: Return'
      )}, "`n== DRAx Console ==`n", "`nDRAx > ")
      switch -regex ($R0) {
        '^0$' {
          return ''
        }
        '^\?$|^[Hh](elp)*$' {
          #ToDo: DisplayHelp
          continue
        }
        '^1$' {
          $R1 = $this.console(@{'Options' = @()}, $null, "`nDRAx [QuickAction] > ")
        }
        '^2|^[Cc]omputer(?:s*)$' {
          $R1 = $this.console(@{'Options' = @(
            '1: Create`tCreate AFNet Computer',
            '2: Restore`tRecreate Computer',
            '3: Delete`tMove Computer to recycling bin',
            '4: Disable`tDisable Computer',
            '5: Enable`tEnable Computer',
            '6: Get`tGet properties for Computer',
            '7: Edit`tEdit properties for Computer',
            '0: Return'
          )}, $null, "`nDRAx [Computer] > ")
        }
        '^3$' {
          $R1 = $this.console(@{'Options' = @(
            '1: Create Group',
            '2: Get Group',
            '3: Edit Group',
            '3: Get Group Member(s)',
            '4: Set Group Member(s)',
            '5: Get Distro Manager',
            '6: Set Distro Manager',
            '7: Get Distro Member(s)',
            '8: Set Distro Member(s)',
            '0: Return'
          )}, $null, "`nDRAx [Group|Distro] > ")
        }
        '^4$' {
          $R1 = $this.console(@{'Options' = @(
            '1: Create User',
            '2: Delete User',
            '3: Get User properties',
            '4: Edit User properties',
            '5: Enable User',
            '6: Disable User',
            '7: Mirror Users',
            '0: Return'
          )}, $null, "`nDRAx [User] > ")
          switch -regex ($R1) {
            '^0$' { break }
            '^1$' {}
            '^2$' {}
            '^3$' {}
            '^4$' {}
            '^5$' {}
            '^6$' {}
            '^7$' {}
          }
        }
        '^5$' {
          $R1 = $this.console(@{'Options' = @(
            '1: Analyze File System'
          )}, $null, "`nDRAx [FSAction] > ")
          while (![string]::isNullOrEmpty($R1)) {
            $this.console(@{}, "Enter Search Path", "`nDRAx [FSAction] > ")
          }
        }
        '[G|g]et [U|u]ser (?<a>.*)' {
          #$r1 = $this.iFind('User', $matches.a.toString())
        }
        '[G|g]et [C|c]omputer (?<a>.*)' {
          #$r1 = $this.iFind('Computer', $matches.a.toString())
        }
        '[G|g]et\s[D|d]istro\s(?<D>\S*)' {
          #$DistroManager = $this.getDistroManager($this.iFind('Group', $matches.D))
        }
        '[N|n]ew [C|c]omputer (?<a>.*)' {
          #ASDF
        }
      }
      [console]::readKey()
    }
    while ($true)
    return ''
  }

  hidden [string] Console([hashtable]$inputObject, [string]$header, [string]$prompt)
  {
    try {
      if (![string]::isNullOrWhiteSpace($header)) {
        [console]::writeLine($header)
      }
      if ($inputObject) {
        foreach ($Item in $inputObject.getEnumerator()) {
          [console]::ForegroundColor = $this.SectionHeader
          [console]::writeLine("  $($Item.Key)")
          if ($Item.Value -is [hashtable]) {
            [console]::ForegroundColor = $this.SectionContent
            foreach ($InnerItem in $Item.Value.getEnumerator()) {
              [console]::writeLine("    $($InnerItem.Key)`n      $($InnerItem.Value)")
            }
          }
          elseif ($Item.Value.Count -gt 1) {
            [console]::ForegroundColor = $this.SectionContent
            for ($i = 0; $i -lt $Item.Value.Count; $i++) {
              [console]::writeLine("    $($Item.Value[$i])")
            }
          }
          else {
            [console]::ForegroundColor = $this.SectionContent
            [console]::writeLine("    $($Item.Value)")
          }
        }
      }
      [console]::resetColor()
      if (![string]::isNullOrEmpty($prompt)) {
        [console]::ForegroundColor = $this.PromptHeader
        $prompt = switch ($prompt) {
          default { $prompt }
        }
        [console]::write($prompt)
      }
    }
    catch {
      #throw $_
    }
    finally {
      [console]::resetColor()
    }
    return [console]::readline()
  }

  hidden [string] IConsole([hashtable]$inputObject, [string]$prompt, [bool]$space)
  {
    try {
      if ($space) {
        [console]::writeLine()
      }
      if ($inputObject) {
        foreach ($Item in $inputObject.getEnumerator()) {
          [console]::ForegroundColor = [consolecolor]::Gray
          [console]::writeLine("  $($Item.Key)")
          if ($Item.Value -is [hashtable]) {
            foreach ($InnerItem in $Item.Value.getEnumerator()) {
              [console]::ForegroundColor = [consolecolor]::DarkGray
              [console]::writeLine("    $($InnerItem.Key)`n      $($InnerItem.Value)")
            }
          }
          elseif ($Item.Value.Count -gt 1) {
            for ($i = 0; $i -lt $Item.Value.Count; $i++) {
              [console]::ForegroundColor = [consolecolor]::DarkGray
              [console]::writeLine("    $($Item.Value[$i])")
            }
          }
          else {
            [console]::ForegroundColor = [consolecolor]::DarkGray
            [console]::writeLine("    $($Item.Value)")
          }
        }
        if ($space) {
          [console]::writeLine()
        }
         [console]::resetColor()
      }
      [console]::ForegroundColor = [consolecolor]::DarkYellow
      $prompt = switch ($prompt) {
        0 { " Press 'enter' to Confirm or 'ctrl+c' to Cancel" }
        1 { " Press 'enter' to Confirm, '+' to add current and search, or try refining search parameter(s)`n > " }
        2 { " Input search parameter(s)`n > " }
        default { $prompt }
      }
      [console]::write($prompt)
    }
    catch {

    }
    finally {
      [console]::resetColor()
    }
    return [console]::readLine()
  }

  [object] IFind([string]$class)
  {
    $Return = [system.collections.arraylist]::new()
    $Queue = [system.collections.queue]::new()
    try {
      $this.setLog(0)
      if ([string]::isNullOrWhiteSpace($class)) {
        $class = $this.iConsole($null, " Input class type`n > ", $false)
      }
      $search = $this.iConsole($null, 2, $false)
      $search.split(',').foreach({ $Queue.enqueue($_) })
      while ($Queue.Count -ne 0) {
        $search = $Queue.dequeue()
        if ($search -match '^[Hh][Ee][Ll][Pp]|\?$') {
          [console]::writeLine(" Search DRA for specified object(s) by parsed string and returns DistinguishedName(s).")
          [console]::writeLine("  ',' Comma(s) is how you submit multiple search strings.                Ex: 'Doe.John, Doe.Jane'")
          [console]::writeLine("  '>' Carat will search 'As Is' without wildcard or regex.               Ex: '>Doe.John.A.12345678'")
          [console]::writeLine("  '*' Star will search by 'FriendlyName' instead of 'DistinguishedName'. Ex: '*Johnny Doe'")
          break
        }
        while ($true) {
          $Object = $this.findObject($class, $search)
          if (!$Object -or ($Object.Count -eq 0)) {
            $search = $this.iConsole(@{"No object(s) returned: $($class)" = $Object}, 2, $true)
          }
          else {
            if ($Object.Count -gt 1) {
              $search = $this.iConsole(@{"Multiple objects returned : $($class)" = $Object}, 1, $true)
            }
            else {
              $search = $this.iConsole(@{"Single object returned : $($class)" = $Object}, 1, $true)
            }
            if ([string]::isNullOrWhiteSpace($search)) {
              $Return.add($Object)
              break
            }
            elseif ($search -match '^\+.*$') {
              $Return.add($Object)
              $search = $search.replace('+', '').trim()
              if ([string]::isNullOrWhiteSpace($search)) {
                $search = $this.iConsole($null, 2, $false)
              }
            }
          }
        }
      }
      #ToDo: This will give time to Ctrl+C. Error Handling should be external to method.
      #$this.iConsole(@{"$($class)" = @(if (!$Return) {$null} else {$Return.split("`n")})}, 0, $false)
    }
    catch {
      $this.toErr("[!] $($_)", 'IFind')
      $Return = [system.collections.arraylist]::new()
    }
    finally {
      $this.resetLog()
    }
    return @(if (!$Return) {$null} else {$Return.split("`n")})
  }

  hidden [void] SetLog([loglevel]$logLevel)
  {
    $this.hLogLevel = $this.LogLevel
    $this.LogLevel = $logLevel
  }

  hidden [void] ResetLog()
  {
    $this.LogLevel = $this.hLogLevel
  }

  ##########################
  #### Random Utilities ####
  ##########################

  [string] ConvertDistinguishedNameToIdentityReference([string]$distinguishedName)
  {
    return $this.convertDistinguishedNameToIdentityReference($distinguishedName, $this.hDomain.split('.')[0].toUpper())
  }

  [string] ConvertDistinguishedNameToIdentityReference([string]$distinguishedName, [string]$domain)
  {
    return [system.security.principal.ntaccount]::new($domain.toUpper(), [regex]::match($distinguishedName, 'CN=([^,]*)').Groups[1].Value)
  }

  ##########################
  ##### Search Section #####
  ##########################
  <#
    Search Section
      Search DRA for specified object(s) by parsed string and returns DistinguishedName(s).
      ',' Comma(s) is how you submit multiple search strings.                Ex: 'Doe.John, Doe.Jane'
      '>' Carat will search 'As Is' without wildcard or regex.               Ex: '>Doe.John.A.12345678'
      '*' Star will search by 'FriendlyName' instead of 'DistinguishedName'. Ex: '*Johnny Doe'
  #>
  
  [string[]] FindObject([draxclass]$class, [string]$search)
  {
    $Query = [hashtable]::new()
    switch -regex ($search) {
      '^>.+$' {
        $this.toDbg("distinguishedname > *$($search.trimStart('>').trim()),*", 'FindObject')
        $Query.add('distinguishedname', "*$($search.trimStart('>').trim()),*")
        break
      }
      '^\*.+$' {
        (' ', '.', '_', '/', '\', '*').foreach({ $search = $search.replace($_, '*') })
        $this.toDbg("displayname > *$($search)", 'FindObject')
        $Query.add('displayname', "*$($search)*")
        break
      }
      default {
        (' ', '.', '_', '/').foreach({ $search = $search.replace($_, '*') })
        $this.toDbg("name > *$($search)", 'FindObject')
        $Query.add('name', "*$($search)*")
        break
      }
    }
    return $this.findDRAxObjects($class, $Query).Items.DistinguishedName
  }

  hidden [object] FindDRAxObjects([draxclass]$class, [hashtable]$query)
  {
    $Splat = [system.collections.hashtable]::new()
    $this.toDbg("$($this.Containers.$($class))", 'FindDRAObjects')
    $Splat.add('ContainerDN', $this.Containers.$($class.toString()))
    $Splat.add('IncludeChildContainers', $true)
    $Splat.add('DRARestServer', "$($this.Server).$($this.Domain)")
    $Splat.add('ErrorAction', 'Stop')
    $Object = [psobject]::new()
    $Key = $Query.Keys[0] -as [string]
    $Value = $Query.Values[0] -as [string]
    switch -regex ($class.toString()) {
      'Computer' {
        $this.toDbg('Computer', 'FindDRAObjects')
        $Object = Find-DRAObjects @Splat -computerOrFilter @{
          'distinguishedname' = $Value
        }
        break
      }
      'Group|AdminGroup' {
        $this.toDbg('(Admin)Group', 'FindDRAObjects')
        $Object = Find-DRAObjects @Splat -groupOrFilter @{
          $Key = $Value
        }
        break
      }
      'Default|User|AdminUser' {
        $this.toDbg('(Admin)User|Default', 'FindDRAObjects')
        $Object = Find-DRAObjects @Splat -userOrFilter @{
          $Key = $Value
        }
        break
      }
    }
    return $Object
  }

  #$DRAx.IConsole(@{'Group' = $ACL.Access.IdentityReference.Value}, "Enter Group > ", $true)

  ############################
  ##### File Permissions #####
  ############################
  <#
    ToDo:
      Show directory information w/ File Permissions and Groups mushed?
    Commands:
      Test if user/group has access to any children in directory.
        * $FSE = $this.getFileSystemEntries($path)
          $FSE.foreach({ if ($this.testAccess($path, $user) { $this.getPermissions($path, $user) })})
  #>

  [object] GetPermissions([string]$path)
  {
    return $this.getPermissions($path, [accesscontrolsections]::All)
  }

  [object] GetPermissions([string]$path, [accesscontrolsections]$section)
  {
    return [directorysecurity]::new($path, $section)
  }

  [object] GetPermissions([string]$path, [string]$name)
  {
    $name = $name.replace('(', '\(')
    $name = $name.replace(')', '\)')
    return [directorysecurity]::new($path, [accesscontrolsections]::Access).Access.where({
      #Hint: Either 'domain\user' or 'user'
      $_.IdentityReference.Value.toString() -match "^.*\\$($name)`$|^$($name.replace('\','\\'))`$"
    })
  }

  [object] SetPermissions([string]$path)
  {
    return $false
  }

  [object] GetAccess([string]$path)
  {
    return $this.getPermissions($path, [accesscontrolsections]::Access).Access `
      | Select-Object 'IdentityReference', 'AccessControlType', 'FileSystemRights', 'IsInherited', 'InheritanceFlags', 'PropagationFlags'
  }

  [bool] GrantAccess([string]$path, [string]$name)
  {
    return $false
  }

  [bool] DenyAccess([string]$path, [string]$name)
  {
    return $false
  }

  [bool] TestAccess([string]$path, [string]$name)
  {
    if (!$this.getPermissions($path, $name)) {
      return $false
    }
    return $true
  }

  [bool] TestVerticalAccess([string]$path, [string]$name)
  {
    $Directories = $this.getAncestors($path)
    if (!$Directories) {
      return $false
    }
    foreach ($directory in $Directories) {
      if (!$this.testAccess($directory, $name)) {
        return $false
      }
    }
    return $true
  }

  [bool] TestVerticalAccess2([string]$path, [string]$name)
  {
    $this.getAncestors($path).foreach({
      if (!$this.testAccess($_, $name)) {
        return $false
      }
    })
    return $true
  }

  [object[]] TestHorizontalAccess([string]$path, [string]$name)
  {
    $Object = [system.collections.arraylist]::new()
    $this.getFileSystemEntries($path).foreach({
      $this.toDbg("$_", "TestHorizontalAccess")
      $this.toDbg("$($_.FullName) - $name", "TestHorizontalAccess")
      if (!$this.testAccess($_.FullName, $name)) {
        $this.toDbg("NoAccess", "TestHorizontalAccess")
        $Object += $_ | Select-Object @{n="Access";e={ @{"$($_.Name)" = $false} }}
      }
      else {
        $this.toDbg("HasAccess", "TestHorizontalAccess")
        $Object += $_ | Select-Object @{n="Access";e={ @{"$($_.Name)" = $this.getPermissions($_.FullName, $name)} }}
      }
    })
    return $Object
  }

  [system.io.directoryinfo[]] GetFileSystemEntries([string]$path)
  {
    return [system.io.directoryinfo[]][system.io.directory]::getFileSystemEntries($path)
  }

  [object] GetAncestors([string]$path)
  {
    if (![system.io.directory]::exists($path)) {
      return $null
    }
    $Item = [system.io.directoryinfo]$path
    $Inner = $Item.FullName.trimEnd('\')
    $Stack = [system.collections.stack]::new()
    do {
      $this.toDbg($Inner, 'GetAncestors')
      $Stack.push($Inner)
      $Inner = $this.getParent($Inner)
    }
    until ($Stack.contains($Item.Root.FullName))
    return $Stack.toArray()
  }

  hidden [object] GetParent([string]$path)
  {
    return ([system.io.directoryinfo]$path).Parent.FullName
  }

  [string] ConvertIdentifier([string]$inputString)
  {
    try {
      switch -regex ($inputString) {
        '^S-1-[0-5](-\S+)*$' {
          return ([system.security.principal.securityidentifier]$inputString).translate([system.security.principal.ntaccount]).Value
        }
        default {
          return ([system.security.principal.ntaccount]$inputString).translate([system.security.principal.securityidentifier]).Value
        }
      }
      $this.toErr("$_", "ConvertIdentifier")
      return 'S-1-0-0'
    }
    catch {
      $this.toErr("$_", "ConvertIdentifier")
      return 'S-1-0-0'
    }
  }

  ###################
  ### Permissions ###
  ###################
  [object] BuildAccessTree([string]$user, [string]$path)
  {
    $UsrGrps = $this.getUser($user, @('MemberOf')).MemberOf.DistinguishedName
    $TstGrps = $this.getFileSystemPermissions($path)
    return $true
  }
  
  [object] TestLogicalAccess([string]$path, [string]$user)
  {
    $Groups = $this.getPermissions($path, $user)
    return $true
  }

  [object] GetFileSystemPermissions([string]$path)
  {
    $Entries = $this.getFileSystemEntries($path)
    $this.Permissions = foreach ($Entry in $Entries) {
      $this.getPermissions($Entry.FullName) | Select-Object -excludeProperty 'Path' @{
        n='Path';e={ $Entry.FullName};
      }, *
    }
    $this.GroupedObjects = $this.Permissions.Access | Group-Object 'IdentityReference'
    return $this.Permissions
  }

  [object] IAnalyze([string]$path)
  {
    $Return = [system.collections.arraylist]::new()
    try {
      $this.setLog(0)
      if ([string]::isNullOrWhiteSpace($path)) {
        $path = $this.iConsole($null, "Input file system path`n > ", $false)
      }
      #$Permissions = $this.getFileSystemPermissions($path)      
    }
    catch {
      $Return = [system.collections.arraylist]::new()
    }
    finally {
      $this.resetLog()
    }
    return $Return
  }

  ##########################
  ##### User Object(s) #####
  ##########################
  <# ToDo:
    Create list of common attributes, all, limited, scenario.
  #>

  [object] GetUser([string]$distinguishedName, [string[]]$attributes)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Get-DRAUser @Splat -id $distinguishedName -attributes $attributes | Select-Object -property $attributes
      $this.toInf("$($distinguishedName)", 'GetUser')
    }
    catch {
      $this.toErr("[!] $($_)", 'GetUser')
    }
    return $Object
  }

  [object] SetUser([string]$distinguishedName, [hashtable]$properties)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Set-DRAUser @Splat -id $distinguishedName -properties $properties
      $this.toInf("$($distinguishedName)", 'SetUser')
    }
    catch {
      $this.toErr("[!] $($_)", 'SetUser')
    }
    return $Object
  }

  [object] RemoveUser([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Remove-DRAUser @Splat -id $distinguishedName
      $this.toInf("$($DistinguishedName)", 'RemoveUser')
    }
    catch {
      $this.toErr("[!] $($_)", 'RemoveUser')
    }
    return $Object
  }

  [object] DisableUser([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Disable-DRAUser @Splat -id $distinguishedName
      $this.toInf("$($distinguishedName)", 'DisableUser')
    }
    catch {
      $this.toErr("[!] $($_)", 'DisableUser')
    }
    return $Object
  }

  [object] EnableUser([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Enable-DRAUser @Splat -id $distinguishedName
      $this.toInf("$($distinguishedName)", 'EnableUser')
    }
    catch {
      $this.toErr("[!] $($_)", 'EnableUser')
    }
    return $Object
  }

  [object] GetUserGroups([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = $this.getUser($distinguishedName, 'MemberOf').MemberOf `
        | Select-Object -property 'sAMAccountName', 'GroupType', 'GroupScope', 'DistinguishedName'
      foreach ($Group in $Object) {
        $this.toInf("[*] $($Group.DistinguishedName)", 'GetUserGroup')
      }
    }
    catch {
      $this.toErr("[!] $($_)", 'GetUserGroup')
    }
    return $Object
  }

  [object] FindOrgBox()
  {
    return $this.getOrgBox($this.iFind([draxclass]::User))
  }

  [object] GetOrgBox([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $CurrentAttributes = 'Office365FullAccess', 'Office365SendAs', 'Office365SendOnBehalf', 'Manager', 'Members', 'DistinguishedName', 'EmailAddress'
      $Object = $this.getUser($distinguishedName, $CurrentAttributes) | Select-Object -property $CurrentAttributes
    }
    catch {
      $this.toErr("[!] $($_)", 'GetOrgBox')
    }
    return $Object
  }

  [object] SetOrgBox([string]$distinguishedName, [hashtable]$properties)
  {
    $Object = [psobject]::new()
    try {
      $Object = $this.setUser($distinguishedName, $properties)
    }
    catch {
      $this.toErr("[!] $($_)", 'SetOrgBox')
    }
    return $Object
  }

  #$rights = @('SendAs','SendOnBehalf','FullAccess')
  [object] AddToOrgBox([string]$distinguishedName, [string[]]$users, [draxemailrights[]]$rights)
  {
    $Object = [psobject]::new()
    try {
      if ($rights -gt 0) {
        $props = @{}
        $rights.foreach({
          $props.add("office365$($_)Add", $users)
        })
      }
      else {
        $props = @{
          'office365SendAsAdd' = $users
          'office365SendOnBehalfAdd' = $users
          'office365FullAccessAdd' = $users
        }
      }
      $Object = $this.setUser($distinguishedName, $props)
    }
    catch {
      $this.toErr("[!] $($_)", 'AddToOrgBox')
    }
    return $Object
  }

  [object] RemoveFromOrgBox([string]$distinguishedName, [string[]]$users, [draxemailrights[]]$rights)
  {
    $Object = [psobject]::new()
    try {
      if ($rights -gt 0) {
        $props = @{}
        $rights.foreach({
          $props.add("office365$($_)Remove", $users)
        })
      }
      else {
        $props = @{
          'office365SendAsRemove' = $users
          'office365SendOnBehalfRemove' = $users
          'office365FullAccessRemove' = $users
        }
      }
      $Object = $this.setUser($distinguishedName, $props)
    }
    catch {
      $this.toErr("[!] $($_)", 'RemoveFromOrgBox')
    }
    return $Object
  }
  
  ###########################
  ##### Group Object(s) #####
  ###########################

  [object] GetGroup([string]$distinguishedName, [string[]]$attributes)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Get-DRAGroup @Splat -id $distinguishedName -attributes $attributes | Select-Object -property $attributes
      $this.toInf("$($distinguishedName)", 'GetGroup')
    }
    catch {
      $this.toErr("[!] $($_)", 'GetGroup')
    }
    return $Object
  }

  [object] SetGroup([string]$distinguishedName, [hashtable]$properties)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Set-DRAGroup @Splat -id $distinguishedName -properties $properties
      $this.toInf("$($distinguishedName)", 'SetGroup')
    }
    catch {
      $this.toErr("[!] $($_)", 'SetGroup')
    }
    return $Object
  }
  
  [object] GetDistro([string]$distinguishedName, [string[]]$attributes)
  {
    $Object = [psobject]::new()
    try {
      $Object = $this.getGroup($distinguishedName, $attributes)
    }
    catch {
      $this.toErr("[!] $($_)", 'GetDistro')
    }
    return $Object
  }

  [object] SetDistro([string]$distinguishedName, [hashtable]$properties)
  {
    $Object = [psobject]::new()
    try {
      $Object = $this.setGroup($distinguishedName, $properties)
    }
    catch {
      $this.toErr("[!] $($_)", 'SetDistro')
    }
    return $Object
  }

  [object] GetDistroManager([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $CurrentAttributes = 'DistinguishedName', 'ManagedBy', 'IsManaged', 'ManagerCanUpdateMembers', 'Members'
      $Object = $this.getDistro($distinguishedName, $CurrentAttributes) | Select-Object -property $CurrentAttributes
      $this.toInf("[*] $distinguishedName", 'GetDistroManager')
    }
    catch {
      $this.toErr("[!] $($_)", 'GetDistroManager')
    }
    return $Object
  }

  [object] SetDistroManager([string]$distinguishedName, [string]$manager) {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Set-DRAGroup @Splat -id $distinguishedName -properties @{
        'ManagedBy' = $manager
        'ManagerCanUpdateMembers' = $true
      }
      $this.toInf("$($manager) > $($distinguishedName)", 'SetDistroManager')
    }
    catch {
      $this.toErr("[!] $($_)", 'SetDistroManager')
    }
    return $Object
  }
  
  ##############################
  ##### Computer Object(s) #####
  ##############################

  [object] IComputer([draxaction]$action)
  {
    $Object = [psobject]::new()

    #Interactive computer operations.
    #Individual methods for 'IAddComputer', 'IRemoveComputer' or 'IComputer' with [draxaction] parameter.
    #F: iComputer with [draxaction] parameter.

    return $Object
  }

  [object] GetComputer([string]$distinguishedName, [string[]]$attributes)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Get-DRAComputer @Splat -id $distinguishedName -attributes $attributes
      $this.toInf("$($distinguishedName)", 'GetComputer')
    }
    catch {
      $this.toErr("[!] $($_)", 'GetComputer')
    }
    return $Object
  }

  [object] SetComputer([string]$distinguishedName, [hashtable]$properties)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Set-DRAComputer @Splat -id $distinguishedName -properties $properties
      $this.toInf("$($distinguishedName)", 'SetComputer')
    }
    catch {
      $this.toErr("[!] $($_)", 'SetComputer')
      return $null
    }
    return $Object
  }

  [object] AddComputer([string]$distinguishedName, [hashtable]$properties)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      if ($distinguishedName -match '[Cc][Nn]=') {
        $DistinguishedName = $distinguishedName
      }
      else {
        $DistinguishedName = "CN=$($distinguishedName),$($this.Containers.Computer)"  
      }
      $properties.add('DistinguishedName', $DistinguishedName)
      #ToDo: Generated Properties for Computer Creation.
      $Object = Add-DRAComputer @Splat -properties $properties
      $this.toInf("$($DistinguishedName)", 'NewComputer')
    }
    catch {
      $this.toErr("[!] $($_)", 'NewComputer')
    }
    return $Object
  }

  [object] RemoveComputer([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Remove-DRAComputer @Splat -id $distinguishedName
      $this.toInf("$($DistinguishedName)", 'RemoveComputer')
    }
    catch {
      $this.toErr("[!] $($_)", 'RemoveComputer')
    }
    return $Object
  }

  [object] DisableComputer([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Object = $this.setComputer($distinguishedName, @{IsDisabled = $true})
    }
    catch {
      $this.toErr("[!] $($_)", 'DisableComputer')
    }
    return $Object
  }

  [object] EnableComputer([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Object = $this.setComputer($distinguishedName, @{IsDisabled = $false})
    }
    catch {
      $this.toErr("[!] $($_)", 'EnableComputer')
    }
    return $Object
  }
}
