<#
  == Directory and Resources Administrator eXtension ==
  Dependencies:
    NetIQ DRA PowerShellExtensions.
  ToDo:
   
    View properties of users, groups, and computers.
    Add version control and security measures.
#>

using namespace System.IO;
using namespace System.Security.AccessControl;

function Start-DRAx {
  
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

enum LogLevel
{
  ERR = 0
  WRN = 1
  INF = 2
  DBG = 3
}

enum OrgBoxAction
{
  FullAccess
  SendAs
  SendOnBehalf
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

  hidden [string]$hDomain = $env:USERDNSDOMAIN
  hidden [string]$hModule = 'C:\Program Files (x86)\NetIQ\DRA Extensions\modules\NetIQ.DRA.PowerShellExtensions'
  hidden [int]$hPort = 8755
  hidden [int]$hLogLevel
  hidden [consolecolor]$PromptHeader   = [consolecolor]::DarkYellow
   hidden [consolecolor]$SectionHeader  = [consolecolor]::Gray
   hidden [consolecolor]$SectionContent = [consolecolor]::DarkGray

  DRAx()
  {
    
  }

  [drax] Initialize()
  {
    if (!$this.import("$($PsScriptRoot)\DRAx.json")) {
      throw "Failed to Initialize"
    }
    return $this.initialize($this.hModule, $true)
  }

  [drax] Initialize([string]$configPath)
  {
    if (!$this.import($configPath)) {
      throw "Failed to Initialize"
    }
    return $this.initialize($this.hModule, $true)
  }

  [drax] Initialize([string]$modulePath, [bool]$findOptimalServer)
  {
    try {
      if ($modulePath -eq [string]::isNullOrEmpty -or !$modulePath) {
        Import-Module -name $this.hModule -errorAction 'Stop'
      }
      else {
        Import-Module -name $modulePath -errorAction 'Stop'
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
      $this.Domain = $Config.Domain
      $this.Containers = $Config.Containers
      $this.Servers = $Config.Servers
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

  ##### Interaction Section #####

  [object] EnterConsole()
  {
    do {
      [console]::clear()
      $R0 = $this.console(@{"Select Category" = @(
        "1: Quick Actions",
        "2: Computer(s)",
        "3: Distro(s)/Group(s)",
        "4: User(s)/OrgAcct(s)",
        "0: Return"
      )}, "`n== DRAx Console ==`n", "`nDRAx > ")
      switch -regex ($R0) {
        "^0$" {
          return ""
        }
        "^\?$|^[Hh](elp)*$" {
          #ToDo: DisplayHelp
          continue
        }
        "^1$" {
          $R1 = $this.console(@{"Options" = @()}, $null, "`nDRAx [QuickAction] > ")
        }
        "^2|^[Cc]omputer(?:s*)$" {
          $R1 = $this.console(@{"Options" = @(
            "1: Create`tCreate AFNet Computer",
            "2: Restore`tRecreate Computer",
            "3: Delete`tMove Computer to recycling bin",
            "4: Disable`tDisable Computer",
            "5: Enable`tEnable Computer",
            "6: Get`tGet properties for Computer",
            "7: Edit`tEdit properties for Computer",
            "0: Return"
          )}, $null, "`nDRAx [Computer] > ")
        }
        "^3$" {
          $R1 = $this.console(@{"Options" = @(
            "1: Create Group",
            "2: Get Group",
            "3: Edit Group",
            "3: Get Group Member(s)",
            "4: Set Group Member(s)",
            "5: Get Distro Manager",
            "6: Set Distro Manager",
            "7: Get Distro Member(s)",
            "8: Set Distro Member(s)",
            "0: Return"
          )}, $null, "`nDRAx [Group|Distro] > ")
        }
        "^4$" {
          $R1 = $this.console(@{"Options" = @(
            "1: Create User",
            "2: Delete User",
            "3: Get User properties",
            "4: Edit User properties",
            "5: Enable User",
            "6: Disable User",
            "7: Mirror Users",
            "0: Return"
          )}, $null, "`nDRAx [User] > ")
          switch -regex ($R1) {
            "^0$" { break }
            "^1$" {
              [console]::writeLine("<NotImplimented>")
            }
            "^2$" {
              [console]::writeLine("<NotImplimented>")
            }
            "^3$" {
              return $this.getUserProperties($this.iFind("User", $null))
            }
            "^4$" {}
            "^5$" {}
            "^6$" {}
            "^7$" {}
          }
        }
        "[G|g]et [U|u]ser (?<a>.*)" {
          $r1 = $this.iFind('User', $matches.a.toString())
        }
        "[G|g]et [C|c]omputer (?<a>.*)" {
          $r1 = $this.iFind('Computer', $matches.a.toString())
        }
        "[G|g]et\s[D|d]istro\s(?<D>\S*)" {
          $DistroManager = $this.getDistroManager($this.iFind("Group", $matches.D))
        }
        "[N|n]ew [C|c]omputer (?<a>.*)" {
          
        }
      }
      [console]::readKey()
    }
    while ($true)
    return ""
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

  ##### Search Section #####
  <#####################################################################################################
    Search Section
      Search DRA for specified object(s) by parsed string and returns DistinguishedName(s).
      ',' Comma(s) is how you submit multiple search strings.                Ex: 'Doe.John, Doe.Jane'
      '>' Carat will search 'As Is' without wildcard or regex.               Ex: '>Doe.John.A.12345678'
      '*' Star will search by 'FriendlyName' instead of 'DistinguishedName'. Ex: '*Johnny Doe'
  #####################################################################################################>
  
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
    $Object = $null
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

  ##### Shared Commands #####

  [object] GetUserGroups([string]$identifier)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = (Get-DRAUser -identifier $identifier -attributes 'MemberOf' @Splat).MemberOf `
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

  #$DRAx.IConsole(@{'Group' = $ACL.Access.IdentityReference.Value}, "Enter Group > ", $true)

  ##### File Permissions #####
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
    return $this.getPermissions($path, 'All')
  }

  [object] GetPermissions([string]$path, [string]$identifier)
  {
    return [directorysecurity]::new($path, 'Access').Access.where({
      $_.IdentityReference.Value -match "^.*\\$($identifier)`$|^$($identifier.replace('\','\\'))`$"
    })
  }
 
  [object] GetPermissions([string]$path, [accesscontrolsections]$section)
  {
    return [directorysecurity]::new($path, $section)
  }

  [object] SetPermissions([string]$path)
  {
    return $false
  }

  [bool] GrantAccess([string]$path, [string]$identifier)
  {
    return $false
  }

  [bool] DenyAccess([string]$path, [string]$identifier)
  {
    return $false
  }

  [bool] TestAccess([string]$path, [string]$identifier)
  {
    if (!$this.getPermissions($path, $identifier)) {
      return $false
    }
    return $true
  }

  [bool] TestVerticalAccess([string]$path, [string]$identifier)
  {
    $Directories = $this.getAncestors($path)
    if (!$Directories) {
      return $false
    }
    foreach ($directory in $Directories) {
      if (!$this.testAccess($directory, $identifier)) {
        return $false
      }
    }
    return $true
  }

  [bool] TestVerticalAccess2([string]$path, [string]$identifier)
  {
    $this.getAncestors($path).foreach({
      if (!$this.testAccess($_, $identifier)) {
        return $false
      }
    })
    return $true
  }

  [object[]] TestHorizontalAccess([string]$path, [string]$identifier)
  {
    $Object = [system.collections.arraylist]::new()
    $this.getFileSystemEntries($path).foreach({
      $this.toDbg("$_", "TestHorizontalAccess")
      $this.toDbg("$($_.FullName) - $identifier", "TestHorizontalAccess")
      if (!$this.testAccess($_.FullName, $identifier)) {
        $this.toDbg("NoAccess", "TestHorizontalAccess")
        $Object += "" | Select-Object @{n="Access";e={ @{"$($_.Name)" = $false} }}
      }
      else {
        $this.toDbg("HasAccess", "TestHorizontalAccess")
        $Object += "" | Select-Object @{n="Access";e={ @{"$($_.Name)" = $this.getPermissions($_.FullName, $identifier)} }}
      }
    })
    return $Object
  }

  [system.io.directoryinfo[]] GetFileSystemEntries([string]$path)
  {
    return [system.io.directoryinfo[]][system.io.directory]::GetFileSystemEntries($path)
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

  ##### Distribution Object(s) #####

  [object] GetDistroManager([string]$identifier)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Attributes = 'DistinguishedName', 'ManagedBy', 'IsManaged', 'ManagerCanUpdateMembers'
      $Object = Get-DRAGroup @Splat -identifier $identifier -attributes $Attributes | Select-Object $Attributes
      $this.toInf("[*] $identifier", 'GetDistroManager')
    }
    catch {
      $this.toErr("[!] $($_)", 'GetDistroManager')
    }
    return $Object
  }

  [object] SetDistroManager([string]$identifier, [string]$manager) {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Set-DRAGroup @Splat -identifier $identifier -properties @{
        'ManagedBy' = $manager
        'ManagerCanUpdateMembers' = $true
      }
      $this.toInf("$($manager) > $($identifier)", 'SetDistroManager')
    }
    catch {
      $this.toErr("[!] $($_)", 'SetDistroManager')
    }
    return $Object
  }

  ##### Organization Object(s) #####

  #TEMP
  [object] FindOrgBox()
  {
    return $this.getOrgBox($this.iFind([draxclass]::User))
  }

  [object] AddOrgBox([string]$identifier, [string[]]$users)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getOrgBoxSplat($identifier)
      $Object = Set-DRAUser @Splat -properties @{
        'office365SendAsAdd' = $users
        'office365SendOnBehalfAdd' = $users
        'office365FullAccessAdd' = $users
      }
      foreach ($user in $users) {
        $this.toInf("$($user.split(',')[0])", 'AddOrgBox')
      }
    }
    catch {
      $this.toErr("[!] $($_)", 'AddOrgBox')
    }
    return $Object
  }

  [object] GetOrgBox([string]$identifier)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getOrgBoxSplat($identifier)
      $Attributes = 'Office365FullAccess', 'Office365SendAs', 'Office365SendOnBehalf', 'Manager', 'DistinguishedName', 'EmailAddress'
      $Object = Get-DRAUser @Splat -attributes $Attributes | Select-Object $Attributes
    }
    catch {
      $this.toErr("[!] $($_)", 'GetOrgBox')
    }
    return $Object
  }

  [object] RemoveOrgBox([string]$identifier, [string[]]$users)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getOrgBoxSplat($identifier)
      $Object = Set-DRAUser @Splat -properties @{
        'office365SendAsRemove' = $users
        'office365SendOnBehalfRemove' = $users
        'office365FullAccessRemove' = $users
      }
      foreach ($user in $users) {
        $this.toInf("$($user.split(',')[0])", 'RemoveOrgBox')
      }
    }
    catch {
      $this.toErr("[!] $($_)", 'RemoveOrgBox')
    }
    return $Object
  }

  hidden [object] GetOrgBoxSplat([string]$identifier)
  {
    $Splat = [system.collections.hashtable]::new()
    $Splat.add('Identifier', "$($identifier)")
    $Splat.add('Domain', "$($this.Domain)")
    $Splat.add('DRARestServer', "$($this.Server).$($this.Domain)")
    $Splat.add('ErrorAction', 'Stop')
    return $Splat    
  }

  ##### Computer Object(s) #####

  [object] IComputer([draxaction]$action)
  {
    $Object = [psobject]::new()

    #Interactive computer operations.
    #Individual methods for 'IAddComputer', 'IRemoveComputer' or 'IComputer' with [draxaction] parameter.
    #F: iComputer with [draxaction] parameter.

    return $Object
  }

  [object] AddComputer([string]$name, [hashtable]$properties)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      if ($name -match '[Cc][Nn]=') {
        $DistinguishedName = $name
      }
      else {
        $DistinguishedName = "CN=$($name),$($this.Containers.Computer)"  
      }
      $properties.add('DistinguishedName', $DistinguishedName)
      #$Object = Add-DRAComputer @Splat -properties $properties
      $this.toInf("$($DistinguishedName)", 'NewComputer')
    }
    catch {
      $this.toErr("[!] $($_)", 'NewComputer')
    }
    return $Object
  }

  #GetComputer
  #SetComputer

  [object] RemoveComputer([string]$distinguishedName)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      #$Object = Remove-DRAComputer @Splat -id $distinguishedName
      $this.toInf("$($DistinguishedName)", 'RemoveComputer')
    }
    catch {
      $this.toErr("[!] $($_)", 'RemoveComputer')
    }
    return $Object
  }

  ##### User Object(s) #####
  <# ToDo:
    Create list of common attributes, all, limited, scenario.
  #>

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
      return $null
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
      return $null
    }
    return $Object
  }

  [object] GetUser([string]$distinguishedName, [string[]]$attributes)
  {
    $Object = [psobject]::new()
    try {
      $Splat = $this.getSplat()
      $Object = Get-DRAUser @Splat -id $distinguishedName -attributes $attributes
      $this.toInf("$($distinguishedName)", 'GetUser')
    }
    catch {
      $this.toErr("[!] $($_)", 'GetUser')
      return $null
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
      return $null
    }
    return $Object
  }
}
