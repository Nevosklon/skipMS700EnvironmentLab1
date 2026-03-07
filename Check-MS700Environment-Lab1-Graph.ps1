<#
.SYNOPSIS
MS-700 Lab 1 automation using Microsoft Graph + Teams with least-privilege Graph scopes.
Phase A: users/licensing/groups (User.ReadWrite.All, Group.ReadWrite.All)
Phase B: directory roles, Group.Unified settings, lifecycle (Directory.ReadWrite.All, Group.ReadWrite.All)
Teams: policies + teams via MicrosoftTeams module.

.NOTES
Requires: Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, MicrosoftTeams
Run as: Global Admin (or equivalent) with Teams service admin permissions
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$TenantName,
  

  # Key users
  [string]$JoniUPN  = "JoniS@$($TenantName).onmicrosoft.com",
  [string]$PattiUPN = "PattiF@$($TenantName).onmicrosoft.com",
  [string]$AllanUPN = "AllanD@$($TenantName).onmicrosoft.com",
  [string]$AlexUPN  = "AlexW@$($TenantName).onmicrosoft.com",
  [string]$LynneUPN = "LynneR@$($TenantName).onmicrosoft.com",
  [string]$DiegoUPN = "DiegoS@$($TenantName).onmicrosoft.com",

  # Pilot users
  [string[]]$PilotUsers = @(
    "JoniS@$($TenantName).onmicrosoft.com",
    "PattiF@$($TenantName).onmicrosoft.com",
    "AllanD@$($TenantName).onmicrosoft.com",
    "AlexW@$($TenantName).onmicrosoft.com",
    "LynneR@$($TenantName).onmicrosoft.com",
    "DiegoS@$($TenantName).onmicrosoft.com"
  ),

  # E5 SKU preference order
  [string[]]$PreferredSkuPartNumbers = @("ENTERPRISEPREMIUM","SPE_E5","M365_E5"),

  # Governance
  [string]$AllowedCreatorsGroupName = "Teams-GroupCreators",
  [string]$PrefixSuffixNamingRequirement = "GRP_[GroupName]_[Department]", # must include [GroupName]
  [string]$CustomBlockedWordsList = "CEO,CFO,Payroll,HR",
  [int]$GroupLifetimeInDays = 180,
  [string]$LifecycleNotificationEmails = "admin@$($TenantName).onmicrosoft.com",

  # Teams update policy
  [string]$TeamsUpdatePolicyName = "PublicPreviewEnabled",
  [ValidateSet("Disabled","Enabled","Forced","FollowOfficePreview","AdminDisabled")]
  [string]$AllowPublicPreview = "Enabled",

  # Lab additions
  [ValidatePattern('^[A-Z]{2}$')]
  [string]$AlexUsageLocation = "CA",

  # Sample M365 group
  [string]$ItDeptGroupName = "IT-Department",
  [string]$ItDeptDescription = "All staff of the IT-Department",

  # Sample Teams
  [string]$TeamsRolloutTeamName = "Teams Rollout",
  [string]$AfterworkTeamName    = "Group_Afterwork_",

  [switch]$complete
  [switch]$WhatIf
)

# ================= Modules =================
function Ensure-Module {
  param([Parameter(Mandatory=$true)][string]$Module)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Information "Installing module: $Name ..."
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $Name -ErrorAction Stop
}
function Ensure-Modules {
  param([Parameter(Mandatory=$true)[string[]]$Modules])
  foreach ( $m in $Modules ) {
    Ensure-Module -Module $m
  }
}

Ensure-Modules -Modules @( 'Microsoft.Graph.Users','Microsoft.Graph.Groups','Microsoft.Graph.Beta.Identity.DirectoryManagement','MicrosoftTeams');

# ================= Graph connection (least privilege) =================
function Connect-Graph-MinScopes {
  param([Parameter(Mandatory=$true)][string[]]$Scopes)
  $Scopes = $Scopes | Sort-Object -Unique
  try {
    $ctx = Get-MgContext -ErrorAction Stop
    $missing = $Scopes | Where-Object { $_ -notin ($ctx.Scopes) }
    if ($missing) {
      Write-Information "Reconnecting to Graph with additional scopes: $($missing -join ', ')"
      Connect-MgGraph -Scopes $Scopes | Out-Null
    } else {
      Write-Information "Graph already connected with required scopes."
    }
  } catch {
    Write-Information "Connecting to Graph with scopes: $($Scopes -join ', ')"
    Connect-MgGraph -Scopes $Scopes | Out-Null
  }
}

# ================= Teams connection =================
function Ensure-TeamsModulesAndConnect {
  try { Get-CsTenant -ErrorAction Stop | Out-Null; Write-Information "Already connected to Microsoft Teams."; }
  catch { Write-Information "Connecting to Microsoft Teams ..."; Connect-MicrosoftTeams | Out-Null }
}

# ================= Utilities =================
$ErrorActionPreference = 'Stop'
$MaximumFunctionCount = 32768

function Get-UserByUpn {
  param([string]$Upn)
  $user = Get-MgUser -Filter "userPrincipalName eq '$Upn'"
  if (-not $user) { throw "User not found: $Upn" }
  return $user
}

function To-MailNickname {
  param([string]$DisplayName)
  ($DisplayName -replace "[^A-Za-z0-9.]", "").ToLower()
}

# ---------- Phase A helpers (Users/Licenses/Groups) ----------
function Resolve-PreferredSku {
  param([string[]]$PreferredSkuPartNumbers)
  $skus = Get-MgBetaSubscribedSku
  foreach ($p in $PreferredSkuPartNumbers) {
    $sku = $skus | Where-Object { $_.SkuPartNumber -eq $p }
    if ($sku) { return $sku }
  }
  $fallback = $skus | Where-Object { $_.SkuPartNumber -match 'E5' } | Select-Object -First 1
  if ($fallback) { return $fallback }
  throw "No suitable E5 license SKU found in tenant."
}

function Ensure-License {
  param([string]$UserUpn,[object]$Sku)
  $user = Get-UserByUpn -Upn $UserUpn
  $has = (Get-MgUserLicenseDetail -UserId $user.Id) | Where-Object { $_.SkuId -eq $Sku.SkuId }
  if ($has) { Write-Information "OK: $UserUpn already has SKU $($Sku.SkuPartNumber)."; return }
  $prepaid = $Sku.PrepaidUnits.Enabled; $used = $Sku.ConsumedUnits
  if ((($prepaid) - ($used)) -le 0) { throw "No available licenses for $($Sku.SkuPartNumber)" }
  Write-Information "Assigning license $($Sku.SkuPartNumber) to $UserUpn ..."
  if (-not $WhatIf) { Update-MgUserLicense -UserId $user.Id -AddLicenses @{SkuId=$Sku.SkuId} -RemoveLicenses @() }
  else { Write-Information "WhatIf: Would assign SkuId $($Sku.SkuId) to $UserUpn" }
}

function Ensure-UsageLocation {
  param([string]$UserUpn,[ValidatePattern('^[A-Z]{2}$')][string]$CountryCode)
  $user = Get-UserByUpn -Upn $UserUpn
  if ($user.UsageLocation -ne $CountryCode) {
    Write-Information "Setting UsageLocation for $($UserUpn): '$($user.UsageLocation)' -> '$CountryCode'"
    if (-not $WhatIf) { Update-MgUser -UserId $user.Id -UsageLocation $CountryCode }
    else { Write-Information "WhatIf: Would set UsageLocation=$CountryCode for $UserUpn" }
  } else { Write-Information "OK: $UserUpn already has UsageLocation '$CountryCode'" }
}

function Ensure-SecurityGroup {
  param([string]$DisplayName)
  $grp = Get-MgGroup -Filter "displayName eq '$DisplayName'"
  if (-not $grp) {
    Write-Information "Creating security group '$DisplayName' ..."
    if (-not $WhatIf) {
      $grp = New-MgGroup -DisplayName $DisplayName `
        -MailEnabled:$false -MailNickname (To-MailNickname $DisplayName) `
        -SecurityEnabled:$true -Description "Users allowed to create Microsoft 365 Groups"
    } else { Write-Information "WhatIf: Would create security-enabled group '$DisplayName'"; return $null }
  } else { Write-Information "OK: Security group '$DisplayName' exists." }
  return $grp
}

function Ensure-GroupMembers {
  param([string]$GroupDisplayName,[string[]]$MemberUpns)
  $grp = Get-MgGroup -Filter "displayName eq '$GroupDisplayName'"
  if (-not $grp) { throw "Group not found: $GroupDisplayName" }
  $existing = @(); try { $existing = (Get-MgGroupMember -GroupId $grp.Id -All).Id } catch {}
  foreach ($u in $MemberUpns) {
    try { $usr = Get-UserByUpn -Upn $u } catch { Write-Warning $_; continue }
    if ($existing -contains $usr.Id) { Write-Information "OK: $u already member of '$GroupDisplayName'" }
    else {
      Write-Information "Adding $u to '$GroupDisplayName' ..."
      if (-not $WhatIf) {
        New-MgGroupMemberByRef -GroupId $grp.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($usr.Id)" }
      } else { Write-Information "WhatIf: Would add $u to $GroupDisplayName" }
    }
  }
}

function Ensure-M365Group {
  param([string]$DisplayName,[string]$Description,[string[]]$OwnersUpn,[string[]]$MembersUpn)
  $existing = Get-MgGroup -Filter "displayName eq '$DisplayName'"
  if (-not $existing) {
    $mailNick = To-MailNickname -DisplayName $DisplayName
    Write-Information "Creating Microsoft 365 Group '$DisplayName' ..."
    if (-not $WhatIf) {
      $grp = New-MgGroup -DisplayName $DisplayName -Description $Description `
        -MailEnabled:$true -MailNickname $mailNick -SecurityEnabled:$false -GroupTypes "Unified"
    } else { Write-Information "WhatIf: Would create M365 Group '$DisplayName'"; return }
  } else { $grp = $existing; Write-Information "OK: Microsoft 365 Group '$DisplayName' exists." }

  if ($grp) {
    # Owners
    $ownerIds = @(); try { $ownerIds = (Get-MgGroupOwner -GroupId $grp.Id -All).Id } catch {}
    foreach ($o in $OwnersUpn) {
      try { $ouser = Get-UserByUpn -Upn $o } catch { Write-Warning $_; continue }
      if ($ownerIds -contains $ouser.Id) { Write-Information "OK: $o already owner of '$DisplayName'" }
      else {
        Write-Information "Adding owner $o to '$DisplayName'"
        if (-not $WhatIf) {
          New-MgGroupOwnerByRef -GroupId $grp.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($ouser.Id)" }
        }
      }
    }

    # Members
    $memberIds = @(); try { $memberIds = (Get-MgGroupMember -GroupId $grp.Id -All).Id } catch {}
    foreach ($m in $MembersUpn) {
      try { $muser = Get-UserByUpn -Upn $m } catch { Write-Warning $_; continue }
      if ($memberIds -contains $muser.Id) { Write-Information "OK: $m already member of '$DisplayName'" }
      else {
        Write-Information "Adding member $m to '$DisplayName'"
        if (-not $WhatIf) {
          New-MgGroupMemberByRef -GroupId $grp.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($muser.Id)" }
        }
      }
    }
  }
}

# ---------- Phase B helpers (Directory settings/Roles/Lifecycle) ----------

function Ensure-DirectoryRole {
  param([Parameter(Mandatory=$true)][string]$RoleDisplayName)

  # 1) Is the role already active?
  $role = Get-MgBetaDirectoryRole | Where-Object { $_.DisplayName -eq $RoleDisplayName }
  if ($role) { return $role }

  # 2) Find its template
  $template = Get-MgBetaDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleDisplayName }
  if (-not $template) { throw "Role template not found for '$RoleDisplayName'." }

  # 3) Activate the role using BodyParameter (works on all SDK versions)
  Write-Information "Activating directory role '$RoleDisplayName' ..."
  if (-not $WhatIf) {
    New-MgBetaDirectoryRole -BodyParameter @{ roleTemplateId = $template.Id } | Out-Null
    Start-Sleep -Seconds 2
  } else {
    Write-Information "WhatIf: Would activate role from template $($template.Id)"
  }

  # 4) Return the active instance
  return (Get-MgBetaDirectoryRole | Where-Object { $_.DisplayName -eq $RoleDisplayName })
}


function Ensure-RoleMembership {
  param([string]$RoleDisplayName,[string]$UserUpn)
  $user = Get-UserByUpn -Upn $UserUpn
  $role = Ensure-DirectoryRole -RoleDisplayName $RoleDisplayName
  if (-not $role) { return }
  $members = Get-MgBetaDirectoryRoleMember -DirectoryRoleId $role.Id -All
  $already = $members | Where-Object { $_.Id -eq $user.Id }
  if ($already) { Write-Information "OK: $UserUpn already in '$RoleDisplayName'." }
  else {
    Write-Information "Adding $UserUpn to '$RoleDisplayName' ..."
    if (-not $WhatIf) {
      New-MgBetaDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)" }
    } else { Write-Information "WhatIf: Would add $UserUpn to $RoleDisplayName" }
  }
}

function Get-OrCreate-GroupUnifiedSetting {
  $setting = Get-MgBetaDirectorySetting | Where-Object { $_.DisplayName -eq 'Group.Unified' }
  if (-not $setting) {
    Write-Information "Creating 'Group.Unified' directory setting from template ..."
    $template = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq 'Group.Unified' }
    if (-not $template) { throw "Group.Unified template not found." }
    if (-not $WhatIf) {
      New-MgBetaDirectorySetting -DirectorySetting @{ TemplateId=$template.Id; Values=@() } | Out-Null
      $setting = Get-MgBetaDirectorySetting | Where-Object { $_.DisplayName -eq 'Group.Unified' }
    } else { Write-Information "WhatIf: Would create directory setting from template $($template.Id)"; return $null }
  }
  return $setting
}
function Update-NCreate-DirectorySetting {
  param( [string]$DirectorySettingId, [object]$DirectorySetting )
  try {
    Update-MgBetaDirectorySetting -DirectorySettingId $Setting.Id -DirectorySetting @{ Values=$Setting.Values } -ErrorAction Stop | Out-Null  
  } catch {
    Write-Information "Attempt to create default tenant directory settings "
    if (-not $template) { throw "Group.Unified template not found." }
    New-MgBetaDirectorySetting -DirectorySetting @{ TemplateId=$template.Id; Values=$Setting.Values } -ErrorAction Stop | Out-Null    
  } 
}
function Update-DirectorySettingValues {
  param([hashtable]$Desired)
  $setting = Get-OrCreate-GroupUnifiedSetting
  $changed = $false
  foreach ($k in $Desired.Keys) {
    $newVal = [string]$Desired[$k]
    if ($entry.Value -eq $newVal) {
      Write-Information "Untouched option $k = $newVal"
      continue
    };

    $changed = $true;
    if (-not $entry) {
    $Setting.Values += @{ Name=$k; Value=$newVal }
      Write-Information "Adding option $k = $newVal"
      continue
    }
    $entry.Value=$newVal
    Write-Information "changing option $k = $newVal"
  }
  if ($WhatIf) {
    Write-Information "whatif: tenant's directory setting changes was performed." 
    return;
  };

  if ($changed) {
    $settings = @{
      DirectorySettingId = $Setting.Id
      DirectorySetting   = @{ Values = $Setting.Values }
    };
    try { Update-NCreate-DirectorySetting @settings return } catch { Write-Error $_.Exception.Message }
    return;
  };

}

function Ensure-GroupCreationRestriction {
  param([string]$AllowedCreatorsGroupName)
  $grp = Get-MgGroup -Filter "displayName eq '$AllowedCreatorsGroupName'"
  $desired = @{
    "EnableGroupCreation"         = "false"
    "GroupCreationAllowedGroupId" = if ($grp) { $grp.Id } else { [Guid]::Empty.Guid }
  }
  Update-DirectorySettingValues  -Desired $desired
}

function Ensure-GroupNamingPolicy {
  param([string]$PrefixSuffixNamingRequirement,[string]$CustomBlockedWordsList)
  $desired = @{
    "PrefixSuffixNamingRequirement" = $PrefixSuffixNamingRequirement
    "CustomBlockedWordsList"        = $CustomBlockedWordsList
  }
  Update-DirectorySettingValues  -Desired $desired
}

function Ensure-GroupLifecyclePolicy {
  param([int]$GroupLifetimeInDays,[string]$AlternateNotificationEmails)
  $policy = Get-MgGroupBetaLifecyclePolicy | Select-Object -First 1
  if (-not $policy) {
    Write-Information "Creating Group Lifecycle Policy ..."
    if (-not $WhatIf) {
      New-MgGroupBetaLifecyclePolicy -GroupLifetimeInDays $GroupLifetimeInDays -ManagedGroupTypes "All" -AlternateNotificationEmails $AlternateNotificationEmails | Out-Null
    } else { Write-Information "WhatIf: Would create lifecycle policy" }
  } else {
    $needsUpdate = ($policy.GroupLifetimeInDays -ne $GroupLifetimeInDays) -or
                   ($policy.ManagedGroupTypes -ne "All") -or
                   ($policy.AlternateNotificationEmails -ne $AlternateNotificationEmails)
    if ($needsUpdate) {
      Write-Information "Updating Group Lifecycle Policy ..."
      if (-not $WhatIf) {
        Update-MgGroupBetaLifecyclePolicy -GroupLifecyclePolicyId $policy.Id `
          -GroupLifetimeInDays $GroupLifetimeInDays -ManagedGroupTypes "All" -AlternateNotificationEmails $AlternateNotificationEmails | Out-Null
      } else { Write-Information "WhatIf: Would update lifecycle policy" }
    } else { Write-Information "OK: Lifecycle policy already desired state." }
  }
}

function Ensure-Tenant {
  try {
    if ( -not (Get-MgBetaDirectorySetting -ErrorAction Stop)) {
      Write-Information "Creating Tenant"
      $id = (Get-MgBetaDirectorySettingTemplate -ErrorAction Stop | where { $_.DisplayName -eq "Group.Unified" }).id;
      New-MgBetaDirectorySetting
      
    } 
  } catch {
     Write-Error "Ensure that we have connected to Entra"
  }
}

# ================= Execution =================

# ---- Phase A: minimal scopes (users, licenses, groups) ----
Connect-Graph-MinScopes -Scopes @('User.ReadWrite.All','Group.ReadWrite.All','LicenseAssignment.Read.All','RoleManagement.ReadWrite.Directory','Directory.ReadWrite.All')

Write-Information "`n=== Ensuring pilot users are licensed (E5) ==="
$sku = Resolve-PreferredSku -PreferredSkuPartNumbers $PreferredSkuPartNumbers
foreach ($u in $PilotUsers) { Ensure-License -UserUpn $u -Sku $sku }

Write-Information "`n=== Lab 1: Setting usage location for Alex Wilber ==="
Ensure-UsageLocation -UserUpn $AlexUPN -CountryCode $AlexUsageLocation

Write-Information "`n=== Preparing Group Creation Restriction helper group ==="
$allowedGrp = Ensure-SecurityGroup -DisplayName $AllowedCreatorsGroupName
if ($allowedGrp) { Ensure-GroupMembers -GroupDisplayName $AllowedCreatorsGroupName -MemberUpns $PilotUsers }

Write-Information "`n=== Lab 1: Creating Microsoft 365 Group (IT-Department) ==="
Ensure-M365Group -DisplayName $ItDeptGroupName -Description $ItDeptDescription -OwnersUpn @($JoniUPN) -MembersUpn @($PattiUPN,$AllanUPN)

Write-Information "`n=== Ensuring admin role assignments ==="
Ensure-RoleMembership -RoleDisplayName "Teams Administrator"                    -UserUpn $JoniUPN
Ensure-RoleMembership -RoleDisplayName "Teams Devices Administrator"           -UserUpn $PattiUPN
Ensure-RoleMembership -RoleDisplayName "Teams Communications Support Engineer" -UserUpn $AllanUPN

Write-Information "`n=== Ensuring Group Naming Policy ==="
if ($PrefixSuffixNamingRequirement -notmatch '\[GroupName\]') { throw "PrefixSuffixNamingRequirement must include [GroupName]." }
#Ensure-GroupNamingPolicy -PrefixSuffixNamingRequirement $PrefixSuffixNamingRequirement -CustomBlockedWordsList $CustomBlockedWordsList

Write-Information "`n=== Restricting Microsoft 365 Group creation to a security group ==="
#Ensure-GroupCreationRestriction -AllowedCreatorsGroupName $AllowedCreatorsGroupName

Write-Information "`n=== Ensuring Group Lifecycle (Expiration) Policy ==="
#Ensure-GroupLifecyclePolicy -GroupLifetimeInDays $GroupLifetimeInDays -AlternateNotificationEmails $LifecycleNotificationEmails

# Optional: Disconnect once done with elevated permissions
Disconnect-MgGraph -ErrorAction SilentlyContinue

# ---- Teams portion (independent of Graph scopes) ----
Write-Information "`n=== Ensuring Teams Update Management Policy (Public Preview) ==="
Ensure-TeamsModulesAndConnect
$policy = $null
try { $policy = Get-CsTeamsUpdateManagementPolicy -Identity $TeamsUpdatePolicyName -ErrorAction Stop } catch {}
if (-not $policy) {
  Write-Information "Creating Teams Update Management policy '$TeamsUpdatePolicyName' (AllowPublicPreview=$AllowPublicPreview) ..."
  if (-not $WhatIf) { New-CsTeamsUpdateManagementPolicy -Identity $TeamsUpdatePolicyName -AllowPublicPreview $AllowPublicPreview | Out-Null }
} else {
  if ($policy.AllowPublicPreview -ne $AllowPublicPreview) {
    Write-Information "Updating policy '$TeamsUpdatePolicyName' to $AllowPublicPreview ..."
    if (-not $WhatIf) { Set-CsTeamsUpdateManagementPolicy -Identity $TeamsUpdatePolicyName -AllowPublicPreview $AllowPublicPreview | Out-Null }
  } else { Write-Information "OK: '$TeamsUpdatePolicyName' already set to $AllowPublicPreview." }
}
foreach ($upn in $PilotUsers) {
  try { $current = (Get-CsOnlineUser -Identity $upn -ErrorAction Stop).TeamsUpdateManagementPolicy } catch { Write-Warning "Cannot read Teams user '$upn'."; continue }
  if ($current -ne $TeamsUpdatePolicyName) {
    Write-Information "Granting policy '$TeamsUpdatePolicyName' to $upn ..."
    if (-not $WhatIf) { Grant-CsTeamsUpdateManagementPolicy -Identity $upn -PolicyName $TeamsUpdatePolicyName | Out-Null }
  } else { Write-Information "OK: $upn already has policy '$TeamsUpdatePolicyName'." }
}

Write-Information "`n=== Lab 1: Creating Teams (Teams Rollout, Group_Afterwork_) ==="
# Teams Rollout owned by Alex; add pilot users as members
$team = $null
try { $team = Get-Team -DisplayName $TeamsRolloutTeamName -ErrorAction Stop } catch {}
if (-not $team) {
  Write-Information "Creating Team '$TeamsRolloutTeamName' ..."
  if (-not $WhatIf) { $team = New-Team -DisplayName $TeamsRolloutTeamName -Visibility Private -Description "Pilot project team for Teams rollout" -Owner $AlexUPN }
} else { Write-Information "OK: Team '$TeamsRolloutTeamName' exists." }
if ($team) {
  $cur = @(); try { $cur = (Get-TeamUser -GroupId $team.GroupId).User } catch {}
  foreach ($m in $PilotUsers) {
    if ($m -eq $AlexUPN) { continue }
    if ($cur -notcontains $m) {
      Write-Information "Adding $m to '$TeamsRolloutTeamName' ..."
      if (-not $WhatIf) { Add-TeamUser -GroupId $team.GroupId -User $m -Role Member }
    }
  }
}

# Group_Afterwork_ owned by Lynne; add subset
$team2 = $null
try { $team2 = Get-Team -DisplayName $AfterworkTeamName -ErrorAction Stop } catch {}
if (-not $team2) {
  Write-Information "Creating Team '$AfterworkTeamName' ..."
  if (-not $WhatIf) { $team2 = New-Team -DisplayName $AfterworkTeamName -Visibility Public -Description "Afterwork interest group created per Lab 1" -Owner $LynneUPN }
} else { Write-Information "OK: Team '$AfterworkTeamName' exists." }
if ($team2) {
  $cur2 = @(); try { $cur2 = (Get-TeamUser -GroupId $team2.GroupId).User } catch {}
  foreach ($m in @($AlexUPN,$DiegoUPN,$PattiUPN,$JoniUPN)) {
    if ($cur2 -notcontains $m) {
      Write-Information "Adding $m to '$AfterworkTeamName' ..."
      if (-not $WhatIf) { Add-TeamUser -GroupId $team2.GroupId -User $m -Role Member }
    }
  }
}

Write-Information "`nAll checks and Lab 1 automations complete (Least-privilege Graph + Teams)."
