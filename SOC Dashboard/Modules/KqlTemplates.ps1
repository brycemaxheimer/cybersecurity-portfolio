$kqlTemplates = [ordered]@{
    'Mega Query Framework rev3.0.0 (TA0001 / TA0004 / TA0009)' = @'
//--------------------Query Functionality Explanation--------------------\\
//                                                                       \\
// This query is designed to be a "Mega Query" that maintains multiple   \\
// functionalities in one, making querying a system by event types easier\\
//                                                                       \\
// You only NEED to interact with a few things at the start of the query \\
// to begin using it. The first is EventType (I will outline the         \\
// different types later), which sets what Windows Events you will focus \\
// on. It is possible to put multiple EventTypes in the EventType array  \\
// however dont go overboard due to the amount of data that may output.  \\
//                                                                       \\
// The other is the StartTime and EndTime variables for obvious reasons. \\
// The query WILL run without specifying a Computer or Account but it's  \\
// not recommended to do so. They are set as dynamic arrays so it's      \\
// possible to run the query searching for more than one User\System at a\\
// time if needed. Otherwise it's fully self-sufficient. Enjoy!          \\
//                                                                       \\
//--------------------Query Functionality Explanation--------------------\\
//-----------------------------------------------------------------------\\
//--------------------------Function Assignment--------------------------\\
let EventType       = dynamic(["TA0004"]);
//--------------------------Function Assignment--------------------------\\
//-----------------------------------------------------------------------\\
//--------------------------Variable Assignment--------------------------\\
let SpecifiedSystem = dynamic([]);
let ExcludedSystem  = dynamic([]);
let SpecifiedUser   = dynamic([]);
let ExcludedUser    = dynamic([]);
let MITR3Search     = dynamic([]);
let MITR3Exclusion  = dynamic([]);
let Output_Detail   = dynamic(["Summarized"]);  // Detailed to return ALL results, Summarized to return grouped results
let StartTime       = datetime(2026-01-21, 00:00:00);
let EndTime         = datetime(2026-01-21, 23:59:59);
//--------------------------Variable Assignment--------------------------\\
//-----------------------------------------------------------------------\\
//--------------------------Datatable Assignment-------------------------\\
let LogonStatus = materialize(datatable(Status:string,StatusLookup:string) 
[
    "0Xc000005e", "There are currently no logon servers available to service the logon request.",
    "0xc000006d", "Unknown user name or bad password.",
	"0xc0000064", "User logon with misspelled or bad user account.",
    "0xc000006a", "User logon with misspelled or bad password",
    "0Xc000006e", "Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication",
	"0xc0000234", "Account is locked out.",
	"0xc000015b", "User not granted the requested logon right/type",
	"0xc0000224", "User must change password at next logon.",
	"0xc0000193", "User logon with expired account.",
    "0xc000006f", "Account logon outside authorized hours.",
    "0xc0000070", "Account logon from unauthorized workstation.",
    "0xc0000071", "Account logon with expired password.",
    "0xc0000072", "Account logon to account disabled by administrator.",
    "0xc0000371", "The local account store does not contain secret material for the specified account.",
    "0Xc0000413", "The machine you are logging on to is protected by an authentication firewall.",
    "0Xc00000dc", "Indicates the Sam Server was in the wrong state to perform the desired operation.",
    "0x0",        "Generic Error."
]);
let AccessMaskAttr = materialize(datatable(AccessCode:string,AccessType:string) [
    "%%4416", "ReadData/ListDirectory/QueryKeyValue"
    , "%%4417", "WriteData/AddFile/SetKeyValue"
    , "%%4418", "AppendData/AddSubdirectory/CreatePipeInstance"
    , "%%4419", "ReadEA/EnumerateSub-Keys"
    , "%%4420", "WriteEA"
    , "%%4421", "Execute/Traverse"
    , "%%4422", "DeleteChild"
    , "%%4423", "ReadAttributes"
    , "%%4424", "WriteAttributes"
    , "%%1537", "DELETE"
    , "%%1538", "READ_CONTROL"
    , "%%1539", "WRITE_DAC"
    , "%%1540", "WRITE_OWNER"
    , "%%1541", "SYNCHRONIZE"
    , "%%1542", "ACCESS_SYS_SEC"
]);
let PrivilegeListDefinitions = materialize(datatable(PrivilegeCode:string,PrivilegeFunction:string) [
    "SeAssignPrimaryTokenPrivilege",     "Replace a process-level token"
    , "SeAuditPrivilege",                "Generate security audits"
    , "SeBackupPrivilege",               "Back up files and directories"
    , "SeChangeNotifyPrivilege",         "Bypass traverse checking"
    , "SeCreateGlobalPrivilege",         "Create global objects"
    , "SeCreatePagefilePrivilege",       "Create a pagefile"
    , "SeCreatePermanentPrivilege",      "Create permanent shared objects"
    , "SeCreateSymbolicLinkPrivilege",   "Create symbolic links"
    , "SeCreateTokenPrivilege",          "Create a token object"
    , "SeDebugPrivilege",                "Debug programs"
    , "SeEnableDelegationPrivilege",     "Enable computer and user accounts to be trusted for delegation"
    , "SeImpersonatePrivilege",          "Impersonate a client after authentication"
    , "SeIncreaseBasePriorityPrivilege", "Increase scheduling priority"
    , "SeIncreaseQuotaPrivilege",        "Adjust memory quotas for a process"
    , "SeIncreaseWorkingSetPrivilege",   "Increase a process working set"
    , "SeLoadDriverPrivilege",           "Load and unload device drivers"
    , "SeLockMemoryPrivilege",           "Lock pages in memory"
    , "SeMachineAccountPrivilege",       "Add workstations to domain"
    , "SeManageVolumePrivilege",         "Perform volume maintenance tasks"
    , "SeProfileSingleProcessPrivilege", "Profile single process"
    , "SeRelabelPrivilege",              "Modify an object label"
    , "SeRemoteShutdownPrivilege",       "Force shutdown from a remote system"
    , "SeRestorePrivilege",              "Restore files and directories"
    , "SeSecurityPrivilege",             "Manage auditing and security log"
    , "SeShutdownPrivilege",             "Shut down the system"
    , "SeSyncAgentPrivilege",            "Synchronize directory service data"
    , "SeSystemEnvironmentPrivilege",    "Modify firmware environment values"
    , "SeSystemProfilePrivilege",        "Profile system performance"
    , "SeSystemtimePrivilege",           "Change the system time"
    , "SeTakeOwnershipPrivilege",        "Take ownership of files or other objects"
    , "SeTcbPrivilege",                  "Act as part of the operating system"
    , "SeTimeZonePrivilege",             "Change the time zone"
    , "SeTrustedCredManAccessPrivilege", "Access Credential Manager as a trusted caller"
    , "SeUndockPrivilege",               "Remove computer from docking station"
    , "SeUnsolicitedInputPrivilege",     "Not applicable"
]);
let TA0001InitialAccess = materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string)
[
      4625 , "Microsoft-Windows-Security-Auditing", "Login denied due to account policy restrictions", "T1078.002", "Valid accounts"
	, 33205, "MSSQL", "Login failure from a single source with a disabled account", "T1078.002", "Valid accounts"
	, 4624 , "Microsoft-Windows-Security-Auditing", "Success login on OpenSSH server/RDP reconnaissance to multiple hosts", "T1078.002", "Valid accounts"
	, 4    , "Microsoft-Windows-Security-Kerberos", "Success login on OpenSSH server", "T1078.002", "Valid accounts"
	, 1149 , "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "RDP reconnaissance with valid credentials performed to multiple hosts", "T1078", "Valid accounts"
]);
let TA0004PrivilegeEscalation = materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string,Tactic:string) [
	4673, "Microsoft-Windows-Security-Auditing", "Exploitation for Privilege Escalation", "T1068", "Privilege SeMachineAccountPrivilege abuse", "TA0004-Privilege Escalation"
	, 4624, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Token Impersonation/Theft", "T1134.001", "Anonymous login", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Token Impersonation/Theft", "T1134.001", "Anonymous login", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)", "TA0004-Privilege Escalation"
	, 4648, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)", "TA0004-Privilege Escalation"
	, 4624, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via RunasCS", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via RunasCS", "TA0004-Privilege Escalation"
	, 4675, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account", "TA0004-Privilege Escalation"
	, 4766, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account", "TA0004-Privilege Escalation"
	, 4738, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account", "TA0004-Privilege Escalation"
	, 4717, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "New access rights granted to an account by a standard user", "TA0004-Privilege Escalation"
	, 4718, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "New access rights granted to an account by a standard user", "TA0004-Privilege Escalation"
	, 4704, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "User right granted to an account by a standard user", "TA0004-Privilege Escalation"
	, 5136, "Microsoft-Windows-Security-Auditing", "Domain Policy Modification-Group Policy Modification", "T1484.001", "Modification of a sensitive Group Policy", "TA0004-Privilege Escalation"
	, 4865, "Microsoft-Windows-Security-Auditing", "Domain or Tenant Policy Modification: Trust Modification", "T1484.002", "New external trust added", "TA0004-Privilege Escalation"
	, 4076, "Microsoft-Windows-Security-Auditing", "Domain or Tenant Policy Modification: Trust Modification", "T1484.002", "New external trust added", "TA0004-Privilege Escalation"
	, 7045, "Microsoft-Windows-Security-Auditing", "Create or Modify System Process-Windows Service", "T1543.003", "PSexec service installation detected", "TA0004-Privilege Escalation"
	, 4697, "Microsoft-Windows-Security-Auditing", "Create or Modify System Process-Windows Service", "T1543.003", "PSexec service installation detected", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "CMD executed by sticky key and detected via hash", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "CMD executed by sticky key and detected via hash", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key called CMD via command execution", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key called CMD via command execution", "TA0004-Privilege Escalation"
	, 4656, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key failed sethc replacement by CMD", "TA0004-Privilege Escalation"
	, 11,   "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key file created from CMD copy", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO command for registry change", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO command for registry change", "TA0004-Privilege Escalation"
	, 12,   "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO registry changed", "TA0004-Privilege Escalation"
	, 800,  "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added", "TA0004-Privilege Escalation"
	, 4103, "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added", "TA0004-Privilege Escalation"
	, 4104, "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "External printer mapped", "TA0004-Privilege Escalation"
	, 4648, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "External printer mapped", "TA0004-Privilege Escalation"
	, 6416, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "New external device added", "TA0004-Privilege Escalation"
	, 808,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed", "TA0004-Privilege Escalation"
	, 354,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed", "TA0004-Privilege Escalation"
	, 321,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "DLL Side-Loading", "T1574.002", "Spool process spawned a CMD shell",	"TA0004-Privilege Escalation"
    , 4688, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Spool process spawned a CMD shell", "TA0004-Privilege Escalation"
]);
let TA0009Collection = materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	  13  , "Microsoft-Windows-Sysmon", "RDP shadow session started (registry)", "T1125", "Video capture"
]);
let BaselineSecEvent = view() { SecurityEvent
| extend Timestamp = TimeGenerated
| where TimeGenerated between (StartTime .. EndTime)
| extend Computer = tostring(split(Computer,".")[0])
| where (array_length(SpecifiedSystem) == 0 or Computer in~ (SpecifiedSystem))
    and (array_length(ExcludedSystem) == 0 or not(Computer has_any (ExcludedSystem)))
| parse EventData with *'SubjectUserName">'SubjectUserName'</Data>'*
| parse EventData with *'TargetUserName">'TargetUserName'</Data>'*
| parse EventData with *'<Data Name="User">'User'</Data>'*
| extend UnifiedAccount = coalesce(SubjectUserName, TargetUserName,
    iff(SubjectAccount contains "\\", tostring(split(SubjectAccount, "\\")[1]), SubjectAccount),
    iff(Account contains "\\", tostring(split(Account, "\\")[1]), Account),
    iff(User contains "\\", tostring(split(User, "\\")[1]), User))
| extend UnifiedAccount = iff(isnotempty(Account), tostring(split(Account,"\\")[1]), UnifiedAccount)
| where (array_length(SpecifiedUser) == 0 or UnifiedAccount in~ (SpecifiedUser))
    and (array_length(ExcludedUser) == 0 or not(UnifiedAccount has_any (ExcludedUser)))};
let TA0001Events = materialize ( BaselineSecEvent
| where "TA0001" in~ (EventType)
| where EventID in (4625,4624) and EventSourceName contains "Microsoft-Windows-Security-Auditing"
     or EventID == 4 and EventSourceName contains "Microsoft-Windows-Security-Kerberos"
     or EventID == 1149 and (EventSourceName contains "Microsoft-Windows-TerminalServices-RemoteConnectionManager" and Channel has "Operational")
     or EventID == 33205 and EventSourceName has "MSSQL"
| extend Status = iff(isnotempty(SubStatus) or not(SubStatus contains "0x0"), SubStatus, Status)
| lookup kind=leftouter LogonStatus on Status
| lookup kind=leftouter TA0001InitialAccess on EventID, EventSourceName
| extend Better4624 = strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'   <Data Name="UtcTime">',TimeGenerated,'</Data>\n''   <Data Name="SubjectUser SID">',SubjectUserSid,'</Data>\n''   <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n'
'   <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n''   <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''   <Data Name="TargetUserSID">',TargetUserSid,'</Data>\n'
'   <Data Name="TargetUserName">',TargetUserName,'</Data>\n''   <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n''   <Data Name="TargetLogonID">',TargetLogonId,'</Data>\n'
'   <Data Name="LogonType">',LogonTypeName,'</Data>\n''   <Data Name="LogonProcess">',LogonProcessName,'</Data>\n''   <Data Name="AuthenticationPackage">',AuthenticationPackageName,'</Data>\n'
'   <Data Name="WorkstationName">',Computer,'</Data>\n''   <Data Name="LogonGuid">',LogonGuid,'</Data>\n''   <Data Name="TransmittedServices">',TransmittedServices,'</Data>\n'
'   <Data Name="LmPackageName">',LmPackageName,'</Data>\n''   <Data Name="ProcessId">',ProcessId,'</Data>\n''   <Data Name="ProcessName">',ProcessName,'</Data>\n'
'   <Data Name="IpAddress">',IpAddress,'</Data>\n''   <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend Better4625 = strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'   <Data Name="UtcTime">',TimeGenerated,'</Data>\n''   <Data Name="Keywords">',Keywords,'</Data>\n''   <Data Name="SubjectUserSID">',SubjectUserSid,'</Data>\n'
'   <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''   <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n''   <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n'
'   <Data Name="TargetUserSID">',TargetUserSid,'</Data>\n''   <Data Name="TargetUserName">',TargetUserName,'</Data>\n''   <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'   <Data Name="Status">',Status,'</Data>\n''   <Data Name="SubStatus">',SubStatus,'</Data>\n''   <Data Name="FailureReason">',FailureReason,'</Data>\n'
'   <Data Name="LogonType">',LogonTypeName,'</Data>\n''   <Data Name="LogonProcess">',LogonProcessName,'</Data>\n''   <Data Name="AuthenticationPackage">',AuthenticationPackageName,'</Data>\n'
'   <Data Name="WorkstationName">',WorkstationName,'</Data>\n''   <Data Name="LogonGuid">',LogonGuid,'</Data>\n''   <Data Name="LmPackageName">',LmPackageName,'</Data>\n'
'   <Data Name="ProcessId">',ProcessId,'</Data>\n''   <Data Name="ProcessName">',ProcessName,'</Data>\n''   <Data Name="IpAddress">',IpAddress,'</Data>\n'
'   <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend EventData = iff(EventID == 4624, Better4624,
                     iff(EventID == 4625, Better4625, EventData))
| extend StatusInformation4625 = iff(EventID == 4625, bag_pack("Status", Status, "StatusLookup", StatusLookup), dynamic([])),
         StatusInformation4624 = iff(EventID == 4624, bag_pack("LogonType", LogonType, "LogonProcess", LogonProcessName), dynamic([]))
| extend MITREAssociation = coalesce(strcat(TechniqueID, ": ", TechniqueName), "N/A"),
         AdditionalInformation = iff(EventID == 4625, StatusInformation4625,
                                 iff(EventID == 4624, StatusInformation4624, dynamic([])))
| project Timestamp=TimeGenerated, Computer, Activity, UnifiedAccount, MITREAssociation, AdditionalInformation, EventData);
let TA0004Events = materialize ( BaselineSecEvent
| where "TA0004" in~ (EventType)
| lookup kind=leftouter TA0004PrivilegeEscalation on EventID, EventSourceName
| where EventID in (4673,4624,4688,4648,4675,4766,4717,4738,4718,4704,5136,4865,4076,4697,4656,6416,808,354,321)
    and EventSourceName contains "Microsoft-Windows-Security-Auditing"
    or  EventID in (800) and EventSourceName contains "PowerShell"
    or  EventID in (7045) and EventSourceName contains "Service Control Manager"
    or  EventID in (1,11,12) and EventSourceName contains "Microsoft-Windows-Sysmon"
    or  EventID in (4103,4104) and EventSourceName contains "Microsoft-Windows-PowerShell"
| parse EventData with *'<Data Name="Hashes">'Hashes'</Data>'*
| parse EventData with *'<Data Name="Image">'FileCreatingProcess'</Data>'*
| parse EventData with *'<Data Name="TargetFilename">'File'</Data>'*
| parse EventData with *'<Data Name="CreationUtcTime">'FileCreationTime'</Data>'*
| parse EventData with *'<Data Name="User">'FileCreator'</Data>'*
| parse EventData with *'<Data Name="CommandLine">'CommandLine'</Data>'*
| parse EventData with *'<Data Name="ObjectType">'ObjType'</Data>'*
| parse EventData with *'<Data Name="ObjectName">'ObjName'</Data>'*
| parse EventData with *'<Data Name="AccessList">'AccessList'</Data>'*
| parse EventData with *'<Data Name="PrivilegeList">'PrivilegeName'</Data>'*
| parse EventData with *'<Data Name="ProcessName">'HandleCreatingProcess'</Data>'*
| extend PrivList = extract_all(@'(\w+)', tostring(PrivilegeName)),AccList = extract_all(@'(%%\d+)', tostring(AccessList))
| extend ParsedHashes = split(Hashes, ",")
| extend SHA256   = ParsedHashes[2], IMPHASH = ParsedHashes[3]
| extend HashInfo = 
    iff((isnotempty(SHA256)  and isnotempty(IMPHASH)), strcat(SHA256,", ",IMPHASH),
    iff((isnotempty(SHA256)  and isempty(IMPHASH)), SHA256,
    iff((isnotempty(IMPHASH) and isempty(SHA256)), IMPHASH, "N/A"))), ""
| extend Better4688 = 
    strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="ProcessId">',NewProcessId,'</Data>\n'
'  <Data Name="Image">',NewProcessName,'</Data>\n''  <Data Name="CommandLine">',CommandLine,'</Data>\n'
'  <Data Name="User">',TargetAccount,'</Data>\n''  <Data Name="LogonId">',TargetLogonId,'</Data>\n'
'  <Data Name="UserName">',TargetUserName,'</Data>\n''  <Data Name="ParentProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ParentImage">',ParentProcessName,'</Data>\n''  <Data Name="ParentUser">',SubjectAccount,'</Data>\n'
'  <Data Name="AccountType">',AccountType,'</Data>\n''</EventData>')
| extend Better4624 =
    strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="SubjectUser SID">',SubjectUserSid,'</Data>\n'
'  <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''  <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n'
'  <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''  <Data Name="TargetUserSID">',TargetUserSid,'</Data>\n'
'  <Data Name="TargetUserName">',TargetUserName,'</Data>\n''  <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'  <Data Name="TargetLogonID">',TargetLogonId,'</Data>\n''  <Data Name="LogonType">',LogonTypeName,'</Data>\n'
'  <Data Name="LogonProcess">',LogonProcessName,'</Data>\n''  <Data Name="AuthenticationPackage">',AuthenticationPackageName,'</Data>\n'
'  <Data Name="WorkstationName">',Computer,'</Data>\n''  <Data Name="LogonGuid">',LogonGuid,'</Data>\n'
'  <Data Name="LmPackageName">',LmPackageName,'</Data>\n''  <Data Name="ProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ProcessName">',ProcessName,'</Data>\n''  <Data Name="IpAddress">',IpAddress,'</Data>\n'
'  <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend Better4648 =
    strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="SubjectUserSID">',SubjectUserSid,'</Data>\n'
'  <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''  <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n'
'  <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''  <Data Name="LogonGuid">',LogonGuid,'</Data>\n'
'  <Data Name="TargetUserName">',TargetUserName,'</Data>\n''  <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'  <Data Name="TargetLogonGuid">',TargetLogonGuid,'</Data>\n''  <Data Name="TargetServerName">',TargetServerName,'</Data>\n'
'  <Data Name="TargetInfo">',TargetInfo,'</Data>\n''  <Data Name="ProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ProcessName">',ProcessName,'</Data>\n''  <Data Name="IpAddress">',IpAddress,'</Data>\n'
'  <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend EventData = iff(EventID == 4688, Better4688,
                     iff(EventID == 4624, Better4624,
                     iff(EventID == 4648, Better4648, EventData)))
| extend row_id=new_guid());
let MappedAccessTypes_table = TA0004Events
| where EventID == 4656 and array_length(AccList) > 0
| mv-expand AccList_item = AccList to typeof(string)
| join kind=leftouter AccessMaskAttr on $left.AccList_item == $right.AccessCode
| summarize MappedAccessTypes = make_set(AccessType) by row_id;
let MappedPrivilegeTypes_table = TA0004Events
| where EventID == 4656 and array_length(PrivList) > 0
| mv-expand PrivList_item = PrivList to typeof(string)
| join kind=leftouter PrivilegeListDefinitions on $left.PrivList_item == $right.PrivilegeCode
| summarize MappedPrivilegeTypes = make_set(PrivilegeFunction) by row_id;
let TA0004EventsFinal = materialize ( TA0004Events
| join kind=leftouter MappedAccessTypes_table on row_id
| join kind=leftouter MappedPrivilegeTypes_table on row_id
| extend StatusInformation4624 = iff(EventID == 4624,bag_pack("LogonType",LogonType,"LogonProcess",LogonProcessName),dynamic([])),
         StatusInformation11   = iff(EventID == 11,  bag_pack("New File", File,"File Creator",FileCreator,"Creating Process",
                                                     FileCreatingProcess,"Creation Time",FileCreationTime),dynamic([])),
         StatusInformation4688 = iff(EventID == 4688,bag_pack("Parent Process",ParentProcessName,"New Process",NewProcessName,
                                                     "Parent User",SubjectUserName),dynamic([])),
         StatusInformation4656 = iff(EventID == 4656,bag_pack("Parent Process",HandleCreatingProcess,"Object Type",ObjType,"Object Name",ObjName,
                                                     "Access List",AccList,"Access Type",MappedAccessTypes,"Privilege List",PrivList,
                                                     "Privilege Function",MappedPrivilegeTypes),dynamic([]))
| extend MITREAssociation = coalesce(strcat(TechniqueID,": ",TechniqueName, " | ",Description),"N/A"),
         AdditionalInformation = iff(EventID==1,HashInfo,
                                 iff(EventID==4624,StatusInformation4624,
                                 iff(EventID==4688,StatusInformation4688,
                                 iff(EventID==4656,StatusInformation4656,
                                 iff(EventID==11,StatusInformation11,dynamic([]))))))
| project Timestamp=TimeGenerated,Computer,UnifiedAccount,Activity,MITREAssociation,todynamic(AdditionalInformation),EventData);
let TA0009Events = materialize ( BaselineSecEvent
| where "TA0009" in~ (EventType)
| lookup kind=leftouter TA0009Collection on EventID, EventSourceName
| where EventID == 13 and EventSourceName contains "Microsoft-Windows-Sysmon"
| parse EventData with *'<Data Name="TargetObject">'RegPath'</Data>'*
| parse EventData with *'<Data Name="Details">'SetValue'</Data>'*
| parse EventData with *'<Data Name="Image">'Image'</Data>'*
| where RegPath contains @"Terminal Services\Shadow" and not(SetValue contains "DWORD (0x00000000)")
| extend StatusInformation13 = bag_pack("Initiating Process",Image,"Registry Object",RegPath,"Modified Value",SetValue)
| extend MITREAssociation = coalesce(strcat(TechniqueID,": ",TechniqueName, " | ",Description),"N/A"),
         AdditionalInformation = iff(EventID==13, StatusInformation13,dynamic([]))
| project Timestamp=TimeGenerated,Computer,UnifiedAccount,Activity,MITREAssociation,AdditionalInformation,EventData);
// --- Initial Output Branch ---
let FinalPreOutput = union TA0001Events,TA0004EventsFinal,TA0009Events
| project-reorder
    Timestamp,
    Computer,
    UnifiedAccount,
    Activity,
    MITREAssociation,
    AdditionalInformation,
    EventData;
// --- Variable Assignment to Determine Detail ---
let outputMode = iif(array_length(Output_Detail) == 0, "Summarized", tostring(Output_Detail[0]));
// --- Summarized Output Branch ---
let SummarizedOutput = FinalPreOutput
| where outputMode == "Summarized"
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    EventData = make_set_if(EventData, isnotempty(EventData), 200),
    AdditionalInformation = make_set_if(AdditionalInformation, isnotempty(AdditionalInformation))
    by
    Computer,
    UnifiedAccount,
    Activity,
    MITREAssociation
| extend Timestamp = iff(FirstSeen == LastSeen, todynamic(tostring(FirstSeen)), pack("FirstSeen ", FirstSeen, "LastSeen ", LastSeen))
| project-away FirstSeen, LastSeen
| project-reorder
    Timestamp,
    Computer,
    UnifiedAccount,
    Activity,
    MITREAssociation,
    AdditionalInformation,
    EventData;
// --- Detailed Output Branch ---
let DetailedOutput = FinalPreOutput
| where outputMode == "Detailed"
| extend
    FirstSeen = Timestamp,
    LastSeen = Timestamp,
    EventData = pack_array(EventData),
    AdditionalInformation = pack_array(AdditionalInformation)
| extend Timestamp = iff(FirstSeen == LastSeen, todynamic(tostring(FirstSeen)), pack("FirstSeen ", FirstSeen, "LastSeen ", LastSeen))
| project-away FirstSeen, LastSeen
| project-reorder
    Timestamp,
    Computer,
    UnifiedAccount,
    Activity,
    MITREAssociation,
    AdditionalInformation,
    EventData;
union SummarizedOutput, DetailedOutput
'@
    'Mega Query Framework rev3.0.1 InProg (adds TA0002)' = @'
//--------------------Query Functionality Explanation--------------------\\
//                                                                       \\
// This query is designed to be a "Mega Query" that maintains multiple   \\
// functionalities in one, making querying a system by event types easier\\
//                                                                       \\
// You only NEED to interact with a few things at the start of the query \\
// to begin using it. The first is EventType (I will outline the         \\
// different types later), which sets what Windows Events you will focus \\
// on. It is possible to put multiple EventTypes in the EventType array  \\
// however dont go overboard due to the amount of data that may output.  \\
//                                                                       \\
// The other is the StartTime and EndTime variables for obvious reasons. \\
// The query WILL run without specifying a Computer or Account but it's  \\
// not recommended to do so. They are set as dynamic arrays so it's      \\
// possible to run the query searching for more than one User\System at a\\
// time if needed. Otherwise it's fully self-sufficient. Enjoy!          \\
//                                                                       \\
//--------------------Query Functionality Explanation--------------------\\
//-----------------------------------------------------------------------\\
//--------------------------Function Assignment--------------------------\\
let EventType       = dynamic(["TA0004"]);
let Output_Detail   = dynamic(["Summarized"]);
//--------------------------Function Assignment--------------------------\\
//-----------------------------------------------------------------------\\
//--------------------------Variable Assignment--------------------------\\
let SpecifiedSystem = dynamic([]); let ExcludedSystem  = dynamic([]);
let SpecifiedUser   = dynamic([]); let ExcludedUser    = dynamic([]);
let MITR3Search     = dynamic([]); let MITR3Exclusion  = dynamic([]);
let StartTime=datetime(2026-01-21, 00:00:00);
let EndTime  =datetime(2026-01-21, 23:59:59);
//--------------------------Variable Assignment--------------------------\\
//-------------NOTHING BEYOND THIS POINT NEEDS TO BE MODIFIED------------\\
//--------------------------Datatable Assignment-------------------------\\
let LogonStatus=materialize(datatable(Status:string,StatusLookup:string) [
    "0Xc000005e", "There are currently no logon servers available to service the logon request."
    , "0xc000006d", "Unknown user name or bad password."
	, "0xc0000064", "User logon with misspelled or bad user account."
    , "0xc000006a", "User logon with misspelled or bad password"
    , "0Xc000006e", "Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication"
	, "0xc0000234", "Account is locked out."
	, "0xc000015b", "User not granted the requested logon right/type"
	, "0xc0000224", "User must change password at next logon."
	, "0xc0000193", "User logon with expired account."
    , "0xc000006f", "Account logon outside authorized hours."
    , "0xc0000070", "Account logon from unauthorized workstation."
    , "0xc0000071", "Account logon with expired password."
    , "0xc0000072", "Account logon to account disabled by administrator."
    , "0xc0000371", "The local account store does not contain secret material for the specified account."
    , "0Xc0000413", "The machine you are logging on to is protected by an authentication firewall."
    , "0Xc00000dc", "Indicates the Sam Server was in the wrong state to perform the desired operation."
    , "0x0",        "Generic Error."
]);
let AccessMaskAttr=materialize(datatable(AccessCode:string,AccessType:string) [
    "%%4416", "ReadData/ListDirectory/QueryKeyValue"
    , "%%4417", "WriteData/AddFile/SetKeyValue"
    , "%%4418", "AppendData/AddSubdirectory/CreatePipeInstance"
    , "%%4419", "ReadEA/EnumerateSub-Keys"
    , "%%4420", "WriteEA"
    , "%%4421", "Execute/Traverse"
    , "%%4422", "DeleteChild"
    , "%%4423", "ReadAttributes"
    , "%%4424", "WriteAttributes"
    , "%%1537", "DELETE"
    , "%%1538", "READ_CONTROL"
    , "%%1539", "WRITE_DAC"
    , "%%1540", "WRITE_OWNER"
    , "%%1541", "SYNCHRONIZE"
    , "%%1542", "ACCESS_SYS_SEC"
]);
let PrivilegeListDefinitions=materialize(datatable(PrivilegeCode:string,PrivilegeFunction:string) [
    "SeAssignPrimaryTokenPrivilege",     "Replace a process-level token"
    , "SeAuditPrivilege",                "Generate security audits"
    , "SeBackupPrivilege",               "Back up files and directories"
    , "SeChangeNotifyPrivilege",         "Bypass traverse checking"
    , "SeCreateGlobalPrivilege",         "Create global objects"
    , "SeCreatePagefilePrivilege",       "Create a pagefile"
    , "SeCreatePermanentPrivilege",      "Create permanent shared objects"
    , "SeCreateSymbolicLinkPrivilege",   "Create symbolic links"
    , "SeCreateTokenPrivilege",          "Create a token object"
    , "SeDebugPrivilege",                "Debug programs"
    , "SeEnableDelegationPrivilege",     "Enable computer and user accounts to be trusted for delegation"
    , "SeImpersonatePrivilege",          "Impersonate a client after authentication"
    , "SeIncreaseBasePriorityPrivilege", "Increase scheduling priority"
    , "SeIncreaseQuotaPrivilege",        "Adjust memory quotas for a process"
    , "SeIncreaseWorkingSetPrivilege",   "Increase a process working set"
    , "SeLoadDriverPrivilege",           "Load and unload device drivers"
    , "SeLockMemoryPrivilege",           "Lock pages in memory"
    , "SeMachineAccountPrivilege",       "Add workstations to domain"
    , "SeManageVolumePrivilege",         "Perform volume maintenance tasks"
    , "SeProfileSingleProcessPrivilege", "Profile single process"
    , "SeRelabelPrivilege",              "Modify an object label"
    , "SeRemoteShutdownPrivilege",       "Force shutdown from a remote system"
    , "SeRestorePrivilege",              "Restore files and directories"
    , "SeSecurityPrivilege",             "Manage auditing and security log"
    , "SeShutdownPrivilege",             "Shut down the system"
    , "SeSyncAgentPrivilege",            "Synchronize directory service data"
    , "SeSystemEnvironmentPrivilege",    "Modify firmware environment values"
    , "SeSystemProfilePrivilege",        "Profile system performance"
    , "SeSystemtimePrivilege",           "Change the system time"
    , "SeTakeOwnershipPrivilege",        "Take ownership of files or other objects"
    , "SeTcbPrivilege",                  "Act as part of the operating system"
    , "SeTimeZonePrivilege",             "Change the time zone"
    , "SeTrustedCredManAccessPrivilege", "Access Credential Manager as a trusted caller"
    , "SeUndockPrivilege",               "Remove computer from docking station"
    , "SeUnsolicitedInputPrivilege",     "Not applicable"
]);
let TA0001InitialAccess=materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
    4625 , "Microsoft-Windows-Security-Auditing", "Login denied due to account policy restrictions", "T1078.002", "Valid accounts"
	, 33205, "MSSQL", "Login failure from a single source with a disabled account", "T1078.002", "Valid accounts"
	, 4624 , "Microsoft-Windows-Security-Auditing", "Success login on OpenSSH server/RDP reconnaissance to multiple hosts", "T1078.002", "Valid accounts"
	, 4    , "Microsoft-Windows-Security-Kerberos", "Success login on OpenSSH server", "T1078.002", "Valid accounts"
	, 1149 , "Microsoft-Windows-TerminalServices-RemoteConnectionManager", "RDP reconnaissance with valid credentials performed to multiple hosts", "T1078", "Valid accounts"
]);
let TA0002Execution=materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	4688, "Microsoft-Windows-Security-Auditing", "Impacket WMIexec process execution", "T1047", "Windows Management Instrumentation"
	, 1   ,	"Microsoft-Windows-Sysmon", "Impacket WMIexec process execution", "T1047", "Windows Management Instrumentation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Interactive shell triggered by scheduled task (at, deprecated)", "T1053.005", "Scheduled Task"
	, 1   ,	"Microsoft-Windows-Sysmon", "Interactive shell triggered by scheduled task (at, deprecated)", "T1053.005", "Scheduled Task"
	, 4688, "Microsoft-Windows-Security-Auditing", "Persistent scheduled task with SYSTEM privileges creation", "T1053.005", "Scheduled Task"
	, 1   , "Microsoft-Windows-Sysmon", "Persistent scheduled task with SYSTEM privileges creation", "T1053.005", "Scheduled Task"
	, 5145, "Microsoft-Windows-Security-Auditing", "Remote schedule task creation via named pipes", "T1053.005", "Scheduled Task"
	, 4698, "Microsoft-Windows-Security-Auditing", "Schedule task created with suspicious arguments", "T1053.005", "Scheduled Task"
	, 4698, "Microsoft-Windows-Security-Auditing", "Schedule task fastly created and deleted", "T1053.005", "Scheduled Task"
	, 4699, "Microsoft-Windows-Security-Auditing", "Schedule task fastly created and deleted", "T1053.005", "Scheduled Task"
	, 4688, "Microsoft-Windows-Security-Auditing", "Scheduled task creation", "T1053.005", "Scheduled Task"
	, 1   ,	"Microsoft-Windows-Sysmon", "Scheduled task creation", "T1053.005", "Scheduled Task"
	, 800 , "PowerShell", "Encoded PowerShell payload deployed", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4103, "Microsoft-Windows-PowerShell", "Encoded PowerShell payload deployed", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4104, "Microsoft-Windows-PowerShell", "Encoded PowerShell payload deployed", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 800 , "Microsoft-Windows-Security-Auditing", "Interactive PipeShell over SMB named pipe", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4103, "Microsoft-Windows-PowerShell", "Interactive PipeShell over SMB named pipe", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4104, "Microsoft-Windows-PowerShell", "Interactive PipeShell over SMB named pipe", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 800 , "PowerShell", "Payload downloaded via PowerShell", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4103, "Microsoft-Windows-PowerShell", "Payload downloaded via PowerShell", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4104, "Microsoft-Windows-PowerShell", "Payload downloaded via PowerShell", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4688, "Microsoft-Windows-Security-Auditing", "Encoded PowerShell payload deployed via process execution", "T1059.003", "Windows Command Shell"
	, 1   ,	"Microsoft-Windows-Sysmon", "Encoded PowerShell payload deployed via process execution", "T1059.003", "Windows Command Shell"
	, 4688, "Microsoft-Windows-Security-Auditing", "SQL Server payload injectection for reverse shell (MSF)", "T1059.003", "Windows Command Shell"
	, 1   ,	"Microsoft-Windows-Sysmon", "SQL Server payload injectection for reverse shell (MSF)", "T1059.003", "Windows Command Shell"
	, 4688, "Microsoft-Windows-Security-Auditing", "Edge abuse for payload download via console", "T1204", "User execution"
	, 1   ,	"Microsoft-Windows-Sysmon", "Edge abuse for payload download via console", "T1204", "User execution"
	, 4688, "Microsoft-Windows-Security-Auditing", "Edge/Chrome headless feature abuse for payload download", "T1204", "User execution"
	, 1   , "Microsoft-Windows-Sysmon", "Edge/Chrome headless feature abuse for payload download", "T1204", "User execution"
	, 4688, "Microsoft-Windows-Security-Auditing", "PSexec installation detected", "T1569.002", "Service Execution"
	, 1   , "Microsoft-Windows-Sysmon", "PSexec installation detected", "T1569.002", "Service Execution"
	, 7000, "Service Control Manager", "Service massive failures (native)", "T1569.002", "Service Execution"
	, 7009, "Service Control Manager", "Service massive failures (native)", "T1569.002", "Service Execution"
	, 7045, "Service Control Manager", "Service massive installation (native)", "T1569.002", "Service Execution"
	, 4697, "Microsoft-Windows-Security-Auditing", "Service massive installation (native)", "T1569.002", "Service Execution"
	, 5145, "Microsoft-Windows-Security-Auditing", "Service massive remote creation via named pipes (native)", "T1569.002", "Service Execution"
]);
let TA0004PrivilegeEscalation=materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	4673, "Microsoft-Windows-Security-Auditing", "Exploitation for Privilege Escalation", "T1068", "Privilege SeMachineAccountPrivilege abuse"
	, 4624, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Token Impersonation/Theft", "T1134.001", "Anonymous login"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Token Impersonation/Theft", "T1134.001", "Anonymous login"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)"
	, 4648, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)"
	, 4624, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)"
	, 1,    "Microsoft-Windows-Sysmon", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via RunasCS"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via RunasCS"
	, 4675, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account"
	, 4766, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account"
	, 4738, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account"
	, 4717, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "New access rights granted to an account by a standard user"
	, 4718, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "New access rights granted to an account by a standard user"
	, 4704, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "User right granted to an account by a standard user"
	, 5136, "Microsoft-Windows-Security-Auditing", "Domain Policy Modification-Group Policy Modification", "T1484.001", "Modification of a sensitive Group Policy"
	, 4865, "Microsoft-Windows-Security-Auditing", "Domain or Tenant Policy Modification: Trust Modification", "T1484.002", "New external trust added"
	, 4076, "Microsoft-Windows-Security-Auditing", "Domain or Tenant Policy Modification: Trust Modification", "T1484.002", "New external trust added"
	, 7045, "Microsoft-Windows-Security-Auditing", "Create or Modify System Process-Windows Service", "T1543.003", "PSexec service installation detected"
	, 4697, "Microsoft-Windows-Security-Auditing", "Create or Modify System Process-Windows Service", "T1543.003", "PSexec service installation detected"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "CMD executed by sticky key and detected via hash"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "CMD executed by sticky key and detected via hash"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key called CMD via command execution"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key called CMD via command execution"
	, 4656, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key failed sethc replacement by CMD"
	, 11,   "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key file created from CMD copy"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO command for registry change"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO command for registry change"
	, 12,   "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO registry changed"
	, 800,  "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added"
	, 4103, "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added"
	, 4104, "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added"
	, 4688, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "External printer mapped"
	, 4648, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "External printer mapped"
	, 6416, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "New external device added"
	, 808,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed"
	, 354,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed"
	, 321,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed"
	, 1,    "Microsoft-Windows-Sysmon", "DLL Side-Loading", "T1574.002", "Spool process spawned a CMD shell"
    , 4688, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Spool process spawned a CMD shell"
]);
let TA0009Collection=materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	  13  , "Microsoft-Windows-Sysmon", "RDP shadow session started (registry)", "T1125", "Video capture"
]);
let BaselineSecEvent=view(){SecurityEvent
| extend Timestamp=TimeGenerated
| where TimeGenerated between(StartTime..EndTime)
| extend Computer=tostring(split(Computer,".")[0])
| where (array_length(SpecifiedSystem)==0 or Computer in~(SpecifiedSystem))
    and (array_length(ExcludedSystem)==0 or not(Computer has_any(ExcludedSystem)))
| parse EventData with *'SubjectUserName">'SubjectUserName'</Data>'*
| parse EventData with *'TargetUserName">'TargetUserName'</Data>'*
| parse EventData with *'<Data Name="User">'User'</Data>'*
| extend UnifiedAccount=coalesce(SubjectUserName,TargetUserName,
    iff(SubjectAccount contains "\\",tostring(split(SubjectAccount,"\\")[1]),SubjectAccount),
    iff(Account contains "\\",tostring(split(Account, "\\")[1]),Account),
    iff(User contains "\\",tostring(split(User, "\\")[1]),User))
| extend UnifiedAccount=iff(isnotempty(Account),tostring(split(Account,"\\")[1]),UnifiedAccount)
| where (array_length(SpecifiedUser)==0 or UnifiedAccount in~(SpecifiedUser))
    and (array_length(ExcludedUser)==0 or not(UnifiedAccount has_any(ExcludedUser)))};
//-- Initial Access Subquery Start --
let TA0001Events=materialize(BaselineSecEvent
| where "TA0001" in~(EventType)
| where EventID in(4625,4624) and EventSourceName contains "Microsoft-Windows-Security-Auditing"
     or EventID==4 and EventSourceName contains "Microsoft-Windows-Security-Kerberos"
     or EventID==1149 and (EventSourceName contains "Microsoft-Windows-TerminalServices-RemoteConnectionManager" and Channel has "Operational")
     or EventID==33205 and EventSourceName has "MSSQL"
| extend Status=iff(isnotempty(SubStatus) or not(SubStatus contains "0x0"),SubStatus,Status)
| lookup kind=leftouter LogonStatus on Status
| lookup kind=leftouter TA0001InitialAccess on EventID,EventSourceName
| extend Better4624=strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'   <Data Name="UtcTime">',TimeGenerated,'</Data>\n''   <Data Name="SubjectUser SID">',SubjectUserSid,'</Data>\n''   <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n'
'   <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n''   <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''   <Data Name="TargetUserSID">',TargetUserSid,'</Data>\n'
'   <Data Name="TargetUserName">',TargetUserName,'</Data>\n''   <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n''   <Data Name="TargetLogonID">',TargetLogonId,'</Data>\n'
'   <Data Name="LogonType">',LogonTypeName,'</Data>\n''   <Data Name="LogonProcess">',LogonProcessName,'</Data>\n''   <Data Name="AuthenticationPackage">',AuthenticationPackageName,'</Data>\n'
'   <Data Name="WorkstationName">',Computer,'</Data>\n''   <Data Name="LogonGuid">',LogonGuid,'</Data>\n''   <Data Name="TransmittedServices">',TransmittedServices,'</Data>\n'
'   <Data Name="LmPackageName">',LmPackageName,'</Data>\n''   <Data Name="ProcessId">',ProcessId,'</Data>\n''   <Data Name="ProcessName">',ProcessName,'</Data>\n'
'   <Data Name="IpAddress">',IpAddress,'</Data>\n''   <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend Better4625=strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'   <Data Name="UtcTime">',TimeGenerated,'</Data>\n''   <Data Name="Keywords">',Keywords,'</Data>\n''   <Data Name="SubjectUserSID">',SubjectUserSid,'</Data>\n'
'   <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''   <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n''   <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n'
'   <Data Name="TargetUserSID">',TargetUserSid,'</Data>\n''   <Data Name="TargetUserName">',TargetUserName,'</Data>\n''   <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'   <Data Name="Status">',Status,'</Data>\n''   <Data Name="SubStatus">',SubStatus,'</Data>\n''   <Data Name="FailureReason">',FailureReason,'</Data>\n'
'   <Data Name="LogonType">',LogonTypeName,'</Data>\n''   <Data Name="LogonProcess">',LogonProcessName,'</Data>\n''   <Data Name="AuthenticationPackage">',AuthenticationPackageName,'</Data>\n'
'   <Data Name="WorkstationName">',WorkstationName,'</Data>\n''   <Data Name="LogonGuid">',LogonGuid,'</Data>\n''   <Data Name="LmPackageName">',LmPackageName,'</Data>\n'
'   <Data Name="ProcessId">',ProcessId,'</Data>\n''   <Data Name="ProcessName">',ProcessName,'</Data>\n''   <Data Name="IpAddress">',IpAddress,'</Data>\n'
'   <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend EventData=iff(EventID==4624,Better4624,iff(EventID==4625,Better4625,EventData))
| extend StatusInformation4625=iff(EventID==4625,bag_pack("Status",Status,"StatusLookup",StatusLookup),dynamic([])),
         StatusInformation4624=iff(EventID==4624,bag_pack("LogonType",LogonType,"LogonProcess",LogonProcessName),dynamic([]))
| extend MITREAssociation=coalesce(strcat(TechniqueID,": ",TechniqueName),"N/A"),
         AdditionalInformation=iff(EventID==4625,StatusInformation4625,iff(EventID==4624,StatusInformation4624,dynamic([])))
| project Timestamp=TimeGenerated,Computer,Activity,UnifiedAccount,MITREAssociation,AdditionalInformation,EventData);
//-- Initial Access Subquery Stop --
//-- Privilege Escalation Subquery Start --
let TA0004Events=materialize(BaselineSecEvent
| where "TA0004" in~(EventType)
| lookup kind=leftouter TA0004PrivilegeEscalation on EventID,EventSourceName
| where EventID in(4673,4624,4688,4648,4675,4766,4717,4738,4718,4704,5136,4865,4076,4697,4656,6416,808,354,321)
    and EventSourceName contains "Microsoft-Windows-Security-Auditing"
    or  EventID in(800) and EventSourceName contains "PowerShell"
    or  EventID in(7045) and EventSourceName contains "Service Control Manager"
    or  EventID in(1,11,12) and EventSourceName contains "Microsoft-Windows-Sysmon"
    or  EventID in(4103,4104) and EventSourceName contains "Microsoft-Windows-PowerShell"
| parse EventData with *'<Data Name="Hashes">'Hashes'</Data>'*
| parse EventData with *'<Data Name="Image">'FileCreatingProcess'</Data>'*
| parse EventData with *'<Data Name="TargetFilename">'File'</Data>'*
| parse EventData with *'<Data Name="CreationUtcTime">'FileCreationTime'</Data>'*
| parse EventData with *'<Data Name="User">'FileCreator'</Data>'*
| parse EventData with *'<Data Name="CommandLine">'CommandLine'</Data>'*
| parse EventData with *'<Data Name="ObjectType">'ObjType'</Data>'*
| parse EventData with *'<Data Name="ObjectName">'ObjName'</Data>'*
| parse EventData with *'<Data Name="AccessList">'AccessList'</Data>'*
| parse EventData with *'<Data Name="PrivilegeList">'PrivilegeName'</Data>'*
| parse EventData with *'<Data Name="ProcessName">'HandleCreatingProcess'</Data>'*
| extend PrivList=extract_all(@'(\w+)',tostring(PrivilegeName)),AccList=extract_all(@'(%%\d+)',tostring(AccessList))
| extend ParsedHashes=split(Hashes,",")
| extend SHA256=ParsedHashes[2],IMPHASH=ParsedHashes[3]
| extend HashInfo=iff((isnotempty(SHA256) and isnotempty(IMPHASH)),strcat(SHA256,", ",IMPHASH)
    ,iff((isnotempty(SHA256) and isempty(IMPHASH)),SHA256,iff((isnotempty(IMPHASH) and isempty(SHA256)),IMPHASH,"N/A"))),""
| extend Better4688=strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="ProcessId">',NewProcessId,'</Data>\n'
'  <Data Name="Image">',NewProcessName,'</Data>\n''  <Data Name="CommandLine">',CommandLine,'</Data>\n'
'  <Data Name="User">',TargetAccount,'</Data>\n''  <Data Name="LogonId">',TargetLogonId,'</Data>\n'
'  <Data Name="UserName">',TargetUserName,'</Data>\n''  <Data Name="ParentProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ParentImage">',ParentProcessName,'</Data>\n''  <Data Name="ParentUser">',SubjectAccount,'</Data>\n'
'  <Data Name="AccountType">',AccountType,'</Data>\n''</EventData>')
| extend Better4624=strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="SubjectUser SID">',SubjectUserSid,'</Data>\n'
'  <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''  <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n'
'  <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''  <Data Name="TargetUserSID">',TargetUserSid,'</Data>\n'
'  <Data Name="TargetUserName">',TargetUserName,'</Data>\n''  <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'  <Data Name="TargetLogonID">',TargetLogonId,'</Data>\n''  <Data Name="LogonType">',LogonTypeName,'</Data>\n'
'  <Data Name="LogonProcess">',LogonProcessName,'</Data>\n''  <Data Name="AuthenticationPackage">',AuthenticationPackageName,'</Data>\n'
'  <Data Name="WorkstationName">',Computer,'</Data>\n''  <Data Name="LogonGuid">',LogonGuid,'</Data>\n'
'  <Data Name="LmPackageName">',LmPackageName,'</Data>\n''  <Data Name="ProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ProcessName">',ProcessName,'</Data>\n''  <Data Name="IpAddress">',IpAddress,'</Data>\n'
'  <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend Better4648=strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="SubjectUserSID">',SubjectUserSid,'</Data>\n'
'  <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''  <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n'
'  <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''  <Data Name="LogonGuid">',LogonGuid,'</Data>\n'
'  <Data Name="TargetUserName">',TargetUserName,'</Data>\n''  <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'  <Data Name="TargetLogonGuid">',TargetLogonGuid,'</Data>\n''  <Data Name="TargetServerName">',TargetServerName,'</Data>\n'
'  <Data Name="TargetInfo">',TargetInfo,'</Data>\n''  <Data Name="ProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ProcessName">',ProcessName,'</Data>\n''  <Data Name="IpAddress">',IpAddress,'</Data>\n'
'  <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend EventData=iff(EventID==4688,Better4688,iff(EventID==4624,Better4624,iff(EventID==4648,Better4648,EventData)))
| extend row_id=new_guid());
//-- PrivEsc Sub-subquery Start --
    let MappedAccessTypes_table=TA0004Events
    | where EventID==4656 and array_length(AccList)>0
    | mv-expand AccList_item=AccList to typeof(string)
    | join kind=leftouter AccessMaskAttr on $left.AccList_item==$right.AccessCode
    | summarize MappedAccessTypes=make_set(AccessType) by row_id;
    let MappedPrivilegeTypes_table=TA0004Events
    | where EventID==4656 and array_length(PrivList)>0
    | mv-expand PrivList_item=PrivList to typeof(string)
    | join kind=leftouter PrivilegeListDefinitions on $left.PrivList_item==$right.PrivilegeCode
    | summarize MappedPrivilegeTypes=make_set(PrivilegeFunction) by row_id;
//-- PrivEsc Sub-subquery Stop --
let TA0004EventsFinal=materialize(TA0004Events
| join kind=leftouter MappedAccessTypes_table on row_id
| join kind=leftouter MappedPrivilegeTypes_table on row_id
| extend StatusInformation4624=iff(EventID==4624,bag_pack("LogonType",LogonType,"LogonProcess",LogonProcessName),dynamic([])),
         StatusInformation11=iff(EventID==11,bag_pack("New File", File,"File Creator",FileCreator,"Creating Process"
         ,FileCreatingProcess,"Creation Time",FileCreationTime),dynamic([])),
         StatusInformation4688=iff(EventID==4688,bag_pack("Parent Process",ParentProcessName,"New Process",NewProcessName
         ,"Parent User",SubjectUserName),dynamic([])),
         StatusInformation4656=iff(EventID==4656,bag_pack("Parent Process",HandleCreatingProcess,"Object Type",ObjType,"Object Name",ObjName
         ,"Access List",AccList,"Access Type",MappedAccessTypes,"Privilege List",PrivList,"Privilege Function",MappedPrivilegeTypes),dynamic([]))
| extend MITREAssociation=coalesce(strcat(TechniqueID,": ",TechniqueName," | ",Description),"N/A"),
         AdditionalInformation=iff(EventID==1,HashInfo,iff(EventID==4624,StatusInformation4624,iff(EventID==4688,StatusInformation4688
                              ,iff(EventID==4656,StatusInformation4656,iff(EventID==11,StatusInformation11,dynamic([]))))))
| project Timestamp=TimeGenerated,Computer,UnifiedAccount,Activity,MITREAssociation,todynamic(AdditionalInformation),EventData);
//-- Privilege Escalation Subquery Stop --
//-- Collection Subquery Start --
let TA0009Events=materialize(BaselineSecEvent
| where "TA0009" in~(EventType)
| lookup kind=leftouter TA0009Collection on EventID,EventSourceName
| where EventID==13 and EventSourceName contains "Microsoft-Windows-Sysmon"
| parse EventData with *'<Data Name="TargetObject">'RegPath'</Data>'*
| parse EventData with *'<Data Name="Details">'SetValue'</Data>'*
| parse EventData with *'<Data Name="Image">'Image'</Data>'*
| where RegPath contains @"Terminal Services\Shadow" and not(SetValue contains "DWORD (0x00000000)")
| extend StatusInformation13=bag_pack("Initiating Process",Image,"Registry Object",RegPath,"Modified Value",SetValue)
| extend MITREAssociation=coalesce(strcat(TechniqueID,": ",TechniqueName," | ",Description),"N/A"),
         AdditionalInformation=iff(EventID==13,StatusInformation13,dynamic([]))
| project Timestamp=TimeGenerated,Computer,UnifiedAccount,Activity,MITREAssociation,AdditionalInformation,EventData);
//-- Collection Subquery Stop --
//-- Output Formatting/Detail Subquery Start --
let FinalPreOutput=union TA0001Events,TA0004EventsFinal,TA0009Events
| project-reorder Timestamp,Computer,UnifiedAccount,Activity,MITREAssociation,AdditionalInformation,EventData;
let outputMode=iif(array_length(Output_Detail)==0,"Summarized",tostring(Output_Detail[0]));
let SummarizedOutput=FinalPreOutput
| where outputMode=="Summarized"
| summarize FirstSeen=min(Timestamp),LastSeen=max(Timestamp),EventData=make_set_if(EventData,isnotempty(EventData),200)
           ,AdditionalInformation=make_set_if(AdditionalInformation,isnotempty(AdditionalInformation))
         by Computer,UnifiedAccount,Activity,MITREAssociation
| extend Timestamp=iff(FirstSeen==LastSeen,todynamic(tostring(FirstSeen)),pack("FirstSeen ",FirstSeen,"LastSeen ",LastSeen))
| project-away FirstSeen,LastSeen
| project-reorder Timestamp,Computer,UnifiedAccount,Activity,MITREAssociation,AdditionalInformation,EventData;
let DetailedOutput=FinalPreOutput
| where outputMode=="Detailed"
| extend FirstSeen=Timestamp,LastSeen=Timestamp,EventData=pack_array(EventData),AdditionalInformation=pack_array(AdditionalInformation)
| extend Timestamp=iff(FirstSeen==LastSeen,todynamic(tostring(FirstSeen)),pack("FirstSeen ",FirstSeen,"LastSeen ",LastSeen))
| project-away FirstSeen,LastSeen
| project-reorder Timestamp,Computer,UnifiedAccount,Activity,MITREAssociation,AdditionalInformation,EventData;
//-- Output Formatting/Detail Subquery Stop --
union SummarizedOutput,DetailedOutput
'@
    'Subquery: Execution (TA0002) - partial filtering' = @'
let SpecifiedSystem = dynamic([]); let ExcludedSystem  = dynamic([]);
let SpecifiedUser   = dynamic([]); let ExcludedUser    = dynamic([]);
let MITR3Search     = dynamic([]); let MITR3Exclusion  = dynamic([]);
let Output_Detail   = dynamic([]);
let StartTime       = datetime(2026-01-31, 00:00:00);
let EndTime         = datetime(2026-02-01, 23:59:59);
let TA0002Execution=materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	4688, "Microsoft-Windows-Security-Auditing", "Impacket WMIexec process execution", "T1047", "Windows Management Instrumentation"
	, 1   ,	"Microsoft-Windows-Sysmon", "Impacket WMIexec process execution", "T1047", "Windows Management Instrumentation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Interactive shell triggered by scheduled task (at, deprecated)", "T1053.005", "Scheduled Task"
	, 1   ,	"Microsoft-Windows-Sysmon", "Interactive shell triggered by scheduled task (at, deprecated)", "T1053.005", "Scheduled Task"
	, 4688, "Microsoft-Windows-Security-Auditing", "Persistent scheduled task with SYSTEM privileges creation", "T1053.005", "Scheduled Task"
	, 1   , "Microsoft-Windows-Sysmon", "Persistent scheduled task with SYSTEM privileges creation", "T1053.005", "Scheduled Task"
	, 5145, "Microsoft-Windows-Security-Auditing", "Remote schedule task creation via named pipes", "T1053.005", "Scheduled Task"
	, 4698, "Microsoft-Windows-Security-Auditing", "Schedule task created with suspicious arguments", "T1053.005", "Scheduled Task"
	, 4698, "Microsoft-Windows-Security-Auditing", "Schedule task fastly created and deleted", "T1053.005", "Scheduled Task"
	, 4699, "Microsoft-Windows-Security-Auditing", "Schedule task fastly created and deleted", "T1053.005", "Scheduled Task"
	, 4688, "Microsoft-Windows-Security-Auditing", "Scheduled task creation", "T1053.005", "Scheduled Task"
	, 1   ,	"Microsoft-Windows-Sysmon", "Scheduled task creation", "T1053.005", "Scheduled Task"
	, 800 , "PowerShell", "Encoded PowerShell payload deployed", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4103, "Microsoft-Windows-PowerShell", "Encoded PowerShell payload deployed", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4104, "Microsoft-Windows-PowerShell", "Encoded PowerShell payload deployed", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 800 , "Microsoft-Windows-Security-Auditing", "Interactive PipeShell over SMB named pipe", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4103, "Microsoft-Windows-PowerShell", "Interactive PipeShell over SMB named pipe", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4104, "Microsoft-Windows-PowerShell", "Interactive PipeShell over SMB named pipe", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 800 , "PowerShell", "Payload downloaded via PowerShell", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4103, "Microsoft-Windows-PowerShell", "Payload downloaded via PowerShell", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4104, "Microsoft-Windows-PowerShell", "Payload downloaded via PowerShell", "T1059.001", "Command and Scripting Interpreter: PowerShell"
	, 4688, "Microsoft-Windows-Security-Auditing", "Encoded PowerShell payload deployed via process execution", "T1059.003", "Windows Command Shell"
	, 1   ,	"Microsoft-Windows-Sysmon", "Encoded PowerShell payload deployed via process execution", "T1059.003", "Windows Command Shell"
	, 4688, "Microsoft-Windows-Security-Auditing", "SQL Server payload injectection for reverse shell (MSF)", "T1059.003", "Windows Command Shell"
	, 1   ,	"Microsoft-Windows-Sysmon", "SQL Server payload injectection for reverse shell (MSF)", "T1059.003", "Windows Command Shell"
	, 4688, "Microsoft-Windows-Security-Auditing", "Edge abuse for payload download via console", "T1204", "User execution"
	, 1   ,	"Microsoft-Windows-Sysmon", "Edge abuse for payload download via console", "T1204", "User execution"
	, 4688, "Microsoft-Windows-Security-Auditing", "Edge/Chrome headless feature abuse for payload download", "T1204", "User execution"
	, 1   , "Microsoft-Windows-Sysmon", "Edge/Chrome headless feature abuse for payload download", "T1204", "User execution"
	, 4688, "Microsoft-Windows-Security-Auditing", "PSexec installation detected", "T1569.002", "Service Execution"
	, 1   , "Microsoft-Windows-Sysmon", "PSexec installation detected", "T1569.002", "Service Execution"
	, 7000, "Service Control Manager", "Service massive failures (native)", "T1569.002", "Service Execution"
	, 7009, "Service Control Manager", "Service massive failures (native)", "T1569.002", "Service Execution"
	, 7045, "Service Control Manager", "Service massive installation (native)", "T1569.002", "Service Execution"
	, 4697, "Microsoft-Windows-Security-Auditing", "Service massive installation (native)", "T1569.002", "Service Execution"
	, 5145, "Microsoft-Windows-Security-Auditing", "Service massive remote creation via named pipes (native)", "T1569.002", "Service Execution"
]);
SecurityEvent
| extend Timestamp=TimeGenerated
| where TimeGenerated between (StartTime..EndTime)
| extend Computer=tostring(split(Computer,".")[0])
| where (array_length(SpecifiedSystem)==0 or Computer in~(SpecifiedSystem))
    and (array_length(ExcludedSystem)==0 or not(Computer has_any(ExcludedSystem)))
| parse EventData with *'SubjectUserName">'SubjectUserName'</Data>'*
| parse EventData with *'TargetUserName">'TargetUserName'</Data>'*
| parse EventData with *'<Data Name="User">'User'</Data>'*
| extend UnifiedAccount = coalesce(SubjectUserName, TargetUserName,
    iff(SubjectAccount contains "\\",tostring(split(SubjectAccount,"\\")[1]),SubjectAccount),
    iff(Account contains "\\",tostring(split(Account,"\\")[1]),Account),
    iff(User contains "\\",tostring(split(User,"\\")[1]),User))
| extend UnifiedAccount=iff(isnotempty(Account), tostring(split(Account,"\\")[1]),UnifiedAccount)
| where (array_length(SpecifiedUser)==0 or UnifiedAccount in~(SpecifiedUser))
    and (array_length(ExcludedUser)==0 or not(UnifiedAccount has_any(ExcludedUser)))
| lookup kind=leftouter TA0002Execution on EventID,EventSourceName
| where EventID in(4688,5145,4698,4697) and EventSourceName contains "Microsoft-Windows-Security-Auditing"
     or EventID in(7000,7009,7045) and EventSourceName contains "Service Control Manager"
     or EventID in(4103,4104) and EventSourceName contains "Microsoft-Windows-PowerShell"
     or EventID in(1) and EventSourceName contains "Microsoft-Windows-Sysmon"
     or EventID in(800) and EventSourceName contains "PowerShell"
| parse EventData with *'"ParentImage">'ParentProcessName1'</Data>'*
| parse EventData with *'"Image">'NewProcessName1'</Data>'*
| parse EventData with *'"UtcTime">'EventCreation'</Data>'*
| extend Better4688=strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="ProcessId">',NewProcessId,'</Data>\n'
'  <Data Name="Image">',NewProcessName,'</Data>\n''  <Data Name="CommandLine">',CommandLine,'</Data>\n'
'  <Data Name="User">',TargetAccount,'</Data>\n''  <Data Name="LogonId">',TargetLogonId,'</Data>\n'
'  <Data Name="UserName">',TargetUserName,'</Data>\n''  <Data Name="ParentProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ParentImage">',ParentProcessName,'</Data>\n''  <Data Name="ParentUser">',SubjectAccount,'</Data>\n'
'  <Data Name="AccountType">',AccountType,'</Data>\n''</EventData>')
| extend EventData=iff(EventID==4688,Better4688,EventData)
| extend ParentProcessName=iff(EventID==1,ParentProcessName1,ParentProcessName)
        ,NewProcessName=iff(EventID==1,NewProcessName1,NewProcessName)
| extend commandLine=tolower(CommandLine),NewProcessId=tolong(NewProcessId)
        ,SysmonTime=todatetime(EventCreation)
| extend ProcessMatch=case(
    Description=="Impacket WMIexec process execution" and commandLine has_all("wmic","process","call","create"),true,
    Description=="Interactive shell triggered by scheduled task (at, deprecated)" and commandLine has "at.exe",true,
    Description=="Persistent scheduled task with SYSTEM privileges creation" and commandLine has_all("schtasks","/create","/sc","onstart","/ru","system"),true,
    Description=="Scheduled task creation" and (commandLine has_all("schtasks","/create") and not(commandLine has_all("/sc","onstart","/ru","system"))),true,
    Description=="Encoded PowerShell payload deployed via process execution" and commandLine has_any("-enc","JABl","SQBFAFgA"),true,
    Description=="SQL Server payload injectection for reverse shell (MSF)" and commandLine has "xp_cmdshell",true,
    Description=="Edge abuse for payload download via console" and commandLine has_all("msedge.exe","--headless"),true,
    Description=="Edge/Chrome headless feature abuse for payload download" and (commandLine has_all("chrome.exe","--headless") or commandLine has_all("msedge.exe","--headless")),true,
    Description=="PSexec installation detected" and (NewProcessName has "PSEXESVC.exe" or commandLine has "PSEXESVC.exe"),true,false)
| where (EventID in(1,4688) and ProcessMatch==true)
| extend StatusInformation1=iff(EventID==1,bag_pack("New Process",NewProcessName,"Parent Process",ParentProcessName,"Command Line",commandLine),dynamic([])),
         StatusInformation4688=iff(EventID==4688,bag_pack("New Process",NewProcessName,"Parent Process",ParentProcessName,"Command Line",commandLine),dynamic([]))
| extend MITREAssociation=coalesce(strcat(TechniqueID,": ",TechniqueName," | ",Description),"N/A"),
         AdditionalInformation=iff(EventID==1,StatusInformation1,
                               iff(EventID==4688,StatusInformation4688,dynamic([])))
| summarize make_set_if(EventID,EventID in(1,4688)),Activity=make_set(Activity),EventData=make_set(EventData),UnifiedAccount=make_set(UnifiedAccount)
         by Computer,MITREAssociation,tostring(AdditionalInformation),bin(TimeGenerated,3s)
| extend EventData=iff(array_length(EventData)>1 and EventData[0] has "Hashes",EventData[0]
                  ,iff(array_length(EventData)>1 and EventData[1] has "Hashes",EventData[1]
                  ,iff(array_length(EventData)==1 and EventData[0] has "Hashes",EventData[0],EventData)))
| parse EventData with *'"Hashes">'ParsedHashes'</Data>'*
| extend AdditionalInformation=todynamic(AdditionalInformation),Hashes=strcat(split(ParsedHashes,",")[2],'\n',split(ParsedHashes,",")[3])
| extend AdditionalInformation=AdditionalInformation,Hashes
| project Timestamp=TimeGenerated,Computer,Activity,UnifiedAccount,MITREAssociation,AdditionalInformation,EventData
'@
    'Subquery: Privilege Escalation (TA0004) - partial filtering' = @'
let SpecifiedSystem = dynamic([]);
let ExcludedSystem  = dynamic([]);
let SpecifiedUser   = dynamic([]);
let ExcludedUser    = dynamic([]);
let StartTime       = datetime();
let EndTime         = datetime();
let TA0004PrivilegeEscalation = materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string,Tactic:string) [
	4673, "Microsoft-Windows-Security-Auditing", "Exploitation for Privilege Escalation", "T1068", "Privilege SeMachineAccountPrivilege abuse", "TA0004-Privilege Escalation"
	, 4624, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Token Impersonation/Theft", "T1134.001", "Anonymous login", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Token Impersonation/Theft", "T1134.001", "Anonymous login", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)", "TA0004-Privilege Escalation"
	, 4648, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)", "TA0004-Privilege Escalation"
	, 4624, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via runas (command)", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via RunasCS", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: Create Process with Token", "T1134.002", "Privilege escalation via RunasCS", "TA0004-Privilege Escalation"
	, 4675, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account", "TA0004-Privilege Escalation"
	, 4766, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account", "TA0004-Privilege Escalation"
	, 4738, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation: SID-History Injection", "T1134.005", "SID history value S/F to be added to a domain account", "TA0004-Privilege Escalation"
	, 4717, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "New access rights granted to an account by a standard user", "TA0004-Privilege Escalation"
	, 4718, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "New access rights granted to an account by a standard user", "TA0004-Privilege Escalation"
	, 4704, "Microsoft-Windows-Security-Auditing", "Access Token Manipulation", "T1134", "User right granted to an account by a standard user", "TA0004-Privilege Escalation"
	, 5136, "Microsoft-Windows-Security-Auditing", "Domain Policy Modification-Group Policy Modification", "T1484.001", "Modification of a sensitive Group Policy", "TA0004-Privilege Escalation"
	, 4865, "Microsoft-Windows-Security-Auditing", "Domain or Tenant Policy Modification: Trust Modification", "T1484.002", "New external trust added", "TA0004-Privilege Escalation"
	, 4076, "Microsoft-Windows-Security-Auditing", "Domain or Tenant Policy Modification: Trust Modification", "T1484.002", "New external trust added", "TA0004-Privilege Escalation"
	, 7045, "Microsoft-Windows-Security-Auditing", "Create or Modify System Process-Windows Service", "T1543.003", "PSexec service installation detected", "TA0004-Privilege Escalation"
	, 4697, "Microsoft-Windows-Security-Auditing", "Create or Modify System Process-Windows Service", "T1543.003", "PSexec service installation detected", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "CMD executed by sticky key and detected via hash", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "CMD executed by sticky key and detected via hash", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key called CMD via command execution", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key called CMD via command execution", "TA0004-Privilege Escalation"
	, 4656, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key failed sethc replacement by CMD", "TA0004-Privilege Escalation"
	, 11,   "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key file created from CMD copy", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO command for registry change", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO command for registry change", "TA0004-Privilege Escalation"
	, 12,   "Microsoft-Windows-Sysmon", "Event Triggered Execution: Accessibility Features", "T1546.008", "Sticky key IFEO registry changed", "TA0004-Privilege Escalation"
	, 800,  "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added", "TA0004-Privilege Escalation"
	, 4103, "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added", "TA0004-Privilege Escalation"
	, 4104, "Microsoft-Windows-Security-Auditing", "Port Monitors", "T1547.010", "Print spooler privilege escalation via printer added", "TA0004-Privilege Escalation"
	, 4688, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "External printer mapped", "TA0004-Privilege Escalation"
	, 4648, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "External printer mapped", "TA0004-Privilege Escalation"
	, 6416, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "New external device added", "TA0004-Privilege Escalation"
	, 808,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed", "TA0004-Privilege Escalation"
	, 354,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed", "TA0004-Privilege Escalation"
	, 321,  "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Printer spool driver from Mimikatz installed", "TA0004-Privilege Escalation"
	, 1,    "Microsoft-Windows-Sysmon", "DLL Side-Loading", "T1574.002", "Spool process spawned a CMD shell",	"TA0004-Privilege Escalation"
    , 4688, "Microsoft-Windows-Security-Auditing", "DLL Side-Loading", "T1574.002", "Spool process spawned a CMD shell", "TA0004-Privilege Escalation"
]);
let AccessMaskAttr = materialize(datatable(AccessCode:string,AccessType:string) [
    "%%4416", "ReadData/ListDirectory/QueryKeyValue"
    , "%%4417", "WriteData/AddFile/SetKeyValue"
    , "%%4418", "AppendData/AddSubdirectory/CreatePipeInstance"
    , "%%4419", "ReadEA/EnumerateSub-Keys"
    , "%%4420", "WriteEA"
    , "%%4421", "Execute/Traverse"
    , "%%4422", "DeleteChild"
    , "%%4423", "ReadAttributes"
    , "%%4424", "WriteAttributes"
    , "%%1537", "DELETE"
    , "%%1538", "READ_CONTROL"
    , "%%1539", "WRITE_DAC"
    , "%%1540", "WRITE_OWNER"
    , "%%1541", "SYNCHRONIZE"
    , "%%1542", "ACCESS_SYS_SEC"
]);
let PrivilegeListDefinitions = materialize(datatable(PrivilegeCode:string,PrivilegeFunction:string) [
    "SeAssignPrimaryTokenPrivilege",     "Replace a process-level token"
    , "SeAuditPrivilege",                "Generate security audits"
    , "SeBackupPrivilege",               "Back up files and directories"
    , "SeChangeNotifyPrivilege",         "Bypass traverse checking"
    , "SeCreateGlobalPrivilege",         "Create global objects"
    , "SeCreatePagefilePrivilege",       "Create a pagefile"
    , "SeCreatePermanentPrivilege",      "Create permanent shared objects"
    , "SeCreateSymbolicLinkPrivilege",   "Create symbolic links"
    , "SeCreateTokenPrivilege",          "Create a token object"
    , "SeDebugPrivilege",                "Debug programs"
    , "SeEnableDelegationPrivilege",     "Enable computer and user accounts to be trusted for delegation"
    , "SeImpersonatePrivilege",          "Impersonate a client after authentication"
    , "SeIncreaseBasePriorityPrivilege", "Increase scheduling priority"
    , "SeIncreaseQuotaPrivilege",        "Adjust memory quotas for a process"
    , "SeIncreaseWorkingSetPrivilege",   "Increase a process working set"
    , "SeLoadDriverPrivilege",           "Load and unload device drivers"
    , "SeLockMemoryPrivilege",           "Lock pages in memory"
    , "SeMachineAccountPrivilege",       "Add workstations to domain"
    , "SeManageVolumePrivilege",         "Perform volume maintenance tasks"
    , "SeProfileSingleProcessPrivilege", "Profile single process"
    , "SeRelabelPrivilege",              "Modify an object label"
    , "SeRemoteShutdownPrivilege",       "Force shutdown from a remote system"
    , "SeRestorePrivilege",              "Restore files and directories"
    , "SeSecurityPrivilege",             "Manage auditing and security log"
    , "SeShutdownPrivilege",             "Shut down the system"
    , "SeSyncAgentPrivilege",            "Synchronize directory service data"
    , "SeSystemEnvironmentPrivilege",    "Modify firmware environment values"
    , "SeSystemProfilePrivilege",        "Profile system performance"
    , "SeSystemtimePrivilege",           "Change the system time"
    , "SeTakeOwnershipPrivilege",        "Take ownership of files or other objects"
    , "SeTcbPrivilege",                  "Act as part of the operating system"
    , "SeTimeZonePrivilege",             "Change the time zone"
    , "SeTrustedCredManAccessPrivilege", "Access Credential Manager as a trusted caller"
    , "SeUndockPrivilege",               "Remove computer from docking station"
    , "SeUnsolicitedInputPrivilege",     "Not applicable"
]);
let TA0004Events = materialize ( SecurityEvent
| where TimeGenerated >ago(24h)
| extend Computer = tostring(split(Computer,".")[0])
| where (array_length(SpecifiedSystem) == 0 or Computer in~ (SpecifiedSystem))
    and (array_length(ExcludedSystem) == 0 or not(Computer has_any (ExcludedSystem)))
| parse EventData with *'SubjectUserName">'SubjectUserName'</Data>'*
| parse EventData with *'TargetUserName">'TargetUserName'</Data>'*
| parse EventData with *'<Data Name="User">'User'</Data>'*
| extend UnifiedAccount = coalesce(SubjectUserName, TargetUserName,
    iff(SubjectAccount contains "\\", tostring(split(SubjectAccount, "\\")[1]), SubjectAccount),
    iff(Account contains "\\", tostring(split(Account, "\\")[1]), Account),
    iff(User contains "\\", tostring(split(User, "\\")[1]), User))
| extend UnifiedAccount = iff(isnotempty(Account), tostring(split(Account,"\\")[1]), UnifiedAccount)
| where (array_length(SpecifiedUser) == 0 or UnifiedAccount in~ (SpecifiedUser))
    and (array_length(ExcludedUser) == 0 or not(UnifiedAccount has_any (ExcludedUser)))
| lookup kind=leftouter TA0004PrivilegeEscalation on EventID, EventSourceName
| where EventID in (4673,4624,4688,4648,4675,4766,4717,4738,4718,4704,5136,4865,4076,4697,4656,6416,808,354,321)
    and EventSourceName contains "Microsoft-Windows-Security-Auditing"
    or  EventID in (800) and EventSourceName contains "PowerShell"
    or  EventID in (7045) and EventSourceName contains "Service Control Manager"
    or  EventID in (1,11,12) and EventSourceName contains "Microsoft-Windows-Sysmon"
    or  EventID in (4103,4104) and EventSourceName contains "Microsoft-Windows-PowerShell"
| parse EventData with *'<Data Name="Hashes">'Hashes'</Data>'*
| parse EventData with *'<Data Name="Image">'FileCreatingProcess'</Data>'*
| parse EventData with *'<Data Name="TargetFilename">'File'</Data>'*
| parse EventData with *'<Data Name="CreationUtcTime">'FileCreationTime'</Data>'*
| parse EventData with *'<Data Name="User">'FileCreator'</Data>'*
| parse EventData with *'<Data Name="CommandLine">'CommandLine'</Data>'*
| parse EventData with *'<Data Name="ObjectType">'ObjType'</Data>'*
| parse EventData with *'<Data Name="ObjectName">'ObjName'</Data>'*
| parse EventData with *'<Data Name="AccessList">'AccessList'</Data>'*
| parse EventData with *'<Data Name="PrivilegeList">'PrivilegeName'</Data>'*
| parse EventData with *'<Data Name="ProcessName">'HandleCreatingProcess'</Data>'*
| extend PrivList = extract_all(@'(\w+)', tostring(PrivilegeName)),AccList = extract_all(@'(%%\d+)', tostring(AccessList))
| extend ParsedHashes = split(Hashes, ",")
| extend SHA256   = ParsedHashes[2], IMPHASH = ParsedHashes[3]
| extend HashInfo = 
    iff((isnotempty(SHA256)  and isnotempty(IMPHASH)), strcat(SHA256,", ",IMPHASH),
    iff((isnotempty(SHA256)  and isempty(IMPHASH)), SHA256,
    iff((isnotempty(IMPHASH) and isempty(SHA256)), IMPHASH, "N/A"))), ""
| extend Better4688 = 
    strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="ProcessId">',NewProcessId,'</Data>\n'
'  <Data Name="Image">',NewProcessName,'</Data>\n''  <Data Name="CommandLine">',CommandLine,'</Data>\n'
'  <Data Name="User">',TargetAccount,'</Data>\n''  <Data Name="LogonId">',TargetLogonId,'</Data>\n'
'  <Data Name="UserName">',TargetUserName,'</Data>\n''  <Data Name="ParentProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ParentImage">',ParentProcessName,'</Data>\n''  <Data Name="ParentUser">',SubjectAccount,'</Data>\n'
'  <Data Name="AccountType">',AccountType,'</Data>\n''</EventData>')
| extend Better4624 =
    strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="SubjectUser SID">',SubjectUserSid,'</Data>\n'
'  <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''  <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n'
'  <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''  <Data Name="TargetUserSID">',TargetUserSid,'</Data>\n'
'  <Data Name="TargetUserName">',TargetUserName,'</Data>\n''  <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'  <Data Name="TargetLogonID">',TargetLogonId,'</Data>\n''  <Data Name="LogonType">',LogonTypeName,'</Data>\n'
'  <Data Name="LogonProcess">',LogonProcessName,'</Data>\n''  <Data Name="AuthenticationPackage">',AuthenticationPackageName,'</Data>\n'
'  <Data Name="WorkstationName">',Computer,'</Data>\n''  <Data Name="LogonGuid">',LogonGuid,'</Data>\n'
'  <Data Name="LmPackageName">',LmPackageName,'</Data>\n''  <Data Name="ProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ProcessName">',ProcessName,'</Data>\n''  <Data Name="IpAddress">',IpAddress,'</Data>\n'
'  <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend Better4648 =
    strcat('<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
'  <Data Name="UtcTime">',TimeGenerated,'</Data>\n''  <Data Name="SubjectUserSID">',SubjectUserSid,'</Data>\n'
'  <Data Name="SubjectUserName">',SubjectUserName,'</Data>\n''  <Data Name="SubjectDomainName">',SubjectDomainName,'</Data>\n'
'  <Data Name="SubjectLogonID">',SubjectLogonId,'</Data>\n''  <Data Name="LogonGuid">',LogonGuid,'</Data>\n'
'  <Data Name="TargetUserName">',TargetUserName,'</Data>\n''  <Data Name="TargetDomainName">',TargetDomainName,'</Data>\n'
'  <Data Name="TargetLogonGuid">',TargetLogonGuid,'</Data>\n''  <Data Name="TargetServerName">',TargetServerName,'</Data>\n'
'  <Data Name="TargetInfo">',TargetInfo,'</Data>\n''  <Data Name="ProcessId">',ProcessId,'</Data>\n'
'  <Data Name="ProcessName">',ProcessName,'</Data>\n''  <Data Name="IpAddress">',IpAddress,'</Data>\n'
'  <Data Name="IpPort">',IpPort,'</Data>\n''</EventData>')
| extend EventData = iff(EventID == 4688, Better4688,
                     iff(EventID == 4624, Better4624,
                     iff(EventID == 4648, Better4648, EventData)))
| extend row_id=new_guid());
let MappedAccessTypes_table = TA0004Events
| where EventID == 4656 and array_length(AccList) > 0
| mv-expand AccList_item = AccList to typeof(string)
| join kind=leftouter AccessMaskAttr on $left.AccList_item == $right.AccessCode
| summarize MappedAccessTypes = make_set(AccessType) by row_id;
let MappedPrivilegeTypes_table = TA0004Events
| where EventID == 4656 and array_length(PrivList) > 0
| mv-expand PrivList_item = PrivList to typeof(string)
| join kind=leftouter PrivilegeListDefinitions on $left.PrivList_item == $right.PrivilegeCode
| summarize MappedPrivilegeTypes = make_set(PrivilegeFunction) by row_id;
TA0004Events
| join kind=leftouter MappedAccessTypes_table on row_id
| join kind=leftouter MappedPrivilegeTypes_table on row_id
| extend StatusInformation4624 = iff(EventID == 4624,bag_pack("LogonType",LogonType,"LogonProcess",LogonProcessName),dynamic([])),
         StatusInformation11   = iff(EventID == 11,  bag_pack("New File", File,"File Creator",FileCreator,"Creating Process",
                                                     FileCreatingProcess,"Creation Time",FileCreationTime),dynamic([])),
         StatusInformation4688 = iff(EventID == 4688,bag_pack("Parent Process",ParentProcessName,"New Process",NewProcessName,
                                                     "Parent User",SubjectUserName),dynamic([])),
         StatusInformation4656 = iff(EventID == 4656,bag_pack("Parent Process",HandleCreatingProcess,"Object Type",ObjType,"Object Name",ObjName,
                                                     "Access List",AccList,"Access Type",MappedAccessTypes,"Privilege List",PrivList,
                                                     "Privilege Function",MappedPrivilegeTypes),dynamic([]))
| extend MITREAssociation = coalesce(strcat(TechniqueID,": ",TechniqueName, " | ",Description),"N/A"),
         AdditionalInformation = iff(EventID==1,HashInfo,
                                 iff(EventID==4624,StatusInformation4624,
                                 iff(EventID==4688,StatusInformation4688,
                                 iff(EventID==4656,StatusInformation4656,
                                 iff(EventID==11,StatusInformation11,dynamic([]))))))
| project Timestamp=TimeGenerated,Computer,UnifiedAccount,Activity,MITREAssociation,AdditionalInformation,EventData
'@
    'Subquery: Collection/C2/Impact (TA0009/11/40) - in progress' = @'
let TA0009Collection = materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	  13  , "Microsoft-Windows-Sysmon", "RDP shadow session started (registry)", "T1125", "Video capture"
]);
let TA0011CommandAndControl = materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	  4688, "Microsoft-Windows-Security-Auditing", "RDP tunneling configuration enabled for port forwarding", "T1572", "Protocol tunneling"
	, 1   , "Microsoft-Windows-Sysmon", "RDP tunneling configuration enabled for port forwarding", "T1572", "Protocol tunneling"
	, 5600, "Microsoft-Windows-WinINet-Config", "Proxy configuration changed", "T1090", "Proxy"
]);
let TA0040Impact = materialize(datatable(EventID:int,EventSourceName:string,Description:string,TechniqueID:string,TechniqueName:string) [
	  4103, "Microsoft-Windows-PowerShell", "VSS backup deletion (PowerShell)", "T1490", "Inhibit System Recovery"
	, 4104, "Microsoft-Windows-PowerShell", "VSS backup deletion (PowerShell)", "T1490", "Inhibit System Recovery"
	, 4688, "Microsoft-Windows-Security-Auditing", "Windows native backup deletion", "T1490", "Inhibit System Recovery"
	, 4688, "Microsoft-Windows-Security-Auditing", "VSS backup deletion (WMI)", "T1490", "Inhibit System Recovery"
	, 1   , "Microsoft-Windows-Sysmon", "VSS backup deletion (WMI)", "T1490", "Inhibit System Recovery"
	, 1   , "Microsoft-Windows-Sysmon", "Windows native backup deletion", "T1490", "Inhibit System Recovery"
	, 11  , "Microsoft-Windows-Sysmon", "DNS hosts file modified", "T1565", "Data manipulation"
	, 800 , "PowerShell", "VSS backup deletion (PowerShell)", "T1490", "Inhibit System Recovery"
]);
let TA0009Events = materialize ( SecurityEvent
| lookup kind=leftouter TA0009Collection on EventID, EventSourceName
| where EventID == 13 and EventSourceName contains "Microsoft-Windows-Sysmon"
| parse EventData with *'<Data Name="TargetObject">'RegPath'</Data>'*
| parse EventData with *'<Data Name="Details">'SetValue'</Data>'*
| parse EventData with *'<Data Name="Image">'Image'</Data>'*
| where RegPath contains @"Terminal Services\Shadow" and not(SetValue contains "DWORD (0x00000000)")
| extend StatusInformation13 = bag_pack("Initiating Process",Image,"Registry Object",RegPath,"Modified Value",SetValue)
| extend MITREAssociation = coalesce(strcat(TechniqueID,": ",TechniqueName, " | ",Description),"N/A"),
         AdditionalInformation = iff(EventID==13, StatusInformation13,dynamic([]))
| project Timestamp=TimeGenerated,Computer,Account,Activity,MITREAssociation,AdditionalInformation,EventData);
let TA0011Events = materialize ( SecurityEvent
| lookup kind=leftouter TA0011CommandAndControl on EventID, EventSourceName
| where EventID == 1 and EventSourceName contains "Microsoft-Windows-Sysmon"
     or EventID == 4688 and EventSourceName contains "Microsoft-Windows-Security-Auditing"
     or EventID == 5600 and EventSourceName contains "Microsoft-Windows-WinINet-Config"
| parse EventData with *'<Data Name="CommandLine">'CmdLine'</Data>'*
| extend IOCMatch = iff(EventID == 1 and CmdLine contains "-L", CmdLine, "N/A")
'@
    'APT Hunt Pack: China & Russia (Salt/Volt Typhoon, APT28/29, Sandworm)' = @'
// =============================================================================
//  APT-Hunt-CN-RU.kql
//  Chinese & Russian APT Hunt Pack  -  Azure Data Explorer
// -----------------------------------------------------------------------------
//  Window  : June 1, 2025  ->  now
//  Target  : SecurityEvent (host = Computer)
//  Network : optional join (host = Hostname) -- gated by HasNetworkTable flag
//
//  IOCs sourced from:
//    CISA AA25-239A  Salt Typhoon / OPERATOR PANDA / RedMike / GhostEmperor (Aug 27 2025)
//    CISA AA25-141A  APT28 / Fancy Bear / Forest Blizzard / GRU 26165       (May 21 2025)
//    Microsoft Threat Intel  BadPilot / Seashell Blizzard / Sandworm        (Feb 12 2025)
//    AWS Threat Intel  Sandworm credential replay campaign                  (Dec 23 2025)
//    Check Point Research  APT29 GRAPELOADER / WINELOADER                   (Apr 15 2025 ->)
//    ESET / Talos / TrendMicro  Salt Typhoon FamousSparrow / SparrowDoor    (Mar 2025)
//    Microsoft  Midnight Blizzard RDP-file spear-phishing                   (Oct 2024 -> 2025)
//
//  This file is structured as:
//    [1] APT_IOCs datatable     -- normalized IOC table for joining
//    [2] APT_TTPs datatable     -- TTP -> EventID mapping for hunts
//    [3] Initial Access hunts   -- per-tactic step-through
//    [4] Persistence hunts
//    [5] Lateral Movement hunts
//    [6] Credential Theft hunts
//    [7] Cross-correlation roll-up
//
//  IMPORTANT  -- IOCs decay quickly. Vet IPs/hashes against current feeds
//  before blocking. CVEs and TTPs remain valid much longer.
// =============================================================================

// -----------------------------------------------------------------------------
// PARAMETERS
// -----------------------------------------------------------------------------
let TargetHost      = "<HOSTNAME>";
let HuntStart       = datetime(2025-06-01T00:00:00Z);
let HuntEnd         = now();
let HasNetworkTable = false;                  // flip to true if Zeek/conn data is mapped into ADX
let NetworkTable    = "ZeekConn";             // override if you have a different network table name

// =============================================================================
//  [1]  APT_IOCs  -  normalized IOC datatable
//      Fields:
//        APT          - canonical group name
//        Country      - CN | RU
//        Aliases      - common alternate names
//        IOCType      - IPv4 | Domain | SHA256 | MD5 | Filename | RegKey | Tool
//        IOCValue     - the indicator
//        Context      - what it represents in the kill chain
//        FirstSeen    - earliest public reporting in window
//        Source       - advisory / vendor reference
// =============================================================================
let APT_IOCs = datatable(APT:string, Country:string, Aliases:string, IOCType:string, IOCValue:string, Context:string, FirstSeen:datetime, Source:string)
[
    // ---- Salt Typhoon (CN) -- AA25-239A IPs (defanged in source, vetted before blocking)
    "Salt Typhoon","CN","OPERATOR PANDA, RedMike, UNC5807, GhostEmperor, Earth Estries","IPv4","167.88.173.252","C2 / staging infrastructure",datetime(2025-08-27),"CISA AA25-239A",
    "Salt Typhoon","CN","OPERATOR PANDA, RedMike, UNC5807, GhostEmperor, Earth Estries","IPv4","193.239.86.132","C2 / staging infrastructure",datetime(2025-08-27),"CISA AA25-239A",
    "Salt Typhoon","CN","OPERATOR PANDA, RedMike, UNC5807, GhostEmperor, Earth Estries","IPv4","45.61.165.157","C2 / staging infrastructure",datetime(2025-08-27),"CISA AA25-239A",
    "Salt Typhoon","CN","OPERATOR PANDA, RedMike, UNC5807","Tool","ScanLine","Network port scanner staged on victim hosts",datetime(2025-08-27),"CISA AA25-239A",
    "Salt Typhoon","CN","FamousSparrow, GhostEmperor","Filename","SparrowDoor","Custom backdoor (multiple variants 2025)",datetime(2025-03-26),"ESET / Talos",
    "Salt Typhoon","CN","FamousSparrow, GhostEmperor","Filename","ShadowPad","Modular backdoor first attributed to FamousSparrow in 2025",datetime(2025-03-26),"ESET",
    "Salt Typhoon","CN","Salt Typhoon","RegKey","access-list 20","ACL whitelist name on Cisco edge devices (network IOC)",datetime(2025-08-27),"CISA AA25-239A",

    // ---- Volt Typhoon (CN) -- continuing 2025 activity
    "Volt Typhoon","CN","BRONZE SILHOUETTE, Vanguard Panda, Insidious Taurus","Filename","comsvcs.dll","Dropped to non-System32 path for LSASS minidump",datetime(2024-02-07),"CISA AA24-038A",
    "Volt Typhoon","CN","Vanguard Panda","Tool","FRPC","Fast Reverse Proxy Client for C2 tunneling",datetime(2024-02-07),"CISA MAR-10448362",
    "Volt Typhoon","CN","Vanguard Panda","Tool","ntdsutil.exe","NTDS.dit extraction from domain controllers",datetime(2024-02-07),"CISA AA24-038A",

    // ---- APT28 (RU) -- AA25-141A
    "APT28","RU","Fancy Bear, Forest Blizzard, BlueDelta, Sednit, GRU 26165","Tool","HEADLACE","Credential phishing dropper / shortcut loader",datetime(2025-05-21),"CISA AA25-141A",
    "APT28","RU","Fancy Bear, Forest Blizzard, BlueDelta","Tool","MASEPIE","Python RAT for file transfer and remote control",datetime(2025-05-21),"CISA AA25-141A",
    "APT28","RU","Fancy Bear, Forest Blizzard","Tool","OCEANMAP","Mailbox-based C2 implant",datetime(2025-05-21),"CISA AA25-141A",
    "APT28","RU","Fancy Bear, Forest Blizzard","Tool","STEELHOOK","PowerShell credential exfiltration",datetime(2025-05-21),"CISA AA25-141A",
    "APT28","RU","Fancy Bear","Tool","Get-GPPPassword.py","Group Policy Preference password decryption",datetime(2025-05-21),"CISA AA25-141A",
    "APT28","RU","Fancy Bear","Tool","Certipy","ADCS abuse / certificate theft",datetime(2025-05-21),"CISA AA25-141A",

    // ---- APT29 / Midnight Blizzard (RU) -- GRAPELOADER campaign Jan 2025+
    "APT29","RU","Midnight Blizzard, Cozy Bear, Nobelium, SVR, BlueBravo","Filename","wine.exe","Legitimate PowerPoint binary abused for DLL side-load",datetime(2025-01-15),"Check Point Research",
    "APT29","RU","Midnight Blizzard, Cozy Bear","Filename","AppvIsvSubsystems64.dll","Bloated dependency DLL for wine.exe side-load",datetime(2025-01-15),"Check Point Research",
    "APT29","RU","Midnight Blizzard, Cozy Bear","Filename","ppcore.dll","GRAPELOADER backdoor (heavily obfuscated)",datetime(2025-01-15),"Check Point Research",
    "APT29","RU","Midnight Blizzard, Cozy Bear","Tool","GRAPELOADER","Initial-stage loader (fingerprint, persistence, payload delivery)",datetime(2025-01-15),"Check Point Research",
    "APT29","RU","Midnight Blizzard, Cozy Bear","Tool","WINELOADER","Mid-stage backdoor (RC4 string decryption variant)",datetime(2025-01-15),"Check Point Research",
    "APT29","RU","Midnight Blizzard, Cozy Bear","Tool","FOGGYWEB","ADFS-targeted backdoor",datetime(2024-10-29),"Microsoft",
    "APT29","RU","Midnight Blizzard, Cozy Bear","Tool","MAGICWEB","Custom ADFS DLL for persistent auth bypass",datetime(2024-10-29),"Microsoft",
    "APT29","RU","Midnight Blizzard, Cozy Bear","Filename",".rdp","Signed RDP config files mapping local resources to attacker host",datetime(2024-10-22),"Microsoft / CERT-UA #11690",

    // ---- Sandworm / Seashell Blizzard (RU) -- BadPilot 2025
    "Sandworm","RU","Seashell Blizzard, APT44, Voodoo Bear, Iron Viking, GRU 74455","Tool","Atera Agent","Legit RMM abused for C2 persistence",datetime(2025-02-12),"Microsoft Threat Intel",
    "Sandworm","RU","Seashell Blizzard, APT44","Tool","Splashtop","Legit RMM abused for C2 persistence",datetime(2025-02-12),"Microsoft Threat Intel",
    "Sandworm","RU","Seashell Blizzard, APT44","Tool","Kapeka","Custom backdoor (post-exploitation)",datetime(2025-02-12),"Microsoft Threat Intel"
];

// =============================================================================
//  [2]  APT_TTPs  -  TTP -> EventID / pattern mapping for hunts
//      One row per (group, tactic, technique). Used by hunts below + roll-up.
// =============================================================================
let APT_TTPs = datatable(APT:string, Tactic:string, Technique:string, MitreID:string, EventIDs:string, HuntPattern:string, CVE:string)
[
    // ---- INITIAL ACCESS ----
    "Salt Typhoon","Initial Access","Exploit Public-Facing App (Cisco IOS XE)","T1190","4688","cli/web exploit chain on edge router; downstream cmd.exe / powershell from svchost","CVE-2023-20198",
    "Salt Typhoon","Initial Access","Exploit Public-Facing App (Ivanti Connect Secure)","T1190","4688","webshell drops then svc account auth","CVE-2024-21887,CVE-2023-46805",
    "Salt Typhoon","Initial Access","Exploit Public-Facing App (PAN-OS GlobalProtect)","T1190","4688","unauthenticated file write -> webshell","CVE-2024-3400",
    "Volt Typhoon","Initial Access","Exploit Public-Facing App (Fortinet/SOHO edge)","T1190","4688","auth bypass on edge device followed by valid account use","CVE-2022-42475",
    "APT28","Initial Access","Phishing - Spearphishing Link","T1566.002","4688","Outlook -> child process (winword/excel/script host) on receipt","CVE-2023-23397",
    "APT28","Initial Access","Exploit Public-Facing App","T1190","4688","external IP -> w3wp/sqlservr -> cmd.exe child","",
    "APT28","Initial Access","Brute Force - Password Spray","T1110.003","4625,4624","high 4625 volume across distinct accounts followed by 4624 success","",
    "APT29","Initial Access","Phishing - Spearphishing Attachment (.rdp)","T1566.001","4688","mail client -> mstsc.exe with attacker .rdp file","",
    "APT29","Initial Access","Phishing - GRAPELOADER","T1566.001","4688","wine.exe loading non-standard side-loaded DLLs from temp paths","",
    "Sandworm","Initial Access","Exploit Public-Facing App (ScreenConnect)","T1190","4688","ScreenConnect.WindowsClient.exe spawning unexpected children","CVE-2024-1709",
    "Sandworm","Initial Access","Exploit Public-Facing App (FortiClient EMS)","T1190","4688","SQLi exploitation chain","CVE-2023-48788",

    // ---- PERSISTENCE ----
    "Volt Typhoon","Persistence","Valid Accounts","T1078","4624","domain admin reuse from non-admin workstations","",
    "Salt Typhoon","Persistence","Modify Authentication Process","T1556","4624,4672","new SVCHOST/lsass auth pkg or token rights","",
    "APT28","Persistence","Scheduled Task","T1053.005","4698","schtasks /create with powershell payload in TaskContent","",
    "APT28","Persistence","Account Manipulation - Mailbox","T1098.002","4738","Exchange permission grants via PowerShell remoting","",
    "APT29","Persistence","Registry Run Key","T1547.001","4688","reg.exe ADD HKCU\\...\\Run pointing to wine.exe","",
    "APT29","Persistence","Server Software Component - ADFS","T1505.005","4688,4624","FOGGYWEB/MAGICWEB DLL drops on ADFS hosts","",
    "Sandworm","Persistence","Remote Access Software","T1219","4688,4697","Atera/Splashtop install events without change ticket","",

    // ---- LATERAL MOVEMENT ----
    "Volt Typhoon","Lateral Movement","Remote Services - SMB/Admin Shares","T1021.002","5140,5145","admin$ / c$ access from non-admin workstations","",
    "Volt Typhoon","Lateral Movement","Lateral Tool Transfer","T1570","4688,5145","wmic /node: invocations","",
    "Salt Typhoon","Lateral Movement","Remote Services - SSH","T1021.004","4688,4624","ssh.exe outbound to internal hosts off-hours","",
    "APT28","Lateral Movement","Remote Services - RDP","T1021.001","4624","LogonType 10 from new source IPs","",
    "APT29","Lateral Movement","Remote Services - RDP File","T1021.001","4624,4688","mstsc.exe spawned from non-Explorer parent","",

    // ---- CREDENTIAL ACCESS ----
    "Volt Typhoon","Credential Access","OS Credential Dumping - LSASS","T1003.001","4688","comsvcs.dll MiniDump call via rundll32","",
    "Volt Typhoon","Credential Access","OS Credential Dumping - NTDS","T1003.003","4688","ntdsutil ifm create full","",
    "Salt Typhoon","Credential Access","Network Sniffing","T1040","4688","passive PCAP collection from compromised network device","",
    "APT28","Credential Access","Forced Authentication - NTLM Relay","T1187","4624,4776","CVE-2023-23397 Outlook NTLMv2 leak","CVE-2023-23397",
    "APT28","Credential Access","Steal Credentials - GPP","T1552.006","4688","Get-GPPPassword.py / cpassword extraction","",
    "APT28","Credential Access","ADCS Abuse","T1649","4688","Certipy req / certutil with template enrollment","",
    "APT29","Credential Access","Steal Web Session Cookie","T1539","4688","browser process memory access via custom tooling","",
    "Sandworm","Credential Access","Network Sniffing","T1040","4688","credential replay against cloud auth endpoints",""
];

// =============================================================================
//  [3]  INITIAL ACCESS HUNTS  -  step through SecurityEvent for each vector
// =============================================================================

// ---- 3.1 Outlook -> child process (APT28 CVE-2023-23397 chain) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend ParentName = tolower(tostring(split(ParentProcessName, "\\")[-1])),
         ChildName  = tolower(tostring(split(NewProcessName, "\\")[-1]))
| where ParentName == "outlook.exe"
| where ChildName in ("powershell.exe","pwsh.exe","cmd.exe","wmic.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","certutil.exe")
| extend APT = "APT28", Vector = "T1566.002 / CVE-2023-23397"
| project TimeGenerated, APT, Vector, Account, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated desc

// ---- 3.2 wine.exe DLL side-load (APT29 GRAPELOADER) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend ProcLower = tolower(NewProcessName),
         CmdLower  = tolower(CommandLine)
| where ProcLower endswith "\\wine.exe"
| where CmdLower has_any ("appdata\\local\\temp","appdata\\roaming","programdata","users\\public")
   or CmdLower has_any ("appvisvsubsystems64","ppcore.dll")
| extend APT = "APT29", Vector = "T1574.002 / GRAPELOADER side-load"
| project TimeGenerated, APT, Vector, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc

// ---- 3.3 mstsc.exe with attacker-supplied .rdp file (APT29 Oct 2024+) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend ProcLower = tolower(NewProcessName),
         CmdLower  = tolower(CommandLine),
         ParentLower = tolower(ParentProcessName)
| where ProcLower endswith "\\mstsc.exe"
| where CmdLower endswith ".rdp"
| where ParentLower has_any ("outlook.exe","winrar.exe","7zfm.exe","explorer.exe","chrome.exe","msedge.exe","firefox.exe","thunderbird.exe")
| extend APT = "APT29", Vector = "T1566.001 / RDP-file phishing"
| project TimeGenerated, APT, Vector, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc

// ---- 3.4 ScreenConnect / RMM exploit child process (Sandworm BadPilot) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend ParentName = tolower(tostring(split(ParentProcessName, "\\")[-1])),
         ChildName  = tolower(tostring(split(NewProcessName, "\\")[-1]))
| where ParentName has_any ("screenconnect.windowsclient.exe","screenconnect.clientservice.exe","atera","splashtop")
| where ChildName in ("powershell.exe","pwsh.exe","cmd.exe","wmic.exe","rundll32.exe","mshta.exe","certutil.exe","bitsadmin.exe")
| extend APT = "Sandworm", Vector = "T1190 / CVE-2024-1709"
| project TimeGenerated, APT, Vector, Account, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated desc

// ---- 3.5 Public-facing app shell-spawn (Salt Typhoon Ivanti / PAN-OS / Cisco) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend ParentName = tolower(tostring(split(ParentProcessName, "\\")[-1])),
         ChildName  = tolower(tostring(split(NewProcessName, "\\")[-1]))
| where ParentName in ("w3wp.exe","httpd.exe","tomcat.exe","java.exe","nginx.exe","sqlservr.exe")
| where ChildName in ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","systeminfo.exe","ipconfig.exe","hostname.exe","tasklist.exe")
| extend APT = "Salt Typhoon (likely)", Vector = "T1190 webshell child"
| project TimeGenerated, APT, Vector, Account, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated desc

// ---- 3.6 Password spray then success (APT28 reconstituted spray capability) ----
let SprayWindows =
    SecurityEvent
    | where TimeGenerated between (HuntStart .. HuntEnd)
    | where Computer == TargetHost
    | where EventID == 4625
    | summarize Fails = count(),
                Users = make_set(TargetUserName, 200),
                DistinctUsers = dcount(TargetUserName)
              by IpAddress, bin(TimeGenerated, 1h)
    | where Fails >= 25 and DistinctUsers >= 10;
let Successes =
    SecurityEvent
    | where TimeGenerated between (HuntStart .. HuntEnd)
    | where Computer == TargetHost
    | where EventID == 4624 and LogonType in (3, 8, 10)
    | project SuccTime = TimeGenerated, SuccUser = TargetUserName, SuccIP = IpAddress, LogonType;
SprayWindows
| join kind=inner Successes on $left.IpAddress == $right.SuccIP
| where SuccTime between (TimeGenerated .. (TimeGenerated + 2h))
| extend APT = "APT28", Vector = "T1110.003 password spray"
| project SprayHour = TimeGenerated, APT, Vector, IpAddress, Fails, DistinctUsers, CompromisedUser = SuccUser, SuccTime
| order by SprayHour desc

// =============================================================================
//  [4]  PERSISTENCE HUNTS
// =============================================================================

// ---- 4.1 Run-key persistence pointing to known APT29 binaries ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend ProcLower = tolower(NewProcessName),
         CmdLower  = tolower(CommandLine)
| where ProcLower endswith "\\reg.exe"
| where CmdLower has "add" and CmdLower has_any ("\\run","\\runonce")
| where CmdLower has_any ("wine.exe","ppcore","appvisvsubsystems64","\\appdata\\","\\programdata\\","\\users\\public\\")
| extend APT = "APT29", Vector = "T1547.001"
| project TimeGenerated, APT, Vector, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc

// ---- 4.2 Scheduled task creation with PowerShell/LOLBin payload (APT28) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4698
| extend TaskName = tostring(parse_xml(EventData).EventXML.TaskName),
         TaskContent = tostring(parse_xml(EventData).EventXML.TaskContent)
| where TaskContent has_any ("powershell -enc","powershell -e ","powershell -nop","-windowstyle hidden","downloadstring","invoke-expression","iex(","frombase64string","certutil -urlcache","bitsadmin /transfer","mshta http","rundll32 javascript")
| extend APT = "APT28 (likely)", Vector = "T1053.005"
| project TimeGenerated, APT, Vector, Account, TaskName, TaskContent
| order by TimeGenerated desc

// ---- 4.3 RMM tool installation (Sandworm BadPilot) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID in (4688, 4697)
| extend ProcLower = tolower(coalesce(NewProcessName, ServiceFileName, "")),
         SvcLower  = tolower(coalesce(ServiceName, ""))
| where ProcLower has_any ("ateraagent","atera_setup","splashtop","screenconnect","syncrosetup","kaseya","anydesk","teamviewer_setup")
   or SvcLower has_any ("ateraagent","splashtop","screenconnect")
| extend APT = "Sandworm (likely)", Vector = "T1219 RMM persistence"
| project TimeGenerated, APT, Vector, EventID, Account, NewProcessName, ServiceName, ServiceFileName, CommandLine
| order by TimeGenerated desc

// ---- 4.4 Service install with binary in non-System32 path (Volt Typhoon comsvcs.dll style) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4697
| extend SvcPathLower = tolower(ServiceFileName)
| where SvcPathLower has_any ("\\windows\\temp\\","\\users\\public\\","\\programdata\\","\\appdata\\","\\perflogs\\","\\$recycle.bin\\")
   or (SvcPathLower has ".dll" and SvcPathLower !has "\\system32\\" and SvcPathLower !has "\\syswow64\\")
| extend APT = "Volt Typhoon (likely)", Vector = "T1543.003 service masquerading"
| project TimeGenerated, APT, Vector, Account, ServiceName, ServiceFileName, ServiceType, ServiceStartType
| order by TimeGenerated desc

// =============================================================================
//  [5]  LATERAL MOVEMENT HUNTS
// =============================================================================

// ---- 5.1 admin$/c$ share access from non-admin workstations (Volt Typhoon) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID in (5140, 5145)
| extend ShareLower = tolower(ShareName)
| where ShareLower in ("\\\\*\\admin$","\\\\*\\c$","\\\\*\\ipc$") or ShareLower has "$"
| where AccountName !endswith "$"
| extend APT = "Volt Typhoon (likely)", Vector = "T1021.002 admin share"
| project TimeGenerated, APT, Vector, AccountName, IpAddress, ShareName, RelativeTargetName
| order by TimeGenerated desc

// ---- 5.2 wmic /node: lateral execution (Volt Typhoon LOTL) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend CmdLower = tolower(CommandLine),
         ProcLower = tolower(NewProcessName)
| where ProcLower endswith "\\wmic.exe" or ProcLower endswith "\\wminc.exe"      // wminc typo per CISA AA23-144A
| where CmdLower has "/node:" or CmdLower has "process call create"
| extend APT = "Volt Typhoon", Vector = "T1047 / T1570"
| project TimeGenerated, APT, Vector, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc

// ---- 5.3 RDP from new source IP (APT28 / APT29) ----
let RdpBaseline =
    SecurityEvent
    | where TimeGenerated between (HuntStart .. (HuntStart + 14d))
    | where Computer == TargetHost
    | where EventID == 4624 and LogonType == 10
    | distinct IpAddress;
SecurityEvent
| where TimeGenerated between ((HuntStart + 14d) .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4624 and LogonType == 10
| where IpAddress !in (RdpBaseline) and isnotempty(IpAddress) and IpAddress != "-"
| extend APT = "APT28/APT29 (likely)", Vector = "T1021.001 new RDP source"
| project TimeGenerated, APT, Vector, Account, TargetUserName, IpAddress, WorkstationName
| order by TimeGenerated desc

// =============================================================================
//  [6]  CREDENTIAL THEFT HUNTS
// =============================================================================

// ---- 6.1 LSASS dumping via comsvcs.dll MiniDump (Volt Typhoon) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend CmdLower  = tolower(CommandLine),
         ProcLower = tolower(NewProcessName)
| where ProcLower endswith "\\rundll32.exe"
| where CmdLower has "comsvcs" and CmdLower has "minidump"
| extend APT = "Volt Typhoon", Vector = "T1003.001 LSASS dump"
| project TimeGenerated, APT, Vector, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc

// ---- 6.2 NTDS.dit extraction via ntdsutil (Volt Typhoon, APT28) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend CmdLower = tolower(CommandLine), ProcLower = tolower(NewProcessName)
| where ProcLower endswith "\\ntdsutil.exe" or CmdLower has "ntdsutil"
| where CmdLower has_any ("ifm","create full","ac i ntds","activate instance ntds")
| extend APT = "Volt Typhoon / APT28", Vector = "T1003.003 NTDS extraction"
| project TimeGenerated, APT, Vector, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc

// ---- 6.3 vssadmin shadow copy (often pre-step for SAM/SECURITY hive copy) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend CmdLower = tolower(CommandLine), ProcLower = tolower(NewProcessName)
| where ProcLower endswith "\\vssadmin.exe"
| where CmdLower has "create shadow"
| extend APT = "APT28 (likely)", Vector = "T1003.002 SAM/SECURITY via VSS"
| project TimeGenerated, APT, Vector, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc

// ---- 6.4 Get-GPPPassword / cpassword retrieval (APT28) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend CmdLower = tolower(CommandLine)
| where CmdLower has_any ("get-gpppassword","cpassword","\\sysvol\\","groups.xml","scheduledtasks.xml","services.xml")
| extend APT = "APT28", Vector = "T1552.006 GPP password"
| project TimeGenerated, APT, Vector, Account, NewProcessName, CommandLine
| order by TimeGenerated desc

// ---- 6.5 Certipy / certutil ADCS abuse (APT28) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4688
| extend CmdLower = tolower(CommandLine), ProcLower = tolower(NewProcessName)
| where (ProcLower endswith "\\certutil.exe" and CmdLower has_any ("-ca","-template","req"))
   or CmdLower has "certipy"
| extend APT = "APT28", Vector = "T1649 ADCS abuse"
| project TimeGenerated, APT, Vector, Account, NewProcessName, CommandLine
| order by TimeGenerated desc

// ---- 6.6 NTLM relay symptoms via 4624 anonymous + 4776 NTLM auth bursts (APT28 CVE-2023-23397) ----
SecurityEvent
| where TimeGenerated between (HuntStart .. HuntEnd)
| where Computer == TargetHost
| where EventID == 4776
| summarize NtlmCount = count(), Workstations = make_set(Workstation, 50)
          by TargetUserName, bin(TimeGenerated, 15m)
| where NtlmCount > 50
| extend APT = "APT28", Vector = "T1187 / CVE-2023-23397 NTLM relay"
| order by TimeGenerated desc

// =============================================================================
//  [7]  CROSS-CORRELATION ROLL-UP
//      Aggregates hits from sections 3-6 into a single per-day timeline so you
//      can eyeball overlap with the APT_TTPs table. This block is intentionally
//      simplistic so you can extend it -- the goal is a one-screen summary.
// =============================================================================
let _IA_Outlook =
    SecurityEvent | where TimeGenerated between (HuntStart .. HuntEnd) | where Computer == TargetHost | where EventID == 4688
    | extend P = tolower(tostring(split(ParentProcessName,"\\")[-1])), C = tolower(tostring(split(NewProcessName,"\\")[-1]))
    | where P == "outlook.exe" and C in ("powershell.exe","cmd.exe","wmic.exe","mshta.exe","rundll32.exe")
    | extend Tactic="InitialAccess", APT="APT28", Detail=strcat(P," -> ",C);
let _Persist_RMM =
    SecurityEvent | where TimeGenerated between (HuntStart .. HuntEnd) | where Computer == TargetHost | where EventID in (4688, 4697)
    | extend P = tolower(coalesce(NewProcessName,ServiceFileName,""))
    | where P has_any ("ateraagent","splashtop","screenconnect")
    | extend Tactic="Persistence", APT="Sandworm", Detail=P;
let _Lat_WMIC =
    SecurityEvent | where TimeGenerated between (HuntStart .. HuntEnd) | where Computer == TargetHost | where EventID == 4688
    | extend P = tolower(NewProcessName), C = tolower(CommandLine)
    | where P endswith "\\wmic.exe" and C has "/node:"
    | extend Tactic="LateralMovement", APT="Volt Typhoon", Detail=substring(C,0,200);
let _Cred_LSASS =
    SecurityEvent | where TimeGenerated between (HuntStart .. HuntEnd) | where Computer == TargetHost | where EventID == 4688
    | extend P = tolower(NewProcessName), C = tolower(CommandLine)
    | where P endswith "\\rundll32.exe" and C has "comsvcs" and C has "minidump"
    | extend Tactic="CredentialAccess", APT="Volt Typhoon", Detail="comsvcs.dll MiniDump";
union _IA_Outlook, _Persist_RMM, _Lat_WMIC, _Cred_LSASS
| project Day = bin(TimeGenerated, 1d), Tactic, APT, Detail, Account, TimeGenerated
| summarize Hits = count(), Samples = make_set(Detail, 5), Accounts = make_set(Account, 5)
          by Day, Tactic, APT
| order by Day desc, Tactic asc

// =============================================================================
//  END OF FILE
// =============================================================================
'@
    'Initial Access Anomaly Hunt Pack (13 sections)' = @'
// =============================================================================
//  InitialAccess-Anomaly.kql
//  Anomaly-Based Initial Access Hunt Pack  -  Azure Data Explorer
// -----------------------------------------------------------------------------
//  Target table : SecurityEvent
//  Host column  : Computer
//  Author notes : Adjust TargetHost, baseline/detection windows, and thresholds
//                 in the parameter block. Every section can be run independently.
//                 Sections lean on series_decompose_anomalies, first-seen
//                 baselining, rare-value detection, and behavioral outliers.
//
//  Coverage map (MITRE ATT&CK Initial Access + adjacent):
//    T1078        Valid Accounts
//    T1078.002    Domain Accounts
//    T1110.003    Password Spraying
//    T1133        External Remote Services
//    T1190        Exploit Public-Facing Application
//    T1199        Trusted Relationship
//    T1566        Phishing  (downstream child-process anomaly)
//    T1543.003    Windows Service (drop-in via initial access)
//    T1053.005    Scheduled Task/Job
//    T1059.001    PowerShell
//    T1021.001    RDP
//    T1071        Application Layer Protocol (LOLBin egress)
// =============================================================================

// -----------------------------------------------------------------------------
// PARAMETERS  -- adjust per investigation
// -----------------------------------------------------------------------------
let TargetHost          = "<HOSTNAME>";                  // exact match against Computer
let LookbackTotal       = 30d;                            // total span for baseline + detection
let BaselineWindow      = 21d;                            // baseline period (older)
let DetectionWindow     = 9d;                             // detection period (recent)
let HourBin             = 1h;                             // anomaly bucket size
let AnomalyThreshold    = 2.5;                            // series_decompose_anomalies sensitivity (1.5 noisy / 3.0 strict)
let RarePctCutoff       = 0.5;                            // value seen in <0.5% of baseline rows = rare
let SprayFailMin        = 15;                             // minimum failed logons in window to qualify as spray
let SprayDistinctUsers  = 5;                              // distinct users targeted before flag
let OffHoursStart       = 19;                             // 7 PM local
let OffHoursEnd         = 6;                              // 6 AM local
let TimeFrom            = ago(LookbackTotal);
let DetectionFrom       = ago(DetectionWindow);
let BaselineFrom        = ago(LookbackTotal);
let BaselineTo          = ago(DetectionWindow);

// =============================================================================
// SECTION 1  -  Time-Series Logon Volume Anomalies
//   Detects spikes/dips on 4624 (success) and 4625 (failure) per hour using
//   series_decompose_anomalies. Flags hours where score exceeds threshold.
// =============================================================================
SecurityEvent
| where TimeGenerated >= TimeFrom
| where Computer == TargetHost
| where EventID in (4624, 4625)
| extend Outcome = iff(EventID == 4624, "Success", "Failure")
| make-series Count = count() default=0 on TimeGenerated from TimeFrom to now() step HourBin by Outcome
| extend (Anomalies, Score, Baseline) = series_decompose_anomalies(Count, AnomalyThreshold, -1, "linefit")
| mv-expand TimeGenerated to typeof(datetime), Count to typeof(long), Anomalies to typeof(int), Score to typeof(double), Baseline to typeof(double)
| where Anomalies != 0
| project TimeGenerated, Outcome, Count, Baseline = round(Baseline,1), AnomalyScore = round(Score,2), Direction = case(Anomalies == 1, "SPIKE", Anomalies == -1, "DIP", "FLAT")
| order by TimeGenerated desc

// =============================================================================
// SECTION 2  -  Password Spray / Credential Stuffing Bursts
//   High failed-logon volume against many distinct accounts from one source IP,
//   followed by a successful logon to one of those accounts within 1h.
// =============================================================================
let Sprays =
    SecurityEvent
    | where TimeGenerated >= DetectionFrom
    | where Computer == TargetHost
    | where EventID == 4625
    | where isnotempty(IpAddress) and IpAddress !in ("-", "::1", "127.0.0.1")
    | summarize FailCount = count(),
                Users = make_set(TargetUserName, 100),
                DistinctUsers = dcount(TargetUserName),
                FirstFail = min(TimeGenerated),
                LastFail  = max(TimeGenerated)
              by IpAddress, bin(TimeGenerated, 1h)
    | where FailCount >= SprayFailMin and DistinctUsers >= SprayDistinctUsers;
let SuccessAfterSpray =
    SecurityEvent
    | where TimeGenerated >= DetectionFrom
    | where Computer == TargetHost
    | where EventID == 4624 and LogonType in (3, 10)        // Network or RemoteInteractive
    | project SuccessTime = TimeGenerated, SuccessUser = TargetUserName, SuccessIP = IpAddress, LogonType;
Sprays
| join kind=inner SuccessAfterSpray on $left.IpAddress == $right.SuccessIP
| where SuccessTime between (FirstFail .. (LastFail + 1h))
| project SprayWindow = TimeGenerated, IpAddress, FailCount, DistinctUsers, Users,
          CompromisedUser = SuccessUser, SuccessTime, LogonType
| order by SprayWindow desc

// =============================================================================
// SECTION 3  -  First-Seen Source IPs (New Entity Baselining)
//   IPs that authenticated successfully in detection window but never appeared
//   in baseline window. Excludes RFC1918 if you want to focus on external.
// =============================================================================
let BaselineIPs =
    SecurityEvent
    | where TimeGenerated between (BaselineFrom .. BaselineTo)
    | where Computer == TargetHost
    | where EventID == 4624
    | where isnotempty(IpAddress)
    | distinct IpAddress;
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4624
| where isnotempty(IpAddress) and IpAddress !in ("-", "::1", "127.0.0.1")
| where IpAddress !in (BaselineIPs)
| summarize FirstSeen = min(TimeGenerated),
            LastSeen  = max(TimeGenerated),
            LogonCount = count(),
            Users = make_set(TargetUserName, 25),
            LogonTypes = make_set(LogonType, 10)
          by IpAddress
| order by FirstSeen desc

// =============================================================================
// SECTION 4  -  Rare LogonTypes for the Host
//   Computes baseline distribution of LogonType values, flags any LogonType
//   in the detection window seen in less than RarePctCutoff% of baseline events.
// =============================================================================
let LogonTypeBaseline =
    SecurityEvent
    | where TimeGenerated between (BaselineFrom .. BaselineTo)
    | where Computer == TargetHost
    | where EventID == 4624
    | summarize TypeCount = count() by LogonType
    | extend TotalRows = toscalar(SecurityEvent | where TimeGenerated between (BaselineFrom .. BaselineTo) | where Computer == TargetHost | where EventID == 4624 | count)
    | extend Pct = todouble(TypeCount) / todouble(TotalRows) * 100.0
    | project LogonType, BaselinePct = round(Pct, 3);
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4624
| join kind=leftouter LogonTypeBaseline on LogonType
| extend BaselinePct = coalesce(BaselinePct, 0.0)
| where BaselinePct < RarePctCutoff
| project TimeGenerated, Account, TargetUserName, LogonType, IpAddress, WorkstationName, BaselinePct
| order by TimeGenerated desc

// =============================================================================
// SECTION 5  -  Off-Hours Interactive / RemoteInteractive Logons
//   Logon types 2 (Interactive) and 10 (RemoteInteractive) outside business
//   hours, excluding service / known maintenance accounts.
// =============================================================================
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4624
| where LogonType in (2, 10)
| where TargetUserName !endswith "$" and TargetUserName !startswith "svc_" and TargetUserName !in~ ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE","ANONYMOUS LOGON","DWM-1","UMFD-0","UMFD-1")
| extend HourLocal = datetime_part("Hour", TimeGenerated)
| where HourLocal >= OffHoursStart or HourLocal < OffHoursEnd
| project TimeGenerated, HourLocal, Account, TargetUserName, LogonType, IpAddress, WorkstationName, AuthenticationPackageName
| order by TimeGenerated desc

// =============================================================================
// SECTION 6  -  Suspicious Parent->Child Process Chains (Phishing Downstream)
//   4688 process creation where parent is an Office app, browser, or mail
//   client and child is a script/shell interpreter or LOLBin.
// =============================================================================
let SuspiciousParents = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mshta.exe","wscript.exe","cscript.exe","acrord32.exe","acrobat.exe","chrome.exe","msedge.exe","firefox.exe","thunderbird.exe"]);
let SuspiciousChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","wmic.exe","rundll32.exe","regsvr32.exe","mshta.exe","bitsadmin.exe","certutil.exe","installutil.exe","msiexec.exe","forfiles.exe","schtasks.exe","wuauclt.exe","ftp.exe"]);
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4688
| extend ParentName = tolower(tostring(split(ParentProcessName, "\\")[-1])),
         ChildName  = tolower(tostring(split(NewProcessName, "\\")[-1]))
| where ParentName in (SuspiciousParents) and ChildName in (SuspiciousChildren)
| project TimeGenerated, Account, ParentProcessName, NewProcessName, CommandLine, ProcessId, ParentProcessId
| order by TimeGenerated desc

// =============================================================================
// SECTION 7  -  Service Installation Anomalies (4697 + 7045 via SecurityEvent)
//   Compares service-name churn between baseline and detection. Any service
//   name installed in detection window that never appeared in baseline.
// =============================================================================
let BaselineServices =
    SecurityEvent
    | where TimeGenerated between (BaselineFrom .. BaselineTo)
    | where Computer == TargetHost
    | where EventID == 4697
    | distinct ServiceName;
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4697
| where ServiceName !in (BaselineServices)
| project TimeGenerated, Account, ServiceName, ServiceFileName, ServiceType, ServiceStartType
| order by TimeGenerated desc

// =============================================================================
// SECTION 8  -  Newly Created Scheduled Tasks (4698)
//   Same first-seen technique against scheduled tasks. The XML payload often
//   contains the actual command line; search it for LOLBins.
// =============================================================================
let BaselineTasks =
    SecurityEvent
    | where TimeGenerated between (BaselineFrom .. BaselineTo)
    | where Computer == TargetHost
    | where EventID == 4698
    | extend TaskName = tostring(parse_xml(EventData).EventXML.TaskName)
    | distinct TaskName;
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4698
| extend TaskName = tostring(parse_xml(EventData).EventXML.TaskName),
         TaskContent = tostring(parse_xml(EventData).EventXML.TaskContent)
| where TaskName !in (BaselineTasks)
| extend HasLolbin = TaskContent has_any ("powershell","cmd.exe","wscript","cscript","mshta","rundll32","regsvr32","bitsadmin","certutil")
| project TimeGenerated, Account, TaskName, HasLolbin, TaskContent
| order by TimeGenerated desc

// =============================================================================
// SECTION 9  -  PowerShell / WMIC Execution Rate Anomaly
//   Per-hour invocation count of powershell.exe and wmic.exe scored against
//   own baseline. Volt Typhoon style LOTL bursts pop here.
// =============================================================================
SecurityEvent
| where TimeGenerated >= TimeFrom
| where Computer == TargetHost
| where EventID == 4688
| extend ChildName = tolower(tostring(split(NewProcessName, "\\")[-1]))
| where ChildName in ("powershell.exe","pwsh.exe","wmic.exe")
| make-series InvocationCount = count() default=0 on TimeGenerated from TimeFrom to now() step HourBin by ChildName
| extend (Anomalies, Score, Baseline) = series_decompose_anomalies(InvocationCount, AnomalyThreshold, -1, "linefit")
| mv-expand TimeGenerated to typeof(datetime), InvocationCount to typeof(long), Anomalies to typeof(int), Score to typeof(double), Baseline to typeof(double)
| where Anomalies == 1
| project TimeGenerated, ChildName, InvocationCount, Baseline = round(Baseline,1), AnomalyScore = round(Score,2)
| order by TimeGenerated desc

// =============================================================================
// SECTION 10  -  Process Execution from Suspicious Paths
//   Binaries executing from world-writable / staging directories often used
//   by initial access payloads. Joins against baseline to suppress noise.
// =============================================================================
let SuspiciousPaths = dynamic([
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\perflogs\\",
    "\\$recycle.bin\\",
    "\\windows\\tasks\\",
    "\\windows\\debug\\"
]);
let BaselinePathExe =
    SecurityEvent
    | where TimeGenerated between (BaselineFrom .. BaselineTo)
    | where Computer == TargetHost
    | where EventID == 4688
    | extend NewProcLower = tolower(NewProcessName)
    | where NewProcLower has_any (SuspiciousPaths)
    | distinct NewProcLower;
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4688
| extend NewProcLower = tolower(NewProcessName)
| where NewProcLower has_any (SuspiciousPaths)
| where NewProcLower !in (BaselinePathExe)
| project TimeGenerated, Account, NewProcessName, ParentProcessName, CommandLine
| order by TimeGenerated desc

// =============================================================================
// SECTION 11  -  First-Seen Process Names per Host
//   Any executable name that fires in detection window but has zero baseline
//   prior. Effective against bespoke implants, renamed binaries, dropped tools.
// =============================================================================
let BaselineProcs =
    SecurityEvent
    | where TimeGenerated between (BaselineFrom .. BaselineTo)
    | where Computer == TargetHost
    | where EventID == 4688
    | extend ProcName = tolower(tostring(split(NewProcessName, "\\")[-1]))
    | distinct ProcName;
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4688
| extend ProcName = tolower(tostring(split(NewProcessName, "\\")[-1]))
| where ProcName !in (BaselineProcs)
| summarize FirstSeen = min(TimeGenerated),
            ExecCount = count(),
            Users = make_set(Account, 10),
            ParentSet = make_set(ParentProcessName, 10),
            SampleCmd = any(CommandLine)
          by ProcName, NewProcessName
| order by FirstSeen desc

// =============================================================================
// SECTION 12  -  Unusual Logon Process / Authentication Package Combinations
//   Any LogonProcessName + AuthenticationPackageName pair that did not exist
//   in baseline. Catches custom authentication providers and pass-the-hash
//   tooling that uses non-standard logon process names.
// =============================================================================
let BaselineAuth =
    SecurityEvent
    | where TimeGenerated between (BaselineFrom .. BaselineTo)
    | where Computer == TargetHost
    | where EventID == 4624
    | distinct LogonProcessName, AuthenticationPackageName;
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 4624
| join kind=leftanti BaselineAuth on LogonProcessName, AuthenticationPackageName
| project TimeGenerated, Account, TargetUserName, LogonProcessName, AuthenticationPackageName, LogonType, IpAddress
| order by TimeGenerated desc

// =============================================================================
// SECTION 13  -  Audit Log Cleared (1102)  -  classic post-IA cleanup
//   Not strictly anomaly-based but always relevant during initial access
//   investigation; correlate timestamps with sections 1-12.
// =============================================================================
SecurityEvent
| where TimeGenerated >= DetectionFrom
| where Computer == TargetHost
| where EventID == 1102
| project TimeGenerated, Account, Activity, EventData
| order by TimeGenerated desc

// =============================================================================
// END OF FILE
// =============================================================================
'@
    'Hunting Pack §1: Scan-based lateral movement (4624 -> 7045/4698)' = @'
// ================================================================
// 1. scan-based lateral movement detection
// ================================================================
// Pattern: successful logon (4624) followed by remote service creation
// (7045) or scheduled task (4698) on the SAME host within 10 minutes,
// by the SAME account. Classic "land and expand" signature.
// ================================================================

SecurityEvent
| where EventID in (4624, 7045, 4698)
| where TimeGenerated > ago(7d)
| sort by Computer asc, TimeGenerated asc
| scan declare (LogonTime:datetime, LogonAccount:string) with (
    step logon output=none:
        EventID == 4624 and LogonType in (3, 10)   // network / RDP
        => LogonTime = TimeGenerated,
           LogonAccount = Account;
    step payload:
        EventID in (7045, 4698)
        and Account == logon.LogonAccount
        and TimeGenerated - logon.LogonTime between (0s .. 10m);
  )
| project Computer, LogonAccount = logon.LogonAccount,
          LogonTime = logon.LogonTime,
          PayloadTime = TimeGenerated,
          PayloadEventID = EventID,
          Details = iff(EventID == 7045, ServiceName, TaskName)


// ================================================================
'@
    'Hunting Pack §2: Sysmon process autocluster (DeviceProcessEvents)' = @'
// ================================================================
// 2. autocluster — unsupervised triage of Sysmon process events
// ================================================================
// Point this at a noisy day of Sysmon EID 1 and it returns the
// dominant (Image, ParentImage, User, CommandLine-prefix) clusters
// ranked by coverage. Anything OUTSIDE the top clusters is your
// hunting surface.
// ================================================================

DeviceProcessEvents
| where TimeGenerated > ago(1d)
| extend CmdPrefix = substring(ProcessCommandLine, 0, 40)
| project DeviceName, AccountName, FileName, InitiatingProcessFileName, CmdPrefix
| evaluate autocluster(0.5, 3, 5)   // minRatio, minFeatures, maxFeatures


// ================================================================
'@
    'Hunting Pack §3: diffpatterns - incident vs baseline (DeviceNetworkEvents)' = @'
// ================================================================
// 3. diffpatterns — "what changed?" surface finder
// ================================================================
// Compare a known-good window to an incident window and get the
// attribute combos that differ most. Pure gold for IR triage.
// ================================================================

let incidentWindow = datetime_range(datetime(2026-04-06 14:00), datetime(2026-04-06 16:00));
DeviceNetworkEvents
| where TimeGenerated > ago(3d)
| extend Bucket = iff(TimeGenerated between (datetime(2026-04-06 14:00) .. datetime(2026-04-06 16:00)), "incident", "baseline")
| project Bucket, RemoteIP, RemotePort, InitiatingProcessFileName, ActionType
| evaluate diffpatterns(Bucket, "baseline", "incident")


// ================================================================
'@
}

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB5D01UHJ0Q2wlk
# 8X8ZSfmAta73f6K7FsoqbSZQq/YH46CCFlAwggMSMIIB+qADAgECAhAtZQe+Ow97
# nknyVZUnzOU8MA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFkJyeWNlIFNPQyBD
# b2RlIFNpZ25pbmcwHhcNMjYwNDI5MTcxNzUwWhcNMzEwNDI5MTcyNzUxWjAhMR8w
# HQYDVQQDDBZCcnljZSBTT0MgQ29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEA3Oe6H+5W3DedBqU2kgW2FbDpJxacLR8tKrO+UgnFWcfe
# JTWv1bxs20yw8WNVkt3oHEjsyk9MZwIjvTfZbtyobU7UU1dSKHPhZT0pBWPenuCf
# EHef25jHGma52Iiyoh06U5Tb51e0TQx7eMF4DQbxfNMZbLFZL1ZIN2/bMHLikeJj
# +nzz606QDzfFjlAA0liD1WlTiK7wFclEd6yY2GwSCWBSIn6ZeyfQvHPRHMgwjmfK
# AYRVEA9WkpSRaTnWX15QWjn1iHxEJ8IeS4274cU369gWsxgFIvKCVdb3I+5eMBcy
# n//v3SF8uhJ6OtJipttmpNAvyf10N/QOnWu4CDzL9QIDAQABo0YwRDAOBgNVHQ8B
# Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFOAL/6bNQwxH
# 3Ir4b9IWNhfKv0dtMA0GCSqGSIb3DQEBCwUAA4IBAQAAePrK/7n1mnXEVikJrfFG
# Hm+MNL6LwrJPt1bLNiZDkG4AUHm0nLiGgSJSe/YpAAbXAamxfJtEWyZI1je8z+TW
# Adle3BHKJ4fttXffhvNoXZjbdq0LQDwehEtHROC1j4pshXmF9Y3NyTfuR31u7Bqp
# HU+x0WBvdIyHcDO8cm8clnZobNM9ASRHj3i3Kb2Bsgz+txIkgeEvor7oTBO9ubMI
# a9+nw1WOGk9K/IukfinUTyrO7hVG14YP9SkuCj75G6SfO4t4GSe8qMbcpB0jdqNt
# lrx2N4LKVH0Xi2BzK9NcLFnprfS4oXmO1GsTDKXQyocHSAthXEGNUpE5HfKVz5dm
# MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBl
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
# b3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7J
# IT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxS
# D1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb
# 7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1ef
# VFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoY
# OAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSa
# M0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI
# 8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9L
# BADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfm
# Q6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDr
# McXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15Gkv
# mB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGL
# p6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0G
# CSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6p
# Grsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1W
# z/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp
# 8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglo
# hJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8S
# uFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQ
# DcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAw
# MDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaD
# LFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1
# +JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh
# /AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpL
# tlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8
# BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMv
# aB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL
# 6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/
# q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb
# 1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVF
# JfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+
# Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNq
# hCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLery
# cvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26M
# HvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjat
# VB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPS
# egOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI
# 7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4Y
# tL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/
# wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch
# 28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQ
# D7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAw
# MDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGlt
# ZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsL
# wOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYe
# sFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54d
# NApZfKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3Dj
# jANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJq
# LbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+EN
# TqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7kn
# h1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRt
# a6Eq4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klE
# TsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMF
# tNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IB
# lTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89h
# jOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQD
# AgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAC
# hlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBU
# oFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8Rwn
# BLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2
# JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnth
# fAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUP
# xAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ8
# 0FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4
# FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678Igmf
# ORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB
# 4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfc
# SYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i
# 71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Frogu
# zzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcxggURMIIFDQIBATA1MCExHzAdBgNV
# BAMMFkJyeWNlIFNPQyBDb2RlIFNpZ25pbmcCEC1lB747D3ueSfJVlSfM5TwwDQYJ
# YIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgHPL5utHWTqzr7w6nn38MTFvVuhJN65qZj0WLJU/i
# oL0wDQYJKoZIhvcNAQEBBQAEggEAYZLWv+b8r5F69wwCnAXjpm6l5dFXw24jpaih
# aUGCmV6MsLJgC0vyLPThMrIhPF5GLp3eCeGn02ZEML5AdwEtQnT47li80RbCKzZL
# xcEEctMMf9MaQ88KqbuzDcOT3euWm+IaGCzzEvmO1UVgZDedEYfvjfpzaUAzfDnt
# eSHnFRvZ/L2A9E1A8IYQGQiI5jKpSnjv+mr2L+g/rANGXmegAbAtTn+oc5loyvCx
# TXc30GbDmGoAdVcRs3wJb5++SqOyyGo+ksB5uIwRyA4eGVr9z3OqOIDNgl2wBSZM
# AgysoDLmAa67ZZENh/OmHHtAdpz8K2Ld31bvJ04gQnM3+udgPqGCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjA0MjkxNzI5MjdaMC8GCSqGSIb3DQEJBDEiBCCk4jfW
# qGelyl/u81RqBpBJFiuqT6cY9oHySuRlQsxtizANBgkqhkiG9w0BAQEFAASCAgDL
# OM1XmsQ6pGBkZ8W/1M47hT3xqO/yjjU5s7kXs/S6t5xSeV4DYoKvPKqwl25sMDt+
# hXf4tjkhJVoOUdpgqxxm3deGVsa+gEOaHi8xsQ5uYNfhv9PO6BX20K5CdGSg2sGK
# aFvLQHUmupEmbRAJ2274oou4tBppKc1JcTX2GGOd3aUqMesJE4tiNOyxuiwnVmDt
# aS1zIEOYFwOtc7cLEOz5L9EZvrKwSp6gWYB4NCqfYpXxA+E+XoiC87zSN74WGHdo
# gHq9ofVIcyJdeqRqhCgcFNGkOWQy6FSIx7S7X40lMrbi6wFhyDzSCD5zYyurkHFi
# 5TUF/znzlpEtQi2BiiKRESJTJzCS+OZnGpcdSHJb9wzAocaQxYFFdCy49pJw0Wts
# 2z1WG5VhHfgW14s7vD9dNkkf6AJBj64CjErqpGE1nXnHuKq97V7V0Gqgz6XMzvMZ
# 176HFCDryyzL7HRr08dMju1mDdy8O/f7IXUC9+zsgyZZUgd9PgGY+fSsAR7OZttE
# 0d8Y6/4AMnEf02d57vlbCZKU/dwQb4h3bOHGgu9nMLwD/qkner/RHswlnaoANpwa
# rqjoww4NhjnnA794OBO1Wjd2oC5ps4pFLXvuws3xU+wKKadyumvAEl5ZQmRG4AA0
# hs+b709dNKeXCWYEE/34ZE9VrM5/7he8GBTgmEFU0w==
# SIG # End signature block
