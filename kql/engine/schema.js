/* schema.js - column type definitions for the lab tables.
 *
 * Each table is defined as { columns: [ { name, type } ] }.
 * Types map to SQLite affinities:
 *   string  -> TEXT
 *   int     -> INTEGER
 *   long    -> INTEGER
 *   real    -> REAL
 *   bool    -> INTEGER (0/1)
 *   datetime -> TEXT (ISO 8601, queries via datetime() / SQLite date funcs)
 *   dynamic -> TEXT (raw JSON)
 *
 * Column names match the CSV headers exactly. Order matters for the SQL
 * INSERT statements that the runtime generates.
 *
 * Schema flavor: these tables model the **Sentinel-projected** view of
 * Microsoft Defender XDR data, not raw Defender XDR Advanced Hunting.
 * Practical implications:
 *   - Defender tables (Device*) carry BOTH `Timestamp` and `TimeGenerated`.
 *     `Timestamp`     = when the event happened (Defender XDR canonical).
 *     `TimeGenerated` = when Log Analytics ingested the row (Sentinel side).
 *     Microsoft documents this dual-column reality and notes the two can
 *     diverge if data arrives late:
 *     https://learn.microsoft.com/defender-xdr/advanced-hunting-microsoft-defender#known-issues
 *     Cheatsheet/practice questions consistently use `TimeGenerated` for the
 *     filter-by-time pattern, matching the Sentinel idiom.
 *   - `DeviceLogonEvents.ActionType` (LogonSuccess / LogonFailed / ...) AND
 *     `LogonType` (Interactive / Network / ...) are both real Defender columns.
 *     They describe different things and both exist on the live table.
 */

(function (global) {
    'use strict';

    var T = function (n, t) { return { name: n, type: t }; };

    var Schema = {
        AuditLogs: { columns: [
            T('TimeGenerated', 'datetime'), T('OperationName', 'string'), T('Category', 'string'),
            T('Result', 'string'), T('ResultReason', 'string'), T('ResultDescription', 'string'),
            T('ActivityDisplayName', 'string'), T('ActivityDateTime', 'datetime'), T('AADOperationType', 'string'),
            T('Identity', 'string'), T('InitiatedBy', 'string'), T('TargetResources', 'dynamic'),
            T('LoggedByService', 'string'), T('Type', 'string'),
        ]},
        CommonSecurityLog: { columns: [
            T('TimeGenerated', 'datetime'), T('DeviceVendor', 'string'), T('DeviceProduct', 'string'),
            T('DeviceVersion', 'string'), T('DeviceEventClassID', 'string'), T('Activity', 'string'),
            T('LogSeverity', 'int'), T('DeviceAction', 'string'), T('ApplicationProtocol', 'string'),
            T('SourceIP', 'string'), T('SourcePort', 'int'), T('DestinationIP', 'string'),
            T('DestinationPort', 'int'), T('Protocol', 'string'), T('SimplifiedDeviceAction', 'string'),
            T('Computer', 'string'), T('Type', 'string'),
        ]},
        DHCP: { columns: [
            T('TimeGenerated', 'datetime'), T('ID', 'string'), T('Date', 'string'), T('Time', 'string'),
            T('Description', 'string'), T('IP', 'string'), T('HostName', 'string'), T('MAC', 'string'),
            T('User', 'string'), T('TransactionID', 'string'), T('QResult', 'string'),
            T('VendorClass', 'string'), T('Type', 'string'),
        ]},
        DeviceFileEvents: { columns: [
            T('TimeGenerated', 'datetime'), T('Timestamp', 'datetime'), T('DeviceName', 'string'),
            T('ActionType', 'string'), T('FileName', 'string'), T('FolderPath', 'string'),
            T('SHA256', 'string'), T('SHA1', 'string'), T('MD5', 'string'), T('FileSize', 'long'),
            T('InitiatingProcessFileName', 'string'), T('InitiatingProcessAccountName', 'string'),
            T('InitiatingProcessCommandLine', 'string'), T('Type', 'string'),
        ]},
        DeviceImageLoadEvents: { columns: [
            T('TimeGenerated', 'datetime'), T('Timestamp', 'datetime'), T('DeviceName', 'string'),
            T('FileName', 'string'), T('FolderPath', 'string'), T('SHA256', 'string'),
            T('InitiatingProcessFileName', 'string'), T('InitiatingProcessFolderPath', 'string'),
            T('Type', 'string'),
        ]},
        DeviceLogonEvents: { columns: [
            T('TimeGenerated', 'datetime'), T('Timestamp', 'datetime'), T('DeviceName', 'string'),
            T('ActionType', 'string'), T('AccountName', 'string'), T('AccountDomain', 'string'),
            T('AccountSid', 'string'), T('LogonType', 'string'), T('FailureReason', 'string'),
            T('IsLocalAdmin', 'bool'), T('LogonId', 'string'), T('RemoteIP', 'string'),
            T('RemoteIPType', 'string'), T('RemotePort', 'int'), T('Protocol', 'string'),
            T('InitiatingProcessFileName', 'string'), T('InitiatingProcessAccountName', 'string'),
            T('Type', 'string'),
        ]},
        DeviceNetworkEvents: { columns: [
            T('TimeGenerated', 'datetime'), T('Timestamp', 'datetime'), T('DeviceName', 'string'),
            T('ActionType', 'string'), T('LocalIP', 'string'), T('LocalIPType', 'string'),
            T('LocalPort', 'int'), T('RemoteIP', 'string'), T('RemoteIPType', 'string'),
            T('RemotePort', 'int'), T('RemoteUrl', 'string'), T('Protocol', 'string'),
            T('InitiatingProcessFileName', 'string'), T('InitiatingProcessFolderPath', 'string'),
            T('InitiatingProcessCommandLine', 'string'), T('InitiatingProcessAccountName', 'string'),
            T('InitiatingProcessSHA256', 'string'), T('Type', 'string'),
        ]},
        DeviceNetworkInfo: { columns: [
            T('TimeGenerated', 'datetime'), T('Timestamp', 'datetime'), T('DeviceName', 'string'),
            T('DeviceId', 'string'), T('MacAddress', 'string'), T('IPAddresses', 'string'),
            T('DnsAddresses', 'string'), T('DefaultGateways', 'string'), T('ConnectedNetworks', 'string'),
            T('NetworkAdapterName', 'string'), T('NetworkAdapterStatus', 'string'),
            T('NetworkAdapterType', 'string'), T('Type', 'string'),
        ]},
        DeviceProcessEvents: { columns: [
            T('TimeGenerated', 'datetime'), T('Timestamp', 'datetime'), T('DeviceName', 'string'),
            T('DeviceId', 'string'), T('AccountName', 'string'), T('AccountDomain', 'string'),
            T('FileName', 'string'), T('FolderPath', 'string'), T('ProcessCommandLine', 'string'),
            T('ProcessId', 'long'), T('SHA256', 'string'), T('SHA1', 'string'), T('MD5', 'string'),
            T('FileSize', 'long'), T('InitiatingProcessFileName', 'string'),
            T('InitiatingProcessFolderPath', 'string'), T('InitiatingProcessCommandLine', 'string'),
            T('InitiatingProcessId', 'long'), T('InitiatingProcessAccountName', 'string'),
            T('InitiatingProcessSHA256', 'string'), T('InitiatingProcessSignatureStatus', 'string'),
            T('InitiatingProcessSignerType', 'string'), T('ProcessIntegrityLevel', 'string'),
            T('ProcessTokenElevation', 'string'), T('Type', 'string'),
        ]},
        DeviceRegistryEvents: { columns: [
            T('TimeGenerated', 'datetime'), T('Timestamp', 'datetime'), T('DeviceName', 'string'),
            T('ActionType', 'string'), T('RegistryKey', 'string'), T('RegistryValueName', 'string'),
            T('RegistryValueData', 'string'), T('RegistryValueType', 'string'),
            T('InitiatingProcessFileName', 'string'), T('InitiatingProcessAccountName', 'string'),
            T('InitiatingProcessCommandLine', 'string'), T('Type', 'string'),
        ]},
        SecurityAlert: { columns: [
            T('TimeGenerated', 'datetime'), T('DisplayName', 'string'), T('AlertName', 'string'),
            T('AlertSeverity', 'string'), T('Description', 'string'), T('ProviderName', 'string'),
            T('VendorName', 'string'), T('ProductName', 'string'), T('SystemAlertId', 'string'),
            T('AlertType', 'string'), T('Status', 'string'), T('ConfidenceLevel', 'string'),
            T('ConfidenceScore', 'real'), T('IsIncident', 'bool'), T('StartTime', 'datetime'),
            T('EndTime', 'datetime'), T('Entities', 'dynamic'), T('Tactics', 'string'),
            T('Techniques', 'string'), T('ProcessingEndTime', 'datetime'), T('Type', 'string'),
        ]},
        SecurityEvent: { columns: [
            T('TimeGenerated', 'datetime'), T('Computer', 'string'), T('EventID', 'int'),
            T('Activity', 'string'), T('Account', 'string'), T('AccountType', 'string'),
            T('AccountDomain', 'string'), T('AccountName', 'string'), T('TargetUserName', 'string'),
            T('TargetDomainName', 'string'), T('IpAddress', 'string'), T('IpPort', 'int'),
            T('LogonType', 'string'), T('LogonProcessName', 'string'), T('FailureReason', 'string'),
            T('ProcessName', 'string'), T('NewProcessName', 'string'), T('ParentProcessName', 'string'),
            T('CommandLine', 'string'), T('ServiceName', 'string'), T('ServiceFileName', 'string'),
            T('EventSourceName', 'string'), T('Channel', 'string'), T('Type', 'string'),
        ]},
        SecurityIncident: { columns: [
            T('TimeGenerated', 'datetime'), T('IncidentNumber', 'string'), T('Title', 'string'),
            T('Description', 'string'), T('Severity', 'string'), T('Status', 'string'),
            T('Classification', 'string'), T('ClassificationReason', 'string'),
            T('FirstActivityTime', 'datetime'), T('LastActivityTime', 'datetime'),
            T('FirstModifiedTime', 'datetime'), T('LastModifiedTime', 'datetime'),
            T('CreatedTime', 'datetime'), T('AlertIds', 'dynamic'), T('ModifiedBy', 'string'),
            T('Type', 'string'),
        ]},
        SigninLogs: { columns: [
            T('TimeGenerated', 'datetime'), T('UserPrincipalName', 'string'),
            T('UserDisplayName', 'string'), T('UserId', 'string'), T('IPAddress', 'string'),
            T('AppDisplayName', 'string'), T('AppId', 'string'), T('ClientAppUsed', 'string'),
            T('ResultType', 'int'), T('ResultDescription', 'string'),
            T('ConditionalAccessStatus', 'string'), T('IsRisky', 'bool'),
            T('RiskLevelDuringSignIn', 'string'), T('RiskState', 'string'),
            T('RiskEventTypes', 'string'), T('LocationDetails', 'dynamic'),
            T('DeviceDetail', 'dynamic'), T('AuthenticationRequirement', 'string'),
            T('IsInteractive', 'bool'), T('UserAgent', 'string'), T('Type', 'string'),
        ]},
        Syslog: { columns: [
            T('TimeGenerated', 'datetime'), T('EventTime', 'datetime'), T('Computer', 'string'),
            T('HostName', 'string'), T('HostIP', 'string'), T('Facility', 'string'),
            T('SeverityLevel', 'string'), T('ProcessName', 'string'), T('ProcessID', 'long'),
            T('SyslogMessage', 'string'), T('CollectorHostName', 'string'), T('Type', 'string'),
        ]},
        W3CIISLog: { columns: [
            T('TimeGenerated', 'datetime'), T('Date', 'string'), T('Time', 'string'),
            T('sSiteName', 'string'), T('sComputerName', 'string'), T('sIP', 'string'),
            T('csMethod', 'string'), T('csUriStem', 'string'), T('csUriQuery', 'string'),
            T('sPort', 'int'), T('csUserName', 'string'), T('cIP', 'string'),
            T('csUserAgent', 'string'), T('scStatus', 'int'), T('scSubStatus', 'int'),
            T('scWin32Status', 'int'), T('scBytes', 'long'), T('csBytes', 'long'),
            T('TimeTaken', 'long'), T('Computer', 'string'), T('Type', 'string'),
        ]},
    };

    // Map of KQL types -> SQLite column affinity.
    var sqliteType = function (kqlType) {
        switch (kqlType) {
            case 'int': case 'long': case 'bool': return 'INTEGER';
            case 'real': return 'REAL';
            default: return 'TEXT';
        }
    };

    Schema.sqliteType = sqliteType;
    Schema.tableNames = function () { return Object.keys(Schema).filter(function (k) {
        return typeof Schema[k] === 'object' && Schema[k].columns;
    }); };

    global.KqlSchema = Schema;

})(window);
