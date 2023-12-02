# Configuration Definition
Configuration CIS_WindowsServer2016_v200 {
   param ( [string[]]$NodeName ='localhost' )

   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'
   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

   Node $NodeName {

      # -------------------------------------------------------------------------------------------------------------------------------------------
      # 1. Account Policy

      AccountPolicy AccountPolicies {

         Name = 'PasswordPolicies'

         # 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
         Minimum_Password_Length = 14

         # 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'
         Account_lockout_threshold = 5

      }

      # -------------------------------------------------------------------------------------------------------------------------------------------
      # 2. Local Policy

      #  2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
      UserRightsAssignment AccessCredentialManagerasatrustedcaller {
         Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
         Identity     = ''
      }

      #  2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)
      UserRightsAssignment Accessthiscomputerfromthenetwork {
         Policy       = 'Access_this_computer_from_the_network'
         Identity     = 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
      }


      # 2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
      UserRightsAssignment Actaspartoftheoperatingsystem {
         Policy       = 'Act_as_part_of_the_operating_system'
         Identity     = ''
      }

     #  2.2.5 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
      UserRightsAssignment Addworkstationstodomain {
         Policy       = 'Add_workstations_to_domain'
         Identity     = 'Administrators'
      }

     #  2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
     UserRightsAssignment Adjustmemoryquotasforaprocess {
        Policy       = 'Adjust_memory_quotas_for_a_process'
        Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
     }

     #  2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'
      UserRightsAssignment Allowlogonlocally {
         Policy       = 'Allow_log_on_locally'
         Identity     = 'Administrators'
      }

     #  2.2.8 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)
      UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
         Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
         Identity     = 'Administrators'
      }

     #  2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
      UserRightsAssignment Backupfilesanddirectories {
         Policy       = 'Back_up_files_and_directories'
         Identity     = 'Administrators'
      }

     #  2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
      UserRightsAssignment Changethesystemtime {
         Policy       = 'Change_the_system_time'
         Identity     = 'Administrators, LOCAL SERVICE'
      }

     #  2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
      UserRightsAssignment Changethetimezone {
         Policy       = 'Change_the_time_zone'
         Identity     = 'Administrators, LOCAL SERVICE'
      }

     #  2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
      UserRightsAssignment Createapagefile {
         Policy       = 'Create_a_pagefile'
         Identity     = 'Administrators'
      }

     #  2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'
      UserRightsAssignment Createatokenobject {
         Policy       = 'Create_a_token_object'
         Identity     = ''
      }

     #  2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
      UserRightsAssignment Createglobalobjects {
         Policy       = 'Create_global_objects'
         Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
      }

     #  2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
      UserRightsAssignment Createpermanentsharedobjects {
         Policy       = 'Create_permanent_shared_objects'
         Identity     = ''
      }

     #  2.2.17 (L1) Ensure 'Create symbolic links' is set to 'Administrators' (DC only)
      UserRightsAssignment Createsymboliclinks {
         Policy       = 'Create_symbolic_links'
         Identity     = 'Administrators'
      }

     #  2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'
      UserRightsAssignment Debugprograms {
         Policy       = 'Debug_programs'
         Identity     = 'Administrators'
      }

     #  2.2.21 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account and member of Administrators group' (MS only)
      UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
         Policy       = 'Deny_access_to_this_computer_from_the_network'
         Identity     = 'Guests, Local account, Administrators'
      }

     #  2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
      UserRightsAssignment Denylogonasabatchjob {
         Policy       = 'Deny_log_on_as_a_batch_job'
         Identity     = 'Guests'
      }

     #  2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'
      UserRightsAssignment Denylogonasaservice {
         Policy       = 'Deny_log_on_as_a_service'
         Identity     = 'Guests'
      }

     #  2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'
      UserRightsAssignment Denylogonlocally {
         Policy       = 'Deny_log_on_locally'
         Identity     = 'Guests'
      }

     # 2.2.25 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests' (DC only)
      UserRightsAssignment DenylogonthroughRemoteDesktopServices {
         Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
         Identity     = 'Guests'
      }

      # 2.2.27 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)
      UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
         Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         Identity     = 'Administrators'
      }


     #  2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
      UserRightsAssignment Forceshutdownfromaremotesystem {
         Policy       = 'Force_shutdown_from_a_remote_system'
         Identity     = 'Administrators'
      }

     #  2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
      UserRightsAssignment Generatesecurityaudits {
         Policy       = 'Generate_security_audits'
         Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
      }

     #  2.2.31 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (DC only)
      UserRightsAssignment Impersonateaclientafterauthentication {
         Policy       = 'Impersonate_a_client_after_authentication'
         Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
      }

     #  2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
      UserRightsAssignment Restorefilesanddirectories {
         Policy       = 'Restore_files_and_directories'
         Identity     = 'Administrators'
      }

     #  2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'
      UserRightsAssignment Shutdownthesystem {
         Policy       = 'Shut_down_the_system'
         Identity     = 'Administrators'
      }


      SecurityOption AccountSecurityOptions {
         Name                                   = 'AccountSecurityOptions'

         # 2.3.1.1 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
         Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts'

         # 2.3.1.3 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
         Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

         # 2.3.1.4 (L1) Configure 'Accounts: Rename administrator account'
         Accounts_Rename_administrator_account = 'User_Adm' # WARNING! Any value different from Administrator

         # 2.3.1.5 (L1) Configure 'Accounts: Rename guest account'
         Accounts_Rename_guest_account = 'User_Guest' # WARNING! Any value different from Guest

         # 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
         Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'

         # 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
         Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'

         # 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
         Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'

         # 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
         Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'

         # 2.3.5.1 (L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)
         Domain_controller_Allow_server_operators_to_schedule_tasks = 'Disabled'

         # 2.3.5.4 (L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require Signature' (DC only) 
         Domain_controller_LDAP_server_signing_requirements = 'Require Signature'

         # 2.3.5.5 (L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only) 
         Domain_controller_Refuse_machine_account_password_changes = 'Disabled'

         # 2.3.7.1 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
         Interactive_logon_Do_not_display_last_user_name = 'Enabled' 

         # 2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
         Interactive_logon_Machine_inactivity_limit = '900' 

         # 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on' 
         Interactive_logon_Message_text_for_users_attempting_to_log_on = 'This computer system is the property of Acme Corporation and is for authorised use by employees and designated contractors only. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.It is the users responsibility to LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this notice.'

         # 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
         Interactive_logon_Message_title_for_users_attempting_to_log_on = 'Logon Warning'

         # 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
         Interactive_logon_Smart_card_removal_behavior = 'Lock Workstation'

         # 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

         # 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

         # 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'

         # 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)
         Network_access_Named_Pipes_that_can_be_accessed_anonymously = ''

         # 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
         Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'

         # 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' 
         Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'

         # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' 
         Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'

         # 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
         Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE'

         # 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' 
         Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'

         # 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
         Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM' 

         # 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'

         # 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked' 

         # 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
         User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'

         # 2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'

         # 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'

      }


      # -------------------------------------------------------------------------------------------------------------------------------------------
      # 9. Windows Defender Firewall with Advanced Security

      
      #  9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
           ValueName   = 'EnableFirewall'
           ValueType   = 'DWord'
           ValueData   = '1'
       }

       #  9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
       Registry 'DefaultInboundActionDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
           ValueName   = 'DefaultInboundAction'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       #  9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
           ValueName   = 'DefaultOutboundAction'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       # 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
           ValueName   = 'DisableNotifications'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       # 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
       Registry 'LogFilePathDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
           ValueName   = 'LogFilePath'
           ValueType   = 'String'
           ValueData   = '%windir%\system32\logfiles\firewall\domainfirewall.log'
       }

       # 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizeDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
           ValueName   = 'LogFileSize'
           ValueType   = 'DWord'
           ValueData   = '16384'
       }

       #  9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
       Registry 'DefaultInboundActionPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DefaultInboundAction'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DefaultOutboundAction'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DisableNotifications'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'
       Registry 'LogFilePathPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogFilePath'
          ValueType    = 'String'
          ValueData    = '%windir%\system32\logfiles\firewall\privatefirewall.log'
       }

       #  9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizePrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogFileSize'
          ValueType    = 'DWord'
          ValueData    = '16384'
       }

       #  9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
       Registry 'DefaultInboundActionPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DefaultInboundAction'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DefaultOutboundAction'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DisableNotifications'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
       Registry 'AllowLocalPolicyMerge' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'AllowLocalPolicyMerge'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
       Registry 'AllowLocalIPsecPolicyMerge' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'AllowLocalIPsecPolicyMerge'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
       Registry 'LogFilePathPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogFilePath'
          ValueType    = 'String'
          ValueData    = '%windir%\system32\logfiles\firewall\publicfirewall.log'
       }

       #  9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizePublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogFileSize'
          ValueType    = 'Dword'
          ValueData    = '16384'
       }

       #  9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }



      # -------------------------------------------------------------------------------------------------------------------------------------------
      # 17. Advanced Audit Policy Configuration


      # 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
      AuditPolicySubcategory "Audit Credential Validation (Success)" {
         Name      = 'Credential Validation'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Credential Validation (Failure)' {
         Name      = 'Credential Validation'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      # 17.1.2 (L1) Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'
      AuditPolicySubcategory "Audit Kerberos Authentication Service (Success)" {
         Name      = 'Kerberos Authentication Service'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Kerberos Authentication Service (Failure)' {
         Name      = 'Kerberos Authentication Service'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }


      # 17.1.3 (L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'
      AuditPolicySubcategory "Audit Kerberos Service Ticket Operations (Success)" {
         Name      = 'Kerberos Service Ticket Operations'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Kerberos Service Ticket Operations (Failure)' {
         Name      = 'Kerberos Service Ticket Operations'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }


      # 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Application Group Management (Success)' {
         Name      = 'Application Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Application Group Management (Failure)' {
         Name      = 'Application Group Management'    
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      # 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Computer Account Management (Failure)' {
         Name      = 'Computer Account Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'      
      }

      AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
         Name      = 'Computer Account Management'
         Ensure    = 'Present'   
         AuditFlag = 'Success'      
      }

       # 17.2.3 (L1) Ensure 'Audit Distribution Group Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit Distribution Group Management (Success)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      # 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit Other Account Management Events (Success)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
         }

      # 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
         Name      = 'Security Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit Security Group Management (Success)' {
         Name      = 'Security Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      # 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit User Account Management (Failure)' {
         Name      = 'User Account Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit User Account Management (Success)' {
         Name      = 'User Account Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      # 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to 'Success' 
      AuditPolicySubcategory 'Audit PNP Activity (Success)' {
         Name      = 'Plug and Play Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit PNP Activity (Failure)' {
         Name      = 'Plug and Play Events'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }

      # 17.3.2 (L1) Ensure 'Audit Process Creation' is set to 'Success'
      AuditPolicySubcategory 'Audit Process Creation (Success)' {
         Name      = 'Process Creation'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Process Creation (Failure)' {
         Name      = 'Process Creation'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }

        # 17.4.1 (L1) Ensure 'Audit Directory Service Access' is set to 'Success and Failure' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Access (Success)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Access (Failure)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.4.2 (L1) Ensure 'Audit Directory Service Changes' is set to 'Success and Failure' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Changes (Success)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Changes (Failure)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.2 (L1) Ensure 'Audit Group Membership' is set to 'Success'
        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Group Membership (Failure)' {
            Name      = 'Group Membership'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
            }
        
        # 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
        AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Logoff'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure)' {
            Name      = 'Logoff'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
        AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Special Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure)' {
            Name      = 'Special Logon'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
      # 17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'
      AuditPolicySubcategory 'Audit Detailed File Share (Success)' {
         Name      = 'Detailed File Share'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Detailed File Share (Failure)' {
         Name      = 'Detailed File Share'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }


      # 17.6.2 (L1) Ensure 'Audit File Share' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit File Share (Success)' {
         Name      = 'File Share'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit File Share (Failure)' {
         Name      = 'File Share'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      # 17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
         Name      = 'Other Object Access Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
         Name      = 'Other Object Access Events'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }
        
      # 17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Removable Storage (Success)' {
         Name      = 'Removable Storage'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
         Name      = 'Removable Storage'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      # 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Policy Change (Success)' {
         Name      = 'Audit Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Policy Change (Failure)' {
         Name      = 'Audit Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      # 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'
      AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
         Name      = 'Authentication Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Authentication Policy Change (Failure)' {
         Name      = 'Authentication Policy Change'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }
        
      # 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
      AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' {
         Name      = 'Authorization Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit Authorization Policy Change (Failure)' {
         Name      = 'Authorization Policy Change'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }


      # 17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)' {
         Name      = 'MPSSVC Rule-Level Policy Change'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
         Name      = 'MPSSVC Rule-Level Policy Change'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }

      # 17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'
      AuditPolicySubcategory 'Audit Other Policy Change Events (Success)' {
         Name      = 'Other Policy Change Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

      AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
         Name      = 'Other Policy Change Events'
         Ensure    = 'Absent'
         AuditFlag = 'Failure'
      }

        
      # 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
      AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
         Name      = 'Sensitive Privilege Use'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
      }

      AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
         Name      = 'Sensitive Privilege Use'
         Ensure    = 'Present'
         AuditFlag = 'Success'
      }

        # 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit IPsec Driver (Failure)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit IPsec Driver (Success)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other System Events (Failure)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other System Events (Success)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
            Name      = 'Security State Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Security State Change (Failure)' {
            Name      = 'Security State Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
       


      # -------------------------------------------------------------------------------------------------------------------------------------------
      # 18. Administrative Templates (Computer)

      # 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
      Registry 'NoLockScreenCamera' {
         Ensure      = 'Present'
         Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
         ValueName   = 'NoLockScreenCamera' 
         ValueType   = 'DWord' 
         ValueData   = '1' 
      }

       #  18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
       Registry 'NoLockScreenSlideshow' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
          ValueName    = 'NoLockScreenSlideshow'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled' 
       Registry 'AllowInputPersonalization' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization'
          ValueName    = 'AllowInputPersonalization'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       # 18.4.2 (L1) Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
       Registry 'RpcAuthnLevelPrivacyEnabled' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print'
         ValueName    = 'RpcAuthnLevelPrivacyEnabled'
         ValueType    = 'DWord'
         ValueData    = '1'
       }

       #  18.4.3 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'
       Registry 'Start' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10'
          ValueName    = 'Start'
          ValueType    = 'DWord'
          ValueData    = '4'
       }

       #  18.4.4 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'
       Registry 'SMB1' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
          ValueName    = 'SMB1'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       # 18.4.6 (L1) Ensure 'LSA Protection' is set to 'Enabled'
       Registry 'RunAsPPL' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
         ValueName    = 'RunAsPPL'
         ValueType    = 'DWord'
         ValueData    = '1'
      }

       #  18.4.7 (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'
       Registry 'NodeType' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
          ValueName    = 'NodeType'
          ValueType    = 'DWord'
          ValueData    = '1'
       }


       #  18.4.8 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
       Registry 'UseLogonCredential' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
          ValueName    = 'UseLogonCredential'
          ValueType    = 'DWord'
          ValueData    = '0'
       }


       #  18.5.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
       Registry 'DisableIPSourceRouting' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
          ValueName    = 'DisableIPSourceRouting'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  18.5.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
       Registry 'DisableIPSourceRouting2' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'DisableIPSourceRouting'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  18.5.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
       Registry 'EnableICMPRedirect' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'EnableICMPRedirect'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled
       Registry 'NoNameReleaseOnDemand' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
          ValueName    = 'NoNameReleaseOnDemand'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.5.8 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
       Registry 'SafeDllSearchMode' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager'
          ValueName    = 'SafeDllSearchMode'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.5.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
       Registry 'ScreenSaverGracePeriod' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon'
          ValueName    = 'ScreenSaverGracePeriod'
          ValueType    = 'String'
          ValueData    = '5'
       }


       #  18.5.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
       Registry 'WarningLevel' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
          ValueName    = 'WarningLevel'
          ValueType    = 'DWord'
          ValueData    = '90'
       }

       #  18.6.4.1 (L1) Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'
       Registry 'EnableNetbios' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\DNSClient'
          ValueName    = 'EnableNetbios'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.6.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'
       Registry 'EnableMulticast' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\DNSClient'
          ValueName    = 'EnableMulticast'
          ValueType    = 'DWord'
          ValueData    = '0'
       }


       #  18.6.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
       Registry 'AllowInsecureGuestAuth' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
          ValueName    = 'AllowInsecureGuestAuth'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       
       #  18.6.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
       Registry 'NC_AllowNetBridge_NLA' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_AllowNetBridge_NLA'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.6.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
       Registry 'NC_ShowSharedAccessUI' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_ShowSharedAccessUI'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.6.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
       Registry 'NC_StdDomainUserSetLocation' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_StdDomainUserSetLocation'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.6.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
       Registry '\\*\NETLOGON' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueName    = '\\*\NETLOGON'
          ValueType    = 'String'
          ValueData    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
       }

       #  18.6.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
       Registry '\\*\SYSVOL' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueName    = '\\*\SYSVOL'
          ValueType    = 'String'
          ValueData    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
       }


       #  18.6.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 1 = Minimize simultaneous connections'
       Registry 'fMinimizeConnections' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
          ValueName  = 'fMinimizeConnections'
          ValueType  = 'DWord'
          ValueData  = '1'
       }
       

       #  18.9.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Enabled'
       Registry 'ProcessCreationIncludeCmdLine_Enabled' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
          ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       # 18.9.4.1 (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'
       Registry 'AllowEncryptionOracle' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
         ValueName  = 'AllowEncryptionOracle'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

       #  18.9.4.2 (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'
       Registry 'AllowProtectedCreds' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
          ValueName  = 'AllowProtectedCreds'
          ValueType  = 'DWord'
          ValueData  = '1'
       }


       # 18.9.7.2 (L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'
       Registry 'PreventDeviceMetadataFromNetwork' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceMetadata'
         ValueName  = 'PreventDeviceMetadataFromNetwork'
         ValueType  = 'DWord'
         ValueData  = '1'
      }


       #  18.9.13.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
       Registry 'DriverLoadPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
          ValueName  = 'DriverLoadPolicy'
          ValueType  = 'DWord'
          ValueData  = '3'
       }

       #  18.9.19.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
       Registry 'NoBackgroundPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueName  = 'NoBackgroundPolicy'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.19.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
       Registry 'NoGPOListChanges' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueName  = 'NoGPOListChanges'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.19.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'
       Registry 'EnableCdp' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'EnableCdp'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.20.1.1 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
       Registry 'DisableWebPnPDownload' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
          ValueName  = 'DisableWebPnPDownload'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.20.1.5 (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
       Registry 'NoWebServices' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoWebServices'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.27.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled'
       Registry 'BlockUserFromShowingAccountDetailsOnSignin' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'BlockUserFromShowingAccountDetailsOnSignin'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.27.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled'
       Registry 'DontDisplayNetworkSelectionUI' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DontDisplayNetworkSelectionUI'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.27.3 (L1) Ensure 'Do not enumerate connected users on domainjoined computers' is set to 'Enabled'
       Registry 'DontEnumerateConnectedUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DontEnumerateConnectedUsers'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.27.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
       Registry 'DisableLockScreenAppNotifications' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DisableLockScreenAppNotifications'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.27.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'
       Registry 'BlockDomainPicturePassword' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'BlockDomainPicturePassword'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.27.7 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
       Registry 'AllowDomainPINLogon' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'AllowDomainPINLogon'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.32.6.3 (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
       Registry 'DCSettingIndex2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51'
          ValueName  = 'DCSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.32.6.4 (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
       Registry 'ACSettingIndex2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51'
          ValueName  = 'ACSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '1'
       }



       #  18.9.34.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
       Registry 'fAllowUnsolicited' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fAllowUnsolicited'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.34.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
       Registry 'fAllowToGetHelp' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fAllowToGetHelp'
          ValueType  = 'DWord'
          ValueData  = '0'
       }


       #  18.10.5.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
       Registry 'MSAOptional' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'MSAOptional'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.10.7.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
       Registry 'NoAutoplayfornonVolume' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoAutoplayfornonVolume'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.10.7.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
       Registry 'NoAutorun' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoAutorun'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.10.7.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
       Registry 'NoDriveTypeAutoRun' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoDriveTypeAutoRun'
          ValueType  = 'DWord'
          ValueData  = '255'
       }
       
       #  18.10.8.1.1 (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'
       Registry 'EnhancedAntiSpoofing' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics\FacialFeatures'
          ValueName  = 'EnhancedAntiSpoofing'
          ValueType  = 'DWord'
          ValueData  = '1'
       }



      # -------------------------------------------------------------------------------------------------------------------------------------------
      # 19. Administrative Templates (User)

      # 19.1.3.1 (L1) Ensure 'Enable screen saver' is set to 'Enabled'
      Registry 'ScreenSaveActive' {
         Ensure      = 'Present'
         Key         = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
         ValueName   = 'ScreenSaveActive'
         ValueType   = 'String'
         ValueData   = '1'
      }

       #  19.1.3.2 (L1) Ensure 'Password protect the screen saver' is set to 'Enabled'
       Registry 'ScreenSaverIsSecure' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'ScreenSaverIsSecure'
          ValueType    = 'String'
          ValueData    = '1'
       }

       #  19.1.3.3 (L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
       Registry 'ScreenSaveTimeOut' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'ScreenSaveTimeOut'
          ValueType    = 'DWord'
          ValueData    = '900'
       }

       #  19.5.1.1 (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
       Registry 'NoToastApplicationNotificationOnLockScreen' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
          ValueName    = 'NoToastApplicationNotificationOnLockScreen'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.4.1 (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
       Registry 'SaveZoneInformation' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
          ValueName    = 'SaveZoneInformation'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
       Registry 'ScanWithAntiVirus' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
          ValueName    = 'ScanWithAntiVirus'
          ValueType    = 'DWord'
          ValueData    = '3'
       }

       #  19.7.7.1 (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'
       Registry 'ConfigureWindowsSpotlight' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
          ValueName    = 'ConfigureWindowsSpotlight'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  19.7.7.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
       Registry 'DisableThirdPartySuggestions' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
          ValueName    = 'DisableThirdPartySuggestions'
          ValueType    = 'DWord'
          ValueData    = '1'
       }
       

       #  19.7.7.5 (L1) Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'
       Registry 'DisableSpotlightCollectionOnDesktop' {
         Ensure       = 'Present'
         Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
         ValueName    = 'DisableSpotlightCollectionOnDesktop'
         ValueType    = 'DWord'
         ValueData    = '1'
      }

       #  19.7.25.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
       Registry 'NoInplaceSharing' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName    = 'NoInplaceSharing'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.40.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'
       Registry 'AlwaysInstallElevated' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer'
          ValueName    = 'AlwaysInstallElevated'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

   }
}

CIS_WindowsServer2016_v200
