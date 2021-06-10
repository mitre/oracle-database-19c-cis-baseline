## Oracle 19c CIS Automated Compliance Validation Profile
<b>Oracle 19c</b>

<b>Oracle 19c</b> CIS Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>Oracle database</b>.

This automated Center of Internet Security (CIS) Benchmark validator was developed to reduce the time it takes to perform a security check based upon hardening Guidance from CIS. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>Oracle 19c</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## Oracle 19c CIS Benchmark Overview

The <b>CIS Oracle Database 19c Benchmark</b>(https://www.cisecurity.org/cis-benchmarks/) is intended to address the recommended security settings for Oracle Database 19c. This guide was tested against Oracle Database 19c installed with and without pluggable database support running on a Windows Server instance as a stand-alone system and running on an Oracle Linux instance also as a stand-alone system. Future Oracle Database 19c critical patch updates (CPUs) may impact the recommendations included in this document.

[CIS Benchmarks](https://en.wikipedia.org/wiki/Center_for_Internet_Security#CIS_Controls_and_CIS_Benchmarks): CIS Controls and CIS Benchmarks provide global standards for Internet security, and are a recognized global standard and best practices for securing IT systems and data against attacks. CIS maintains "The CIS Controls", a popular set of 20 security controls "which map to many compliance standards", and are applicable to the Internet of things. Through an independent consensus process, CIS Benchmarks provide frameworks to help organizations bolster their security. CIS offers a variety of free resources, which include "secure configuration benchmarks, automated configuration assessment tools and content, security metrics and security software product certifications".


While the Oracle 19c CIS automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This CIS Automated Compliance Validation Profile was developed based upon:
- CIS Oracle Database 19c Benchmark
### Update History 
| Guidance Name  | Guidance Version | Guidance Location                            | Profile Version | Profile Release Date | STIG EOL    | Profile EOL |
|---------------------------------------|------------------|--------------------------------------------|-----------------|----------------------|-------------|-------------|
| CIS Benchmark for Oracle Database 19c | NA  | https://www.cisecurity.org/cis-benchmarks/ | 1.0.0   | 09-21-2020 | NA | NA |


## Getting Started

### Requirements

#### Oracle 19c  
- Oracle 19c Database
- An account with at least SYSTEM-level role access to run SQL commands

#### Required software on InSpec Runner
- [InSpec](https://www.chef.io/products/chef-inspec/)

#### Required software on target of evaluation
- [SQL\*Plus](https://docs.oracle.com/cd/B19306_01/server.102/b14357/qstart.htm)
    - Release 19c

### Setup Environment on Oracle Database machine 
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.

#### Ensure InSpec version is most recent ( > 4.23.X )
```sh
inspec --version
```

### How to execute this instance  
This profile can be executed against a remote target using the ssh transport, docker transport, or winrm transport of InSpec. Profiles can also be executed directly on the host where InSpec is installed (see https://www.inspec.io/docs/reference/cli/). 

#### Required Inputs
You must specify inputs in an `inputs.yml` file. See `example_inputs.yml` in the profile root folder for a sample. Each input is required for proper execution of the profile.
```yaml
user: 'SYSTEM'
password: 'password'
host: '127.0.0.1'
service: 'ORCLCDB'
sqlplus_bin: 'sqlplus'
listener_file: /opt/oracle/product/19c/dbhome_1/network/admin/listener.ora
multitenant: false
version: '19.0.0.0.0'
listeners: ['LISTENER']
```
Some default values have been added to `inspec.yml`, but can be overridden by defining new values in `inputs.yml`. No default values have been given for database-specific connection variables like the password or the service name; these must be specified in the input file.
##### Note
Environment variables will not be interpreted correctly in `inputs.yml` or `inspec.yml`.
Example:
```
listener_file: $ORACLE_HOME/network/admin/listener.ora # $ORACLE_HOME will not be expanded out correctly!
```
#### Execute a single control in the profile 
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml --controls=oracle19c-1.1 -t <target>
```
#### Execute a single control in the profile and save results as JSON
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml --controls=<control id> -t <target> --reporter cli json:results.json
```
#### Execute all controls in the profile 
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml -t <target>
```
#### Execute all controls in the profile and save results as JSON
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml -t <target> --reporter cli json:results.json
```
#### Execute the profile directly on the Oracle database host
```bash
inspec exec <path to profile on the host> --input-file=inputs.yml --reporter cli json:results.json
```
## Check Overview

**Manual Checks**

This profile includes no manual checks.

**Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.

| Check Number | Description                                                                                                                                                                                                               |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1.1 | Ensure the Appropriate Version/Patches for Oracle Software Is Installed |
| 3.1 | Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5' |
| 3.2 | Ensure 'PASSWORD_LOCK_TIME' Is Greater than or Equal to '1' |
| 3.3 | Ensure 'PASSWORD_LIFE_TIME' Is Less than or Equal to '90' |
| 3.4 | Ensure 'PASSWORD_REUSE_MAX' Is Greater than or Equal to '20' |
| 3.5 | Ensure 'PASSWORD_REUSE_TIME' Is Greater than or Equal to '365' |
| 3.6 | Ensure 'PASSWORD_GRACE_TIME' Is Less than or Equal to '5' |
| 3.7 | Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles |
| 3.8 | Ensure 'SESSIONS_PER_USER' Is Less than or Equal to '10' |
| 3.9 | Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120' |
| 4.1 | Ensure All Default Passwords Are Changed |
| 4.2 | Ensure All Sample Data And Users Have Been Removed |
| 4.3 | Ensure 'DBA_USERS.AUTHENTICATION_TYPE' Is Not Set to 'EXTERNAL' for Any User |
| 4.4 | Ensure No Users Are Assigned the 'DEFAULT' Profile |
| 4.5 | Ensure 'SYS.USER$MIG' Has Been Dropped |
| 4.6 | Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Network\" Packages |
| 2.1.1 | Ensure 'extproc' Is Not Present in 'listener.ora' |
| 2.1.2 | Ensure 'ADMIN_RESTRICTIONS_<listener_name>' Is Set to 'ON' |
| 2.2.1 | Ensure 'AUDIT_SYS_OPERATIONS' Is Set to 'TRUE' |
| 2.2.10 | Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is '3' or Less |
| 2.2.11 | Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set to '(DROP,3)' |
| 2.2.12 | Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set to 'LOG' |
| 2.2.13 | Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set to 'FALSE' |
| 2.2.14 | Ensure 'SQL92_SECURITY' Is Set to 'TRUE' |
| 2.2.15 | Ensure '_trace_files_public' Is Set to 'FALSE' |
| 2.2.16 | Ensure 'RESOURCE_LIMIT' Is Set to 'TRUE' |
| 2.2.2 | Ensure 'AUDIT_TRAIL' Is Set to 'DB', 'XML', 'OS', 'DB,EXTENDED', or 'XML,EXTENDED' |
| 2.2.3 | Ensure 'GLOBAL_NAMES' Is Set to 'TRUE' |
| 2.2.4 | Ensure 'OS_ROLES' Is Set to 'FALSE' |
| 2.2.5 | Ensure 'REMOTE_LISTENER' Is Empty |
| 2.2.6 | Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set to 'NONE' |
| 2.2.7 | Ensure 'REMOTE_OS_AUTHENT' Is Set to 'FALSE' |
| 2.2.8 | Ensure 'REMOTE_OS_ROLES' Is Set to 'FALSE' |
| 2.2.9 | Ensure 'SEC_CASE_SENSITIVE_LOGON' Is Set to 'TRUE' |
| 5.1.1.1 | Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Network\" Packages |
| 5.1.1.2 | Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"File System\" Packages |
| 5.1.1.3 | Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Encryption\" Packages |
| 5.1.1.4 | Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Java\" Packages |
| 5.1.1.5 | Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Job Scheduler\"  Packages |
| 5.1.1.6 | Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"SQL Injection Helper\" Packages |
| 5.1.2.1 | Ensure 'EXECUTE' is not granted to 'PUBLIC' on \"Non-default\" Packages |
| 5.1.3.1 | Ensure 'ALL' Is Revoked from Unauthorized 'GRANTEE' on 'AUD$' |
| 5.1.3.2 | Ensure 'ALL' Is Revoked from Unauthorized 'GRANTEE' on 'DBA_%' |
| 5.1.3.3 | Ensure 'ALL' Is Revoked on 'Sensitive' Tables |
| 5.2.1 | Ensure '%ANY%' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.10 | Ensure 'CREATE PROCEDURE' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.11 | Ensure 'ALTER SYSTEM' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.12 | Ensure 'CREATE ANY LIBRARY' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.13 | Ensure 'CREATE LIBRARY' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.14 | Ensure 'GRANT ANY OBJECT PRIVILEGE' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.15 | Ensure 'GRANT ANY ROLE' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.16 | Ensure 'GRANT ANY PRIVILEGE' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.2 | Ensure 'DBA_SYS_PRIVS.%' Is Revoked from Unauthorized 'GRANTEE' with 'ADMIN_OPTION' Set to 'YES' |
| 5.2.3 | Ensure 'EXECUTE ANY PROCEDURE' Is Revoked from 'OUTLN' |
| 5.2.4 | Ensure 'EXECUTE ANY PROCEDURE' Is Revoked from 'DBSNMP' |
| 5.2.5 | Ensure 'SELECT ANY DICTIONARY' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.6 | Ensure 'SELECT ANY TABLE' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.7 | Ensure 'AUDIT SYSTEM' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.8 | Ensure 'EXEMPT ACCESS POLICY' Is Revoked from Unauthorized 'GRANTEE' |
| 5.2.9 | Ensure 'BECOME USER' Is Revoked from Unauthorized 'GRANTEE' |
| 5.3.1 | Ensure 'SELECT_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE' |
| 5.3.2 | Ensure 'EXECUTE_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE' |
| 5.3.3 | Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE' |
| 6.1.1 | Ensure the 'USER' Audit Option Is Enabled |
| 6.1.10 | Ensure the 'SELECT ANY DICTIONARY' Audit Option Is Enabled |
| 6.1.11 | Ensure the 'GRANT ANY OBJECT PRIVILEGE' Audit Option Is Enabled |
| 6.1.12 | Ensure the 'GRANT ANY PRIVILEGE' Audit Option Is Enabled |
| 6.1.13 | Ensure the 'DROP ANY PROCEDURE' Audit Option Is Enabled |
| 6.1.14 | Ensure the 'ALL' Audit Option on 'SYS.AUD$' Is Enabled |
| 6.1.15 | Ensure the 'PROCEDURE' Audit Option Is Enabled |
| 6.1.16 | Ensure the 'ALTER SYSTEM' Audit Option Is Enabled |
| 6.1.17 | Ensure the 'TRIGGER' Audit Option Is Enabled |
| 6.1.18 | Ensure the 'CREATE SESSION' Audit Option Is Enabled |
| 6.1.2 | Ensure the 'ROLE' Audit Option Is Enabled |
| 6.1.3 | Ensure the 'SYSTEM GRANT' Audit Option Is Enabled |
| 6.1.4 | Ensure the 'PROFILE' Audit Option Is Enabled |
| 6.1.5 | Ensure the 'DATABASE LINK' Audit Option Is Enabled |
| 6.1.6 | Ensure the 'PUBLIC DATABASE LINK' Audit Option Is Enabled |
| 6.1.7 | Ensure the 'PUBLIC SYNONYM' Audit Option Is Enabled |
| 6.1.8 | Ensure the 'SYNONYM' Audit Option Is Enabled |
| 6.1.9 | Ensure the 'DIRECTORY' Audit Option Is Enabled |
| 6.2.1 | Ensure the 'CREATE USER' Action Audit Is Enabled |
| 6.2.10 | Ensure the 'ALTER PROFILE' Action Audit Is Enabled |
| 6.2.11 | Ensure the 'DROP PROFILE' Action Audit Is Enabled |
| 6.2.12 | Ensure the 'CREATE DATABASE LINK' Action Audit Is Enabled |
| 6.2.13 | Ensure the 'ALTER DATABASE LINK' Action Audit Is Enabled |
| 6.2.14 | Ensure the 'DROP DATABASE LINK' Action Audit Is Enabled |
| 6.2.15 | Ensure the 'CREATE SYNONYM' Action Audit Is Enabled |
| 6.2.16 | Ensure the 'ALTER SYNONYM' Action Audit Is Enabled |
| 6.2.17 | Ensure the 'DROP SYNONYM' Action Audit Is Enabled |
| 6.2.18 | Ensure the 'SELECT ANY DICTIONARY' Privilege Audit Is Enabled |
| 6.2.19 | Ensure the 'AUDSYS.AUD$UNIFIED' Access Audit Is Enabled |
| 6.2.2 | Ensure the 'ALTER USER' Action Audit Is Enabled |
| 6.2.20 | Ensure the 'CREATE PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled |
| 6.2.21 | Ensure the 'ALTER PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled |
| 6.2.22 | Ensure the 'DROP PROCEDURE/FUNCTION/PACKAGE/PACKAGE BODY' Action Audit Is Enabled |
| 6.2.23 | Ensure the 'ALTER SYSTEM' Privilege Audit Is Enabled |
| 6.2.24 | Ensure the 'CREATE TRIGGER' Action Audit Is Enabled |
| 6.2.25 | Ensure the  'ALTER TRIGGER' Action Audit IS Enabled |
| 6.2.26 | Ensure the 'DROP TRIGGER' Action Audit Is Enabled |
| 6.2.27 | Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled |
| 6.2.3 | Ensure the 'DROP USER' Audit Option Is Enabled |
| 6.2.4 | Ensure the 'CREATE ROLE' Action Audit Is Enabled |
| 6.2.5 | Ensure the 'ALTER ROLE' Action Audit Is Enabled |
| 6.2.6 | Ensure the 'DROP ROLE' Action Audit Is Enabled |
| 6.2.7 | Ensure the 'GRANT' Action Audit Is Enabled |
| 6.2.8 | Ensure the 'REVOKE' Action Audit Is Enabled |
| 6.2.9 | Ensure the 'CREATE PROFILE' Action Audit Is Enabled |

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
