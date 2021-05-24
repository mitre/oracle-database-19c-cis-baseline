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

It is highly encouraged to utilize the json or hdf reporters, which will export the results of a validation run to a format which can be ingested by a visualization tool (see the section on Heimdall below).

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
#### Execute All Controls in the Profile 
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml -t <target> --reporter cli json:results.json
```
#### Execute a single Control in the Profile 
```bash
inspec exec <path to profile on runner> --input-file=inputs.yml --controls=oracle19c-1.1 -t <target> --reporter cli json:results.json
```
#### Execute the profile directly on the Oracle database host
```bash
inspec exec <path to profile on the host> --input-file=inputs.yml --reporter cli json:results.json
```
## Using Heimdall for Viewing the JSON Results

The JSON `results.json` output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results.

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall2)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
