## Oracle 19c CIS Automated Compliance Validation Profile

InSpec profile to validate the secure configuration of Oracle Database 19c against the Oracle Database 19c Benchmark version 1.0.0 [CIS](https://www.cisecurity.org/cis-benchmarks/)

## Oracle 19c CIS Benchmark Overview

The <b>CIS Oracle Database 19c Benchmark</b>(https://www.cisecurity.org/cis-benchmarks/) is intended to address the recommended security settings for Oracle Database 19c. Future Oracle Database 19c critical patch updates (CPUs) may impact the recommendations included in this document.

For more information see [CIS Benchmarks FAQ](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq)

This InSpec profile automates the validation of Oracle Database 19c against the equivalent CIS Benchmark.

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
