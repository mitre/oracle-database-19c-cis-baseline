# encoding: UTF-8

control 'oracle19c-6.1.15' do
  title "Ensure the 'PROCEDURE' Audit Option Is Enabled"
  desc  "In this statement audit, `PROCEDURE` means any procedure, function,
package or library. Enabling this audit option causes any attempt, successful
or not, to create or drop any of these types of objects to be audited,
regardless of privilege or lack thereof. Java schema objects (sources, classes,
and resources) are considered the same as procedures for the purposes of
auditing SQL statements."
  desc  'rationale', "Any unauthorized attempts to create or drop a procedure
in another's schema should cause concern, whether successful or not. Changes to
critical stored code can dramatically change the behavior of the application
and produce serious security consequences, including enabling privilege
escalation and introducing SQL injection vulnerabilities. Audit records of such
changes can be helpful in forensics."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT AUDIT_OPTION,SUCCESS,FAILURE
    FROM DBA_STMT_AUDIT_OPTS
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='PROCEDURE';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has auditing
turned on. To assess this recommendation, execute the following SQL statement.
    ```
    SELECT AUDIT_OPTION,SUCCESS,FAILURE,
     DECODE (A.CON_ID,
     0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_STMT_AUDIT_OPTS A
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='PROCEDURE';
    ```
    Lack of results implies a finding.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT PROCEDURE;
    ```
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AU-12', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['6.2', 'Rev_6']
  tag cis_rid: '6.1.15'
end

