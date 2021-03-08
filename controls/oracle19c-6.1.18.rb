# encoding: UTF-8

control 'oracle19c-6.1.18' do
  title "Ensure the 'CREATE SESSION' Audit Option Is Enabled"
  desc  "Enabling this audit option will cause auditing of all attempts to
connect to the database, whether successful or not, as well as audit session
disconnects/logoffs. The commands to audit `SESSION`, `CONNECT` or `CREATE
SESSION` all accomplish the same thing - they initiate statement auditing of
the connect statement used to create a database session."
  desc  'rationale', "Auditing attempts to connect to the database is basic and
mandated by most security initiatives. Any attempt to logon to a locked
account, failed attempts to logon to default accounts or an unusually high
number of failed logon attempts of any sort, for any user, in a particular time
period may indicate an intrusion attempt. In forensics, the logon record may be
first in a chain of evidence and contain information found in no other type of
audit record for the session. Logon and logoff in the audit trail define the
period and duration of the session."
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
    AND AUDIT_OPTION='CREATE SESSION';
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
    AND AUDIT_OPTION='CREATE SESSION';
    ```
    Lack of results implies a finding.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT SESSION;
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
  tag cis_rid: '6.1.18'
end

