# encoding: UTF-8

control 'oracle19c-6.1.11' do
  title "Ensure the 'GRANT ANY OBJECT PRIVILEGE' Audit Option Is Enabled"
  desc  "`GRANT ANY OBJECT PRIVILEGE` allows the user to grant or revoke any
object privilege, which includes privileges on tables, directories, mining
models, etc. Enabling this audit option causes auditing of all uses of that
privilege."
  desc  'rationale', "Logging of privilege grants that can lead to the
creation, alteration, or deletion of critical data, the modification of
objects, object privilege propagation and other such activities can be critical
to forensic investigations."
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
    AND AUDIT_OPTION='GRANT ANY OBJECT PRIVILEGE';
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
    AND AUDIT_OPTION='GRANT ANY OBJECT PRIVILEGE';
    ```
    Lack of results implies a finding.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this needs to be done in both container and pluggable database, you
must connect to both places to do the audit statement.
    ```
    AUDIT GRANT ANY OBJECT PRIVILEGE;
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
  tag cis_rid: '6.1.11'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
    SELECT AUDIT_OPTION,SUCCESS,FAILURE
    FROM DBA_STMT_AUDIT_OPTS
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='GRANT ANY OBJECT PRIVILEGE';
    "
  else
    query_string = "
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
    AND AUDIT_OPTION='GRANT ANY OBJECT PRIVILEGE';
    "
  end
  parameter = sql.query(query_string)
  describe 'GRANT ANY OBJECT PRIVILEGE audit option should be enabled -- GRANT ANY OBJECT PRIVILEGE AUDIT_OPTION'  do
    subject { parameter }
    it { should_not be_empty }
  end
end
