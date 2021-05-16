# encoding: UTF-8

control 'oracle19c-6.1.16' do
  title "Ensure the 'ALTER SYSTEM' Audit Option Is Enabled"
  desc  "`ALTER SYSTEM` allows one to change instance settings, including
security settings and auditing options. Additionally, `ALTER SYSTEM` can be
used to run operating system commands using undocumented Oracle functionality.
Enabling the audit option will audit all attempts to perform `ALTER SYSTEM`,
whether successful or not and regardless of whether or not the `ALTER SYSTEM`
privilege is held by the user attempting the action."
  desc  'rationale', "Any unauthorized attempt to alter the system should be
cause for concern. Alterations outside of some specified maintenance window may
be of concern. In forensics, these audit records could be quite useful."
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
    AND AUDIT_OPTION='ALTER SYSTEM';
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
    AND AUDIT_OPTION='ALTER SYSTEM';
    ```
    Lack of results implies a finding.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT ALTER SYSTEM;
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
  tag cis_rid: '6.1.16'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
    SELECT AUDIT_OPTION,SUCCESS,FAILURE
    FROM DBA_STMT_AUDIT_OPTS
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='ALTER SYSTEM';
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
    AND AUDIT_OPTION='ALTER SYSTEM';
    "
  end
  parameter = sql.query(query_string)
  describe 'ALTER SYSTEM audit option should be enabled -- ALTER SYSTEM AUDIT_OPTION'  do
    subject { parameter }
    it { should_not be_empty }
  end
end
