# encoding: UTF-8

control 'oracle19c-6.1.3' do
  title "Ensure the 'SYSTEM GRANT' Audit Option Is Enabled"
  desc  "Enabling the audit option for the `SYSTEM GRANT` object causes
auditing of any attempt, successful or not, to grant or revoke any system
privilege or role, regardless of privilege held by the user attempting the
operation."
  desc  'rationale', "Logging of all grant and revokes (roles and system
privileges) can provide forensic evidence about a pattern of
suspect/unauthorized activities. Any unauthorized attempt may be cause for
further investigation."
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
    AND AUDIT_OPTION='SYSTEM GRANT';
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
    AND AUDIT_OPTION='SYSTEM GRANT';
    ```
    Lack of results implies a finding.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT SYSTEM GRANT;
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
  tag nist: ['CM-6 (2)', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['5.4', 'Rev_6']
  tag cis_rid: '6.1.3'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("SELECT AUDIT_OPTION,SUCCESS,FAILURE FROM CDB_STMT_AUDIT_OPTS WHERE USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS' AND AUDIT_OPTION='SYSTEM GRANT';").column('audit_option')

  describe 'SGAO' do
    subject { parameter }
    it { should_not be_empty }
  end
end
