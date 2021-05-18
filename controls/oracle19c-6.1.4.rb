control 'oracle19c-6.1.4' do
  title "Ensure the 'PROFILE' Audit Option Is Enabled"
  desc  "The `PROFILE` object allows for the creation of a set of database
resource limits that can be assigned to a user, so that that user cannot exceed
those resource limitations. Enabling the audit option causes auditing of all
attempts, successful or not, to create, drop or alter any profile."
  desc  'rationale', "As profiles are part of the database security
infrastructure, auditing the creation, modification, and deletion of profiles
is recommended."
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
    AND AUDIT_OPTION='PROFILE';
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
    AND AUDIT_OPTION='PROFILE';
    ```
    Lack of results implies a finding.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT PROFILE;
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
  tag nist: %w(AU-12 Rev_4)
  tag cis_level: 1
  tag cis_controls: ['6.2', 'Rev_6']
  tag cis_rid: '6.1.4'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
    SELECT AUDIT_OPTION,SUCCESS,FAILURE
    FROM DBA_STMT_AUDIT_OPTS
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='PROFILE';
    "
                 else
                   "
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
    AND AUDIT_OPTION='PROFILE';
    "
                 end
  parameter = sql.query(query_string)
  describe 'PROFILE audit option should be enabled -- PROFILE AUDIT_OPTION' do
    subject { parameter }
    it { should_not be_empty }
  end
end
