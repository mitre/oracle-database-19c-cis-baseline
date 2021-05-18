control 'oracle19c-6.1.1' do
  title "Ensure the 'USER' Audit Option Is Enabled"
  desc  "The `USER` object allows for creating accounts that can interact with
the database according to the roles and privileges allotted to the account. It
may also own database objects. Enabling the audit option causes auditing of all
activities and requests to create, drop or alter a user, including a user
changing their own password. (The latter is not audited by `audit ALTER USER`.)"
  desc  'rationale', "Any unauthorized attempts to create, drop or alter a user
should cause concern, whether successful or not. Auditing can also be useful in
forensics if an account is compromised, and auditing is mandated by many common
security initiatives. An abnormally high number of these activities in a given
period might be worth investigation. Any failed attempt to drop a user or
create a user may be worth further review."
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
    AND AUDIT_OPTION='USER';
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
    AND AUDIT_OPTION='USER';
    ```
    Lack of results implies a finding.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT USER;
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
  tag cis_rid: '6.1.1'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
    SELECT AUDIT_OPTION,SUCCESS,FAILURE
    FROM DBA_STMT_AUDIT_OPTS
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='USER';
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
    AND AUDIT_OPTION='USER';
    "
                 end
  parameter = sql.query(query_string)
  describe 'USER audit option should be enabled -- USER AUDIT_OPTION' do
    subject { parameter }
    it { should_not be_empty }
  end
end
