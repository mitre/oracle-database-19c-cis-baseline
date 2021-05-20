control 'oracle19c-6.1.17' do
  title "Ensure the 'TRIGGER' Audit Option Is Enabled"
  desc  "A `TRIGGER` may be used to modify `DML` actions or invoke other
(recursive) actions when some types of user-initiated actions occur. Enabling
this audit option will cause auditing of any attempt, successful or not, to
create, drop, enable or disable any schema trigger in any schema regardless of
privilege or lack thereof. For enabling and disabling a trigger, it covers both
`ALTER TRIGGER` and `ALTER TABLE`."
  desc  'rationale', "Triggers are often part of schema security, data
validation and other critical constraints upon actions and data. A trigger in
another schema may be used to escalate privileges, redirect operations,
transform data and perform other sorts of perhaps undesired actions. Any
unauthorized attempt to create, drop or alter a trigger in another schema may
be cause for investigation."
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
    AND AUDIT_OPTION='TRIGGER';
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
    AND AUDIT_OPTION='TRIGGER';
    ```
    Lack of results implies a finding.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT TRIGGER;
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
  tag nist: %w(AU-12 )
  tag cis_level: 1
  tag cis_controls: ['6.2']
  tag cis_rid: '6.1.17'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
    SELECT AUDIT_OPTION,SUCCESS,FAILURE
    FROM DBA_STMT_AUDIT_OPTS
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='TRIGGER';
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
    AND AUDIT_OPTION='TRIGGER';
    "
                 end
  parameter = sql.query(query_string)
  describe 'TRIGGER audit option should be enabled -- TRIGGER AUDIT_OPTION' do
    subject { parameter }
    it { should_not be_empty }
  end
end
