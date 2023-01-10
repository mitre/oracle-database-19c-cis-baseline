control 'oracle19c-3.4' do
  title "Ensure 'PASSWORD_REUSE_MAX' Is Greater than or Equal to '#{input('password_reuse_max')}'"
  desc  "The `PASSWORD_REUSE_MAX` setting determines how many different
passwords must be used before the user is allowed to reuse a prior password.
The suggested value for this is #{input('password_reuse_max')} passwords or greater."
  desc  'rationale', "Allowing reuse of a password within a short period of
time after the password's initial use can make the success of both
social-engineering and brute-force password-based attacks more likely."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
    FROM DBA_PROFILES P
    WHERE TO_NUMBER(DECODE(P.LIMIT,
     'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
     FROM DBA_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME='PASSWORD_REUSE_MAX'),
     'UNLIMITED','9999',P.LIMIT)) < #{ input('password_reuse_max') == 'UNLIMITED'? '9999' : input('password_reuse_max') } AND
     P.RESOURCE_NAME = 'PASSWORD_REUSE_MAX' AND
     EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE );
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
    DECODE (P.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B
     WHERE P.CON_ID = B.CON_ID)) DATABASE
    FROM CDB_PROFILES P
    WHERE TO_NUMBER(DECODE(P.LIMIT,
     'DEFAULT',(SELECT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
     FROM CDB_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME='PASSWORD_REUSE_MAX'
     AND CON_ID = P.CON_ID),
     'UNLIMITED','9999',P.LIMIT)) < #{ input('password_reuse_max') == 'UNLIMITED'? '9999' : input('password_reuse_max') }
    AND P.RESOURCE_NAME = 'PASSWORD_REUSE_MAX'
    AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    Remediate this setting by executing the following SQL statement for each
`PROFILE` returned by the audit procedure.
    ```
    ALTER PROFILE <profile_name> LIMIT PASSWORD_REUSE_MAX #{input('password_reuse_max')};
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
  tag nist: %w(AC-2 )
  tag cis_level: 1
  tag cis_controls: %w(16 Rev_6)
  tag cis_rid: '3.4'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
      FROM DBA_PROFILES P
      WHERE TO_NUMBER(DECODE(P.LIMIT,
       'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
       FROM DBA_PROFILES
       WHERE PROFILE='DEFAULT'
       AND RESOURCE_NAME='PASSWORD_REUSE_MAX'),
       'UNLIMITED','9999',P.LIMIT)) < #{ input('password_reuse_max') == 'UNLIMITED'? '9999' : input('password_reuse_max') } AND
       P.RESOURCE_NAME = 'PASSWORD_REUSE_MAX' AND
       EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE );
    "
                 else
                   "
      SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
      DECODE (P.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B
       WHERE P.CON_ID = B.CON_ID)) DATABASE
      FROM CDB_PROFILES P
      WHERE TO_NUMBER(DECODE(P.LIMIT,
       'DEFAULT',(SELECT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
       FROM CDB_PROFILES
       WHERE PROFILE='DEFAULT'
       AND RESOURCE_NAME='PASSWORD_REUSE_MAX'
       AND CON_ID = P.CON_ID),
       'UNLIMITED','9999',P.LIMIT)) < #{ input('password_reuse_max') == 'UNLIMITED'? '9999' : input('password_reuse_max') }
      AND P.RESOURCE_NAME = 'PASSWORD_REUSE_MAX'
      AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
      ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe "Passwords for all profiles should not be reused -- profiles with PASSWORD_REUSE_MAX > #{input('password_reuse_max')}" do
    subject { parameter }
    it { should be_empty }
  end
end
