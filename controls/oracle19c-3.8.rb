control 'oracle19c-3.8' do
  title "Ensure 'SESSIONS_PER_USER' Is Less than or Equal to '#{input('sessions_per_user')}'"
  desc  "The `SESSIONS_PER_USER` setting determines the maximum number of user
sessions that are allowed to be open concurrently. The suggested value for this
is 10 or less."
  desc  'rationale', "Limiting the number of the `SESSIONS_PER_USER` can help
prevent memory resource exhaustion by poorly formed requests or intentional
denial-of-service attacks."
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
     AND RESOURCE_NAME='SESSIONS_PER_USER'),
     'UNLIMITED','9999',P.LIMIT)) > #{input('sessions_per_user')}
    AND P.RESOURCE_NAME = 'SESSIONS_PER_USER'
    AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE );
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
     AND RESOURCE_NAME='SESSIONS_PER_USER'
     AND CON_ID = P.CON_ID),
     'UNLIMITED','9999',P.LIMIT)) > #{input('sessions_per_user')}
    AND P.RESOURCE_NAME = 'SESSIONS_PER_USER'
    AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement for each
`PROFILE` returned by the audit procedure.
    ```
    ALTER PROFILE <profile_name> LIMIT SESSIONS_PER_USER #{input('sessions_per_user')};
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
  tag nist: %w(AC-6 )
  tag cis_level: 1
  tag cis_controls: %w(18 Rev_6)
  tag cis_rid: '3.8'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
      FROM DBA_PROFILES P
      WHERE TO_NUMBER(DECODE(P.LIMIT,
       'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
       FROM DBA_PROFILES
       WHERE PROFILE='DEFAULT'
       AND RESOURCE_NAME='SESSIONS_PER_USER'),
       'UNLIMITED','9999',P.LIMIT)) > #{input('sessions_per_user')}
      AND P.RESOURCE_NAME = 'SESSIONS_PER_USER'
      AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE );
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
       AND RESOURCE_NAME='SESSIONS_PER_USER'
       AND CON_ID = P.CON_ID),
       'UNLIMITED','9999',P.LIMIT)) > #{input('sessions_per_user')}
      AND P.RESOURCE_NAME = 'SESSIONS_PER_USER'
      AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
      ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe "Users should have a limited number of maximum sessions at once -- profiles with SESSIONS_PER_USER > #{input('sessions_per_user')}" do
    subject { parameter }
    it { should be_empty }
  end
end
