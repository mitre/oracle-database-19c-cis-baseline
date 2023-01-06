control 'oracle19c-3.2' do
  title "Ensure 'PASSWORD_LOCK_TIME' Is Greater than or Equal to '#{input('password_lock_time')}'"
  desc  "The `PASSWORD_LOCK_TIME` setting determines how many days must pass
for the user's account to be unlocked after the set number of failed login
attempts has occurred. The suggested value for this is one day or greater."
  desc  'rationale', "Locking the user account after repeated failed login
attempts can block further brute-force login attacks, but can create
administrative headaches as this account unlocking process always requires DBA
intervention."
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
     AND RESOURCE_NAME='PASSWORD_LOCK_TIME'),
     'UNLIMITED','9999',
     P.LIMIT)) < #{input('password_lock_time')}
    AND P.RESOURCE_NAME = 'PASSWORD_LOCK_TIME'
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
     AND RESOURCE_NAME='PASSWORD_LOCK_TIME'
     AND CON_ID = P.CON_ID),
     'UNLIMITED','9999',P.LIMIT)) < #{input('password_lock_time')}
    AND P.RESOURCE_NAME = 'PASSWORD_LOCK_TIME'
    AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    Remediate this setting by executing the following SQL statement for each
`PROFILE` returned by the audit procedure.
    ```
    ALTER PROFILE <profile_name> LIMIT PASSWORD_LOCK_TIME #{input('password_lock_time')};
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
  tag cis_controls: ['16.7']
  tag cis_rid: '3.2'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
      FROM DBA_PROFILES P
      WHERE TO_NUMBER(DECODE(P.LIMIT,
       'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
       FROM DBA_PROFILES
       WHERE PROFILE='DEFAULT'
       AND RESOURCE_NAME='PASSWORD_LOCK_TIME'),
       'UNLIMITED','9999',
       P.LIMIT)) < #{input('password_lock_time')}
      AND P.RESOURCE_NAME = 'PASSWORD_LOCK_TIME'
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
       AND RESOURCE_NAME='PASSWORD_LOCK_TIME'
       AND CON_ID = P.CON_ID),
       'UNLIMITED','9999',P.LIMIT)) < #{input('password_lock_time')}
      AND P.RESOURCE_NAME = 'PASSWORD_LOCK_TIME'
      AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
      ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe "Ensure locktime of at least one day for each profile password after a lockout -- profiles with PASSWORD_LOCK_TIME < #{input('password_lock_time')}" do
    subject { parameter }
    it { should be_empty }
  end
end
