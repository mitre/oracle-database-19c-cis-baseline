control 'oracle19c-3.3' do
  title "Ensure 'PASSWORD_LIFE_TIME' Is Less than or Equal to '90'"
  desc  "The `PASSWORD_LIFE_TIME` setting determines how long a password may be
used before the user is required to be change it. The suggested value for this
is 90 days or less."
  desc  'rationale', "Allowing passwords to remain unchanged for long periods
makes the success of brute-force login attacks more likely."
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
     AND RESOURCE_NAME='PASSWORD_LIFE_TIME'),
     'UNLIMITED','9999',P.LIMIT)) > 90 AND
     P.RESOURCE_NAME = 'PASSWORD_LIFE_TIME' AND
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
     AND RESOURCE_NAME='PASSWORD_LIFE_TIME'
     AND CON_ID = P.CON_ID),
     'UNLIMITED','9999',
     P.LIMIT)) > 90
    AND P.RESOURCE_NAME = 'PASSWORD_LIFE_TIME'
    AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    Remediate this setting by executing the following SQL statement for each
PROFILE returned by the audit procedure.
    ```
    ALTER PROFILE <profile_name> LIMIT PASSWORD_LIFE_TIME 90;
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
  tag nist: %w(AC-2 Rev_4)
  tag cis_level: 1
  tag cis_controls: %w(16 Rev_6)
  tag cis_rid: '3.3'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
    SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
    FROM DBA_PROFILES P
    WHERE TO_NUMBER(DECODE(P.LIMIT,
     'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
     FROM DBA_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME='PASSWORD_LIFE_TIME'),
     'UNLIMITED','9999',P.LIMIT)) > 90 AND
     P.RESOURCE_NAME = 'PASSWORD_LIFE_TIME' AND
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
       AND RESOURCE_NAME='PASSWORD_LIFE_TIME'
       AND CON_ID = P.CON_ID),
       'UNLIMITED','9999',
       P.LIMIT)) > 90
      AND P.RESOURCE_NAME = 'PASSWORD_LIFE_TIME'
      AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
      ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe 'Passwords for all profiles should be set to change frequently -- profiles with PASSWORD_LIFE_TIME > 90' do
    subject { parameter }
    it { should be_empty }
  end
end
