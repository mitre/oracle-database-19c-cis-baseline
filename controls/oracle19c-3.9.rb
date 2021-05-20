control 'oracle19c-3.9' do
  title "Ensure 'INACTIVE_ACCOUNT_TIME' Is Less than or Equal to '120'"
  desc  "The 'INACTIVE_ACCOUNT_TIME' setting determines the maximum number of
days of inactivity (no logins at all) after which the account will be locked.
The suggested value for this is 120 or less."
  desc  'rationale', "Setting 'INACTIVE_ACCOUNT_TIME' can help with
deactivation of \"inactive\" or \"unused\" accounts."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
    FROM DBA_PROFILES P
    WHERE TO_NUMBER(DECODE(P.LIMIT,'DEFAULT',(SELECT DISTINCT
DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
     FROM DBA_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME='INACTIVE_ACCOUNT_TIME'),
     'UNLIMITED','9999',
     P.LIMIT)) > 120
    AND P.RESOURCE_NAME = 'INACTIVE_ACCOUNT_TIME'
    AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE );
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT DISTINCT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
    DECODE (P.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B
     WHERE P.CON_ID = B.CON_ID)) DATABASE
    FROM CDB_PROFILES P
    WHERE TO_NUMBER(DECODE(P.LIMIT,
     'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
     FROM CDB_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME='INACTIVE_ACCOUNT_TIME'
     AND CON_ID = P.CON_ID),
     'UNLIMITED','9999',
     P.LIMIT)) > 120
    AND P.RESOURCE_NAME = 'INACTIVE_ACCOUNT_TIME'
    AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE );
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement for each
`PROFILE` returned by the audit procedure.
    ```
    ALTER PROFILE <profile_name> LIMIT INACTIVE_ACCOUNT_TIME 120;
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
  tag cis_rid: '3.9'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
      FROM DBA_PROFILES P
      WHERE TO_NUMBER(DECODE(P.LIMIT,'DEFAULT',(SELECT DISTINCT
  DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
       FROM DBA_PROFILES
       WHERE PROFILE='DEFAULT'
       AND RESOURCE_NAME='INACTIVE_ACCOUNT_TIME'),
       'UNLIMITED','9999',
       P.LIMIT)) > 120
      AND P.RESOURCE_NAME = 'INACTIVE_ACCOUNT_TIME'
      AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE );
    "
                 else
                   "
      SELECT DISTINCT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
      DECODE (P.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B
       WHERE P.CON_ID = B.CON_ID)) DATABASE
      FROM CDB_PROFILES P
      WHERE TO_NUMBER(DECODE(P.LIMIT,
       'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
       FROM CDB_PROFILES
       WHERE PROFILE='DEFAULT'
       AND RESOURCE_NAME='INACTIVE_ACCOUNT_TIME'
       AND CON_ID = P.CON_ID),
       'UNLIMITED','9999',
       P.LIMIT)) > 120
      AND P.RESOURCE_NAME = 'INACTIVE_ACCOUNT_TIME'
      AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE );
    "
                 end
  parameter = sql.query(query_string)
  describe 'Accounts should lock after a long enough stretch of inactivity -- profiles with INACTIVE_ACCOUNT_TIME < 120' do
    subject { parameter }
    it { should be_empty }
  end
end
