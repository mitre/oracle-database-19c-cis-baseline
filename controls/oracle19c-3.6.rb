# encoding: UTF-8

control 'oracle19c-3.6' do
  title "Ensure 'PASSWORD_GRACE_TIME' Is Less than or Equal to '5'"
  desc  "The `PASSWORD_GRACE_TIME` setting determines how many days can pass
after the user's password expires before the user's login capability is
automatically locked out. The suggested value for this is five days or less."
  desc  'rationale', "Locking the user account after the expiration of the
password change requirement's grace period can help prevent password-based
attacks against any forgotten or disused accounts, while still allowing the
account and its information to be accessible by DBA intervention."
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
     AND RESOURCE_NAME='PASSWORD_GRACE_TIME'),
     'UNLIMITED','9999',P.LIMIT)) > 5 AND
     P.RESOURCE_NAME = 'PASSWORD_GRACE_TIME' AND
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
     AND RESOURCE_NAME='PASSWORD_GRACE_TIME'
     AND CON_ID = P.CON_ID),
     'UNLIMITED','9999',P.LIMIT)) > 5
    AND P.RESOURCE_NAME = 'PASSWORD_GRACE_TIME'
    AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    Remediate this setting by executing the following SQL statement for each
`PROFILE` returned by the audit procedure.
    ```
    ALTER PROFILE <profile_name> LIMIT PASSWORD_GRACE_TIME 5;
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
  tag nist: ['AC-2', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['16', 'Rev_6']
  tag cis_rid: '3.6'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
      FROM DBA_PROFILES P
      WHERE TO_NUMBER(DECODE(P.LIMIT,
       'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
       FROM DBA_PROFILES
       WHERE PROFILE='DEFAULT'
       AND RESOURCE_NAME='PASSWORD_GRACE_TIME'),
       'UNLIMITED','9999',P.LIMIT)) > 5 AND
       P.RESOURCE_NAME = 'PASSWORD_GRACE_TIME' AND
       EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE );
    "
  else
    query_string = "
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
       AND RESOURCE_NAME='PASSWORD_GRACE_TIME'
       AND CON_ID = P.CON_ID),
       'UNLIMITED','9999',P.LIMIT)) > 5
      AND P.RESOURCE_NAME = 'PASSWORD_GRACE_TIME'
      AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
      ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    "
  end
  parameter = sql.query(query_string)
  describe 'Passwords that expire without being changed should lock out the user after a short grace period -- profiles with PASSWORD_GRACE_TIME > 5'  do
    subject { parameter }
    it { should be_empty }
  end 
end

