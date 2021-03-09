# encoding: UTF-8

control 'oracle19c-3.7' do
  title "Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles"
  desc  "The `PASSWORD_VERIFY_FUNCTION` determines password settings
requirements when a user password is changed at the SQL command prompt. It
should be set for all profiles. Note that this setting does not apply for users
managed by the Oracle password file."
  desc  'rationale', "Through Oracle database profiles, password complexity
rules (mixed cases with digits and special characters), blocking of simple
combinations, and enforcing change/history settings can potentially thwart
unauthorized logins by an unauthorized user."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
    FROM DBA_PROFILES P
    WHERE DECODE(P.LIMIT,
     'DEFAULT',(SELECT LIMIT
     FROM DBA_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME = P.RESOURCE_NAME),
     LIMIT) = 'NULL'
    AND P.RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
    AND EXISTS ( SELECT 'X'
     FROM DBA_USERS U
     WHERE U.PROFILE = P.PROFILE );
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
    WHERE DECODE(P.LIMIT,
     'DEFAULT',(SELECT LIMIT
     FROM CDB_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME = P.RESOURCE_NAME
     AND CON_ID = P.CON_ID),
     LIMIT) = 'NULL'
    AND P.RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
    AND EXISTS ( SELECT 'X'
     FROM CDB_USERS U
     WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "Create a custom password verification function which fulfills
the password requirements of the organization."
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
  tag cis_rid: '3.7'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  pw_verify_function = sql.query("SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
    DECODE (P.CON_ID,0,(SELECT NAME FROM V$DATABASE),
    1,(SELECT NAME FROM V$DATABASE),
    (SELECT NAME FROM V$PDBS B
    WHERE P.CON_ID = B.CON_ID)) DATABASE
    FROM CDB_PROFILES P
    WHERE DECODE(P.LIMIT,
    'DEFAULT',(SELECT LIMIT
    FROM CDB_PROFILES
    WHERE PROFILE='DEFAULT'
    AND RESOURCE_NAME = P.RESOURCE_NAME
    AND CON_ID = P.CON_ID),
    LIMIT) = 'NULL'
    AND P.RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
    AND EXISTS ( SELECT 'X'
    FROM CDB_USERS U
    WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;").rows()

  describe "Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles" do
    subject { pw_verify_function }
    it { should be_empty }
  end
end
