# encoding: UTF-8

control 'oracle19c-4.4' do
  title "Ensure No Users Are Assigned the 'DEFAULT' Profile"
  desc  "Upon creation database users are assigned to the `DEFAULT` profile
unless otherwise specified. No users should be assigned to that profile."
  desc  'rationale', "Users should be created with function-appropriate
profiles. The `DEFAULT` profile, being defined by Oracle, is subject to change
at any time (e.g. by patch or version update). The `DEFAULT` profile has
unlimited settings that are often required by the `SYS` user when patching;
such unlimited settings should be tightly reserved and not applied to
unnecessary users."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT USERNAME
    FROM DBA_USERS
    WHERE PROFILE='DEFAULT'
    AND ACCOUNT_STATUS='OPEN'
    AND ORACLE_MAINTAINED = 'N';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT A.USERNAME,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_USERS A
    WHERE A.PROFILE='DEFAULT'
    AND A.ACCOUNT_STATUS='OPEN'
    AND A.ORACLE_MAINTAINED = 'N';
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this recommendation, execute the following SQL statement for
each user returned by the audit query using a functional-appropriate profile,
keeping in mind if this is granted in both container and pluggable database,
you must connect to both places to revoke.
    ```
    ALTER USER <username> PROFILE <appropriate_profile>;
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
  tag cis_rid: '4.4'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  profiles = sql.query("SELECT A.USERNAME,
  DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
  1,(SELECT NAME FROM V$DATABASE),
  (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
  FROM CDB_USERS A
  WHERE A.PROFILE='DEFAULT'
  AND A.ACCOUNT_STATUS='OPEN'
  AND A.ORACLE_MAINTAINED = 'N';").rows()

  describe 'Users should be created with function-appropriate profiles.' do
    subject { profiles }
    it { should be_empty }
  end
end
