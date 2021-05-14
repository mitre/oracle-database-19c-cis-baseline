# encoding: UTF-8

control 'oracle19c-4.5' do
  title "Ensure 'SYS.USER$MIG' Has Been Dropped"
  desc  "The table `sys.user$mig` is created during migration and contains the
Oracle password hashes before the migration starts. This table should be
dropped."
  desc  'rationale', "The table `sys.user$mig` is not deleted after the
migration. An attacker could access the table containing the Oracle password
hashes."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT OWNER, TABLE_NAME
    FROM DBA_TABLES
    WHERE TABLE_NAME='USER$MIG' AND OWNER='SYS';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT OWNER, TABLE_NAME,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_TABLES A
    WHERE TABLE_NAME='USER$MIG' AND OWNER='SYS';
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    DROP TABLE SYS.USER$MIG;
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
  tag nist: ['SC-28', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['16.14', 'Rev_6']
  tag cis_rid: '4.5'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT OWNER, TABLE_NAME
      FROM DBA_TABLES
      WHERE TABLE_NAME='USER$MIG' AND OWNER='SYS';
    "
  else
    query_string = "
      SELECT OWNER, TABLE_NAME,
      DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_TABLES A
      WHERE TABLE_NAME='USER$MIG' AND OWNER='SYS';
    "
  end
  parameter = sql.query(query_string)
  describe 'SYS.USER$MIG'  do
    subject { parameter }
    it { should be_empty }
  end 
end
