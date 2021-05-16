# encoding: UTF-8

control 'oracle19c-5.2.3' do
  title "Ensure 'EXECUTE ANY PROCEDURE' Is Revoked from 'OUTLN'"
  desc  'Remove unneeded `EXECUTE ANY PROCEDURE` privileges from `OUTLN`.'
  desc  'rationale', "Migrated `OUTLN` users have more privileges than
required."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='EXECUTE ANY PROCEDURE'
    AND GRANTEE='OUTLN';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_SYS_PRIVS A
    WHERE PRIVILEGE='EXECUTE ANY PROCEDURE'
    AND GRANTEE='OUTLN';
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ANY PROCEDURE FROM OUTLN;
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
  tag nist: ['CM-6', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['5.1', 'Rev_6']
  tag cis_rid: '5.2.3'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='EXECUTE ANY PROCEDURE'
    AND GRANTEE='OUTLN';
    "
  else
    query_string = "
    SELECT GRANTEE, PRIVILEGE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_SYS_PRIVS A
    WHERE PRIVILEGE='EXECUTE ANY PROCEDURE'
    AND GRANTEE='OUTLN';
    "
  end
  parameter = sql.query(query_string)
  describe 'OUTLN user should not be able to execute procedures -- list of OUTLN GRANTEES with `EXECUTE ANY PROCEDURE` privileges'  do
    subject { parameter }
    it { should be_empty }
  end
end
