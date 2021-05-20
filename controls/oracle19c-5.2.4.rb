control 'oracle19c-5.2.4' do
  title "Ensure 'EXECUTE ANY PROCEDURE' Is Revoked from 'DBSNMP'"
  desc  'Remove unneeded `EXECUTE ANY PROCEDURE` privileges from `DBSNMP`.'
  desc  'rationale', "Migrated `DBSNMP` users have more privileges than
required."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='EXECUTE ANY PROCEDURE'
    AND GRANTEE='DBSNMP';
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
    AND GRANTEE='DBSNMP';
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ANY PROCEDURE FROM DBSNMP;
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
  tag nist: %w(CM-6 )
  tag cis_level: 1
  tag cis_controls: ['5.1']
  tag cis_rid: '5.2.4'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='EXECUTE ANY PROCEDURE'
    AND GRANTEE='DBSNMP';
    "
                 else
                   "
    SELECT GRANTEE, PRIVILEGE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_SYS_PRIVS A
    WHERE PRIVILEGE='EXECUTE ANY PROCEDURE'
    AND GRANTEE='DBSNMP';
    "
                 end
  parameter = sql.query(query_string)
  describe 'DBSNMP user should not be able to create procedures -- list of DBSNMP GRANTEES with `EXECUTE ANY PROCEDURE` privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
