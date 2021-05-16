# encoding: UTF-8

control 'oracle19c-5.3.1' do
  title "Ensure 'SELECT_CATALOG_ROLE' Is Revoked from Unauthorized 'GRANTEE'"
  desc  "The Oracle database `SELECT_CATALOG_ROLE` provides `SELECT` privileges
on all data dictionary views held in the `SYS` schema. Unauthorized grantees
should not have that role."
  desc  'rationale', "Permitting unauthorized access to the
`SELECT_CATALOG_ROLE` can allow the disclosure of all dictionary data."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, GRANTED_ROLE
    FROM DBA_ROLE_PRIVS
    WHERE GRANTED_ROLE='SELECT_CATALOG_ROLE'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, GRANTED_ROLE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_ROLE_PRIVS A
    WHERE GRANTED_ROLE='SELECT_CATALOG_ROLE'
    AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE SELECT_CATALOG_ROLE FROM <grantee>;
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
  tag cis_rid: '5.3.1'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
    SELECT GRANTEE, GRANTED_ROLE
    FROM DBA_ROLE_PRIVS
    WHERE GRANTED_ROLE='SELECT_CATALOG_ROLE'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
  else
    query_string = "
    SELECT GRANTEE, GRANTED_ROLE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_ROLE_PRIVS A
    WHERE GRANTED_ROLE='SELECT_CATALOG_ROLE'
    AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
  end
  parameter = sql.query(query_string)
  describe 'Unauthorized users should not have SELECT privileges on data dictionary -- list of GRANTEES with `SELECT_CATALOG_ROLE` privileges'  do
    subject { parameter }
    it { should be_empty }
  end
end
