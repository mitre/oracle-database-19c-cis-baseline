control 'oracle19c-5.1.3.2' do
  title "Ensure 'ALL' Is Revoked from Unauthorized 'GRANTEE' on 'DBA_%'"
  desc  "The Oracle database `DBA_` views show all information which is
relevant to administrative accounts. Unauthorized grantees should not have full
access to those views."
  desc  'rationale', "Permitting users the authorization to manipulate the
`DBA_` views can expose sensitive data."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE,TABLE_NAME
    FROM DBA_TAB_PRIVS
    WHERE TABLE_NAME LIKE 'DBA_%'
    AND OWNER = 'SYS'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE,TABLE_NAME,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_TAB_PRIVS A
    WHERE TABLE_NAME LIKE 'DBA_%'
    AND OWNER = 'SYS'
    AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    Replace _`<Non-DBA/SYS grantee>`_ in the query below, with the Oracle
login(s) or role(s) returned from the associated audit procedure and execute,
keeping in mind if this is granted in both container and pluggable database,
you must connect to both places to revoke:
    ```
    REVOKE ALL ON <DBA_%> FROM <Non-DBA/SYS grantee>;
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
  tag cis_rid: '5.1.3.2'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT GRANTEE,TABLE_NAME
      FROM DBA_TAB_PRIVS
      WHERE TABLE_NAME LIKE 'DBA_%'
      AND OWNER = 'SYS'
      AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
  ORACLE_MAINTAINED='Y')
      AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
                 else
                   "
      SELECT GRANTEE,TABLE_NAME,
      DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_TAB_PRIVS A
      WHERE TABLE_NAME LIKE 'DBA_%'
      AND OWNER = 'SYS'
      AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
  ORACLE_MAINTAINED='Y')
      AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
                 end
  parameter = sql.query(query_string)
  describe 'Unauthorized grantees should not have access to DBA_ schemas -- list of GRANTEES in DBA_ tables' do
    subject { parameter }
    it { should be_empty }
  end
end
