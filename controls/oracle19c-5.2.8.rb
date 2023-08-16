control 'oracle19c-5.2.8' do
  title "Ensure 'EXEMPT ACCESS POLICY' Is Revoked from Unauthorized 'GRANTEE'"
  desc  "The Oracle database `EXEMPT ACCESS POLICY` keyword provides the user
the capability to access all the table rows regardless of row-level security
lockouts. Unauthorized grantees should not have that keyword assigned to them."
  desc  'rationale', "The `EXEMPT ACCESS POLICY` privilege can allow an
unauthorized user to potentially access and change data."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='EXEMPT ACCESS POLICY'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
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
    WHERE PRIVILEGE='EXEMPT ACCESS POLICY'
    AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXEMPT ACCESS POLICY FROM <grantee>;
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
  tag nist: %w(SC-8 )
  tag cis_level: 1
  tag cis_controls: ['14.4']
  tag cis_rid: '5.2.8'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='EXEMPT ACCESS POLICY'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
                 else
                   "
    SELECT GRANTEE, PRIVILEGE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_SYS_PRIVS A
    WHERE PRIVILEGE='EXEMPT ACCESS POLICY'
    AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
                 end
  parameter = sql.query(query_string).rows

  if input('exempted_privileged_accounts')
    parameter = parameter.reject { |account| input('exempted_privileged_accounts').include?(account.grantee) }
  end
                 
  describe 'Unauthorized users should not be exempt from access policy -- list of GRANTEES with `EXEMPT ACCESS POLICY` privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
