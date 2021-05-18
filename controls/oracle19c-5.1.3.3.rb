control 'oracle19c-5.1.3.3' do
  title "Ensure 'ALL' Is Revoked on 'Sensitive' Tables"
  desc  "The Oracle database tables listed below may contain sensitive
information, and should not be accessible to unauthorized users.
    - `USER$`, `USER_HISTORY$`, `XS$VERIFIERS` and `DEFAULT_PWD$` may contain
password hashes.
    - `CDB_LOCAL_ADMINAUTH$` and `PDB_SYNC$` may contain DDLs.
    - `LINK$` and `SCHEDULER$_CREDENTIAL` may contain encrypted passwords.
    - `ENC$` may contains encryption keys.
    - `HISTGRM$` and `HIST_HEAD$` may contain sensitive data.
  "
  desc  'rationale', "Access to sensitive information such as hashed passwords
may allow unauthorized users to decrypt the passwords hashes which could
potentially result in complete compromise of the database."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE, TABLE_NAME
    FROM DBA_TAB_PRIVS
    WHERE TABLE_NAME in
('CDB_LOCAL_ADMINAUTH$','DEFAULT_PWD$','ENC$','HISTGRM$','HIST_HEAD$','LINK$','PDB_SYNC$','SCHEDULER$_CREDENTIAL','USER$','USER_HISTORY$','XS$VERIFIERS')
    AND OWNER = 'SYS'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    Lack of results implies compliance.

    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.

    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) DATABASE
    FROM CDB_TAB_PRIVS A
    WHERE TABLE_NAME in
('CDB_LOCAL_ADMINAUTH$','DEFAULT_PWD$','ENC$','HISTGRM$','HIST_HEAD$','LINK$','PDB_SYNC$','SCHEDULER$_CREDENTIAL','USER$','USER_HISTORY$','XS$VERIFIERS')
    AND OWNER = 'SYS'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
    ORDER BY CON_ID, TABLE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    Execute applicable SQLs listed below to remediate:
    ```
    REVOKE ALL ON SYS.CDB_LOCAL_ADMINAUTH$ FROM <grantee>;
    REVOKE ALL ON SYS.DEFAULT_PWD$ FROM <grantee>;
    REVOKE ALL ON SYS.ENC$ FROM <grantee>;
    REVOKE ALL ON SYS.HISTGRM$ FROM <grantee>;
    REVOKE ALL ON SYS.HIST_HEAD$ FROM <grantee>;
    REVOKE ALL ON SYS.LINK$ FROM <grantee>;
    REVOKE ALL ON SYS.PDB_SYNC$ FROM <grantee>;
    REVOKE ALL ON SYS.SCHEDULER$_CREDENTIAL FROM <grantee>;
    REVOKE ALL ON SYS.USER$ FROM <grantee>;
    REVOKE ALL ON SYS.USER_HISTORY$ FROM <grantee>;
    REVOKE ALL ON SYS.XS$VERIFIERS FROM <grantee>;
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
  tag nist: %w(CM-6 Rev_4)
  tag cis_level: 1
  tag cis_controls: ['5.1', 'Rev_6']
  tag cis_rid: '5.1.3.3'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT GRANTEE, PRIVILEGE, TABLE_NAME
      FROM DBA_TAB_PRIVS
      WHERE TABLE_NAME in
  ('CDB_LOCAL_ADMINAUTH$','DEFAULT_PWD$','ENC$','HISTGRM$','HIST_HEAD$','LINK$','PDB_SYNC$','SCHEDULER$_CREDENTIAL','USER$','USER_HISTORY$','XS$VERIFIERS')
      AND OWNER = 'SYS'
      AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
  ORACLE_MAINTAINED='Y')
      AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
                 else
                   "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) DATABASE
      FROM CDB_TAB_PRIVS A
      WHERE TABLE_NAME in
  ('CDB_LOCAL_ADMINAUTH$','DEFAULT_PWD$','ENC$','HISTGRM$','HIST_HEAD$','LINK$','PDB_SYNC$','SCHEDULER$_CREDENTIAL','USER$','USER_HISTORY$','XS$VERIFIERS')
      AND OWNER = 'SYS'
      AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
  ORACLE_MAINTAINED='Y')
      AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y')
      ORDER BY CON_ID, TABLE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe 'Users should not have access to `CDB_LOCAL_ADMINAUTH$`,`DEFAULT_PWD$`,`ENC$`,`HISTGRM$`,`HIST_HEAD$`,`LINK$`,`PDB_SYNC$`,`SCHEDULER$_CREDENTIAL`,`USER$`,`USER_HISTORY$`,`XS$VERIFIERS` -- list of GRANTEES in Sensitive Tables' do
    subject { parameter }
    it { should be_empty }
  end
end
