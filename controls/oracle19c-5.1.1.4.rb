# encoding: UTF-8

control 'oracle19c-5.1.1.4' do
  title "Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Java\" Packages"
  desc  "As described below, Oracle Database PL/SQL \"Java\" packages -
`DBMS_JAVA` and `DBMS_JAVA_TEST` – provide APIs to run Java classes or grant
Java packages. The user `PUBLIC` should not be able to execute these packages.
    - The Oracle database `DBMS_JAVA` package can run Java classes (e.g. OS
commands) or grant Java privileges. The user `PUBLIC` should not be able to
execute `DBMS_JAVA`.
    - The Oracle database `DBMS_JAVA_TEST` package can run Java classes (e.g.
OS commands) or grant Java privileges. The user `PUBLIC` should not be able to
execute `DBMS_JAVA_TEST`.
  "
  desc  'rationale', "
    As described below, Oracle Database PL/SQL \"Java\" packages - `DBMS_JAVA`
and `DBMS_JAVA_TEST` – should not be granted to `PUBLIC`.
    - The `DBMS_JAVA` package could allow an attacker to run OS commands from
the database.
    - The `DBMS_JAVA_TEST` package could allow an attacker to run operating
system commands from the database.
  "
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE
    FROM DBA_TAB_PRIVS
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN ('DBMS_JAVA','DBMS_JAVA_TEST');
    ```
    Lack of results implies compliance.

    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.

    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_TAB_PRIVS A
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN ('DBMS_JAVA','DBMS_JAVA_TEST')
    ORDER BY CON_ID, TABLE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ON DBMS_JAVA FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_JAVA_TEST FROM PUBLIC;
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
  tag cis_rid: '5.1.1.4'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))
  java_packages = sql.query("
  SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
  1,(SELECT NAME FROM V$DATABASE),
  (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
  FROM CDB_TAB_PRIVS A
  WHERE GRANTEE='PUBLIC'
  AND PRIVILEGE='EXECUTE'
  AND TABLE_NAME IN ('DBMS_JAVA','DBMS_JAVA_TEST')
  ORDER BY CON_ID, TABLE_NAME;").column('table_name')

  describe 'Public should not be able to EXECUTE java packages' do
    subject { java_packages }
    it { should be_empty }
  end
end
