control 'oracle19c-5.1.1.2' do
  title "Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"File System\" Packages"
  desc  "As described below, Oracle Database PL/SQL \"File System\" packages -
`DBMS_ADVISOR`, `DBMS_LOB` and `UTL_FILE` – provide PL/SQL APIs to access files
on the servers. The user `PUBLIC` should not be able to execute these packages.
    - The Oracle database `DBMS_ADVISOR` package can be used to write files
located on the server where the Oracle instance is installed. The user PUBLIC
should not be able to execute `DBMS_ADVISOR`.
    - The Oracle database `DBMS_LOB` package provides subprograms that can
manipulate and read/write on `BLOB`'s, `CLOB`'s, `NCLOB`'s, `BFILE`'s, and
temporary `LOB`'s. The user `PUBLIC` should not be able to execute `DBMS_LOB`.
    - The Oracle database `UTL_FILE` package can be used to read/write files
located on the server where the Oracle instance is installed. The user `PUBLIC`
should not be able to execute `UTL_FILE`.
  "
  desc 'rationale', "
    As described below, Oracle Database PL/SQL \"File System\" packages -
`DBMS_ADVISOR`, `DBMS_LOB` and `UTL_FILE` – should not be granted to `PUBLIC`.
    - Use of the `DBMS_ADVISOR` package could allow an unauthorized user to
corrupt operating system files on the instance's host.
    - Use of the `DBMS_LOB` package could allow an unauthorized user to
manipulate `BLOB`'s, `CLOB`'s, `NCLOB`'s, `BFILE`'s, and temporary LOBs on the
instance, either destroying data or causing a denial-of-service condition due
to corruption of disk space.
    - Use of the `UTL_FILE` package could allow a user to read OS files. These
files could contain sensitive information (e.g. passwords in `.bash_history`)
  "
  desc 'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE
    FROM DBA_TAB_PRIVS
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN ('DBMS_ADVISOR','DBMS_LOB','UTL_FILE');
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
    AND TABLE_NAME IN ('DBMS_ADVISOR','DBMS_LOB','UTL_FILE')
    ORDER BY CON_ID, TABLE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ON DBMS_ADVISOR FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_LOB FROM PUBLIC;
    REVOKE EXECUTE ON UTL_FILE FROM PUBLIC;
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
  tag cis_rid: '5.1.1.2'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE
      FROM DBA_TAB_PRIVS
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN ('DBMS_ADVISOR','DBMS_LOB','UTL_FILE');
    "
                 else
                   "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_TAB_PRIVS A
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN ('DBMS_ADVISOR','DBMS_LOB','UTL_FILE')
      ORDER BY CON_ID, TABLE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe 'Public users should not be able to execute the `DBMS_ADVISOR`, `DBMS_LOB` or `UTL_FILE` packages -- list of File System packages with public execute privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
