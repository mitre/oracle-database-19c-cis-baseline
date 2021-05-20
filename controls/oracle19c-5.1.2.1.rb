control 'oracle19c-5.1.2.1' do
  title "Ensure 'EXECUTE' is not granted to 'PUBLIC' on \"Non-default\"
Packages"
  desc  "The packages described in this control are not granted to `PUBLIC` by
default (\"Non-default\" packages). These packages should not be granted to
`PUBLIC`.
    - The Oracle database `DBMS_BACKUP_RESTORE` package is used for applying
PL/SQL commands to the native `RMAN` sequences.
    - The Oracle database `DBMS_FILE_TRANSFER` package allows a user to
transfer files from one database server to another.
    - The Oracle database `DBMS_SYS_SQL`,`DBMS_REPCAT_SQL_UTL`, `INITJVMAUX`,
`DBMS_AQADM_SYS`, `DBMS_STREAMS_RPC`, `DBMS_PRVTAQIM`, `LTADM` and `DBMS_IJOB`
packages are shipped as undocumented.
  "
  desc 'rationale', "
    As described below, these \"non-default\" group of PL/SQL packages, which
are not granted to `PUBLIC` by default, packages should not be granted to
`PUBLIC`.
    - The `DBMS_BACKUP_RESTORE` package can allow access to OS files.
    - The `DBMS_FILE_TRANSFER` package could allow to transfer files from one
database server to another without authorization to do so.
    - The `DBMS_SYS_SQL` package could allow a user to run code as a different
user without entering valid credentials.
    - The `DBMS_REPCAT_SQL_UTL` package could allow an unauthorized user to run
SQL commands as user `SYS`.
    - The `INITJVMAUX` package could allow an unauthorized user to run SQL
commands as user `SYS`.
    - The `DBMS_AQADM_SYS` package could allow an unauthorized user to run SQL
commands as user `SYS`.
    - The `DBMS_STREAMS_RPC` package could allow an unauthorized user to run
SQL commands as user `SYS`.
    - The `DBMS_PRVTAQIM` package could allow an unauthorized user to escalate
privileges because any SQL statements could be executed as user `SYS`.
    - The `LTADM` package could allow an unauthorized user to run any SQL
command as user `SYS`. It allows privilege escalation if granted to
unprivileged users.
    - The `DBMS_IJOB` package could allow an attacker to change identities by
using a different username to execute a database job. It allows a user to run
database jobs in the context of another user.
  "
  desc 'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE
    FROM DBA_TAB_PRIVS
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN
('DBMS_BACKUP_RESTORE','DBMS_FILE_TRANSFER','DBMS_SYS_SQL','DBMS_REPCAT_SQL_UTL','INITJVMAUX',
    'DBMS_AQADM_SYS','DBMS_STREAMS_RPC','DBMS_PRVTAQIM','LTADM',
    'DBMS_IJOB','DBMS_PDB_EXEC_SQL');
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
    AND TABLE_NAME IN
('DBMS_BACKUP_RESTORE','DBMS_FILE_TRANSFER','DBMS_SYS_SQL','DBMS_REPCAT_SQL_UTL','INITJVMAUX',
    'DBMS_AQADM_SYS','DBMS_STREAMS_RPC','DBMS_PRVTAQIM','LTADM',
    'DBMS_IJOB','DBMS_PDB_EXEC_SQL')
    ORDER BY CON_ID, TABLE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ON DBMS_BACKUP_RESTORE FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_FILE_TRANSFER FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_SYS_SQL FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_REPCAT_SQL_UTL FROM PUBLIC;
    REVOKE EXECUTE ON INITJVMAUX FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_AQADM_SYS FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_STREAMS_RPC FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_PRVTAQIM FROM PUBLIC;
    REVOKE EXECUTE ON LTADM FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_IJOB FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_PDB_EXEC_SQL FROM PUBLIC;
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
  tag nist: %w(AC-6 )
  tag cis_level: 1
  tag cis_controls: %w(18 Rev_6)
  tag cis_rid: '5.1.2.1'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE
      FROM DBA_TAB_PRIVS
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN
  ('DBMS_BACKUP_RESTORE','DBMS_FILE_TRANSFER','DBMS_SYS_SQL','DBMS_REPCAT_SQL_UTL','INITJVMAUX',
      'DBMS_AQADM_SYS','DBMS_STREAMS_RPC','DBMS_PRVTAQIM','LTADM',
      'DBMS_IJOB','DBMS_PDB_EXEC_SQL');
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
      AND TABLE_NAME IN
  ('DBMS_BACKUP_RESTORE','DBMS_FILE_TRANSFER','DBMS_SYS_SQL','DBMS_REPCAT_SQL_UTL','INITJVMAUX',
      'DBMS_AQADM_SYS','DBMS_STREAMS_RPC','DBMS_PRVTAQIM','LTADM',
      'DBMS_IJOB','DBMS_PDB_EXEC_SQL')
      ORDER BY CON_ID, TABLE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe 'Public users should not be able to execute the `DBMS_SYS_SQL`,`DBMS_REPCAT_SQL_UTL`, `INITJVMAUX`, `DBMS_AQADM_SYS`, `DBMS_STREAMS_RPC`, `DBMS_PRVTAQIM`, `LTADM` or `DBMS_IJOB` packages -- list of Non-default packages with public execute privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
