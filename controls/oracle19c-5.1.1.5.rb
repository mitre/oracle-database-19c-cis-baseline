control 'oracle19c-5.1.1.5' do
  title "Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Job Scheduler\"
Packages"
  desc  "As described below, Oracle Database PL/SQL \"Job Scheduler\" packages
- `DBMS_SCHEDULER` and `DBMS_JOB` – provide APIs to schedule jobs. The user
`PUBLIC` should not be able to execute these packages.
    - The Oracle database `DBMS_SCHEDULER` package schedules and manages the
database and operating system jobs. The user `PUBLIC` should not be able to
execute `DBMS_SCHEDULER`.
    - The Oracle database `DBMS_JOB` package schedules and manages the jobs
sent to the job queue and has been superseded by the `DBMS_SCHEDULER` package,
even though `DBMS_JOB` has been retained for backwards compatibility. The user
`PUBLIC` should not be able to execute `DBMS_JOB`.
  "
  desc 'rationale', "
    As described below, Oracle Database PL/SQL \"Job Scheduler\" packages -
`DBMS_SCHEDULER` and `DBMS_JOB` – should not be granted to the user `PUBLIC`.
    - Use of the `DBMS_SCHEDULER` package could allow an unauthorized user to
run database or operating system jobs.
    - Use of the `DBMS_JOB` package could allow an unauthorized user to disable
or overload the job queue. It has been superseded by the `DBMS_SCHEDULER`
package.
  "
  desc 'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE
    FROM DBA_TAB_PRIVS
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN ('DBMS_SCHEDULER','DBMS_JOB');
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
    AND TABLE_NAME IN ('DBMS_SCHEDULER','DBMS_JOB')
    ORDER BY CON_ID, TABLE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ON DBMS_JOB FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_SCHEDULER FROM PUBLIC;
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
  tag cis_rid: '5.1.1.5'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE
      FROM DBA_TAB_PRIVS
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN ('DBMS_SCHEDULER','DBMS_JOB');
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
      AND TABLE_NAME IN ('DBMS_SCHEDULER','DBMS_JOB')
      ORDER BY CON_ID, TABLE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe 'Public users should not be able to execute the `DBMS_SCHEDULER` or `DBMS_JOB` packages -- list of Job Scheduler packages with public execute privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
