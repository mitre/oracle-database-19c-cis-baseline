control 'oracle19c-5.1.1.6' do
  title "Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"SQL Injection Helper\"
Packages"
  desc  "As described below, Oracle Database PL/SQL \"SQL Injection Helper
Packages\" packages - `DBMS_SQL`, `DBMS_XMLGEN`, `DBMS_XMLQUERY`,
`DBMS_XLMSTORE`, `DBMS_XLMSAVE` and `DBMS_REDACT` – provide APIs to schedule
jobs. The user `PUBLIC` should not be able to execute these packages.
    - The Oracle database `DBMS_SQL` package is used for running dynamic SQL
statements.
    - The `DBMS_XMLGEN` package takes an arbitrary SQL query as input, converts
it to XML format, and returns the result as a `CLOB`.
    - The Oracle package `DBMS_XMLQUERY` takes an arbitrary SQL query, converts
it to XML format, and returns the result. This package is similar to
`DBMS_XMLGEN`.
    - The `DBMS_XLMSTORE` package provides XML functionality. It accepts a
table name and XML as input to perform `DML` operations against the table.
    - The `DBMS_XLMSAVE` package provides XML functionality. It accepts a table
name and XML as input and then inserts into or updates that table.
    - The DBMS_REDACT package provides an interface to Oracle Data Redaction,
which enables you to mask (redact) data that is returned from queries issued by
low-privileged users or an application.
  "
  desc 'rationale', "
    As described below, Oracle Database PL/SQL \"SQL Injection Helper
Packages\" packages - `DBMS_SQL`, `DBMS_XMLGEN`, `DBMS_XMLQUERY`,
`DBMS_XLMSTORE`, `DBMS_XLMSAVE` and 'DBMS_REDACT' – should not be granted to
`PUBLIC`.
    - The `DBMS_SQL` package could allow privilege escalation if input
validation is not done properly.
    - The package `DBMS_XMLGEN` can be used to search the entire database for
sensitive information like credit card numbers
    - The package `DBMS_XMLQUERY` can be used to search the entire database for
sensitive information like credit card numbers. Malicious users may be able to
exploit this package as an auxiliary inject function in a SQL injection attack.
    - Malicious users may be able to exploit the `DBMS_XLMSTORE` package as an
auxiliary inject function in a SQL injection attack.
    - Malicious users may be able to exploit the `DBMS_XLMSAVE` package as an
auxiliary inject function in a SQL injection attack.
    - Malicious users may be able to exploit DBMS_REDACT as an auxiliary inject
function in a SQL injection attack.
  "
  desc 'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE
    FROM DBA_TAB_PRIVS
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN ('DBMS_SQL', 'DBMS_XMLGEN',
'DBMS_XMLQUERY','DBMS_XMLSTORE','DBMS_XMLSAVE','DBMS_AW','OWA_UTIL','DBMS_REDACT');
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
    AND TABLE_NAME IN ('DBMS_SQL', 'DBMS_XMLGEN',
'DBMS_XMLQUERY','DBMS_XMLSTORE','DBMS_XMLSAVE','DBMS_AW','OWA_UTIL','DBMS_REDACT')
    ORDER BY CON_ID, TABLE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ON DBMS_SQL FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_XMLGEN FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_XMLQUERY FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_XMLSAVE FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_XMLSTORE FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_AW FROM PUBLIC;
    REVOKE EXECUTE ON OWA_UTIL FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_REDACT FROM PUBLIC;
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
  tag cis_rid: '5.1.1.6'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE
      FROM DBA_TAB_PRIVS
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN ('DBMS_SQL', 'DBMS_XMLGEN',
  'DBMS_XMLQUERY','DBMS_XMLSTORE','DBMS_XMLSAVE','DBMS_AW','OWA_UTIL','DBMS_REDACT');
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
      AND TABLE_NAME IN ('DBMS_SQL', 'DBMS_XMLGEN',
  'DBMS_XMLQUERY','DBMS_XMLSTORE','DBMS_XMLSAVE','DBMS_AW','OWA_UTIL','DBMS_REDACT')
      ORDER BY CON_ID, TABLE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe 'Public users should not be able to execute the `DBMS_SQL`, `DBMS_XMLGEN`, `DBMS_XMLQUERY`, `DBMS_XLMSTORE`, `DBMS_XLMSAVE` or `DBMS_REDACT` packages -- list of SQL Injection Helper Packages packages with public execute privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
