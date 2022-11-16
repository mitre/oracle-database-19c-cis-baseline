control 'oracle19c-5.1.1.1' do
  title "Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Network\" Packages"
  desc  "As described below, Oracle Database PL/SQL \"Network\" packages -
`DBMS_LDAP`, `UTL_INADDR`, `UTL_TCP`, `UTL_MAIL`, `UTL_SMTP`, `UTL_DBWS`,
`UTL_ORAMTS`, `UTL_HTTP` and type `HTTPURITYPE` – provide PL/SQL APIs to
interact or access remote servers. The PUBLIC should not be able to execute
these packages.
    - The Oracle database `DBMS_LDAP` package contains functions and procedures
that enable programmers to access data from LDAP servers.
    - The Oracle database `UTL_INADDR` package provides an API to retrieve host
names and IP addresses of local and remote hosts.
    - The Oracle database `UTL_TCP` package can be used to read/write file to
TCP sockets on the server where the Oracle instance is installed.
    - The Oracle database `UTL_MAIL` package can be used to send email from the
server where the Oracle instance is installed.
    - The Oracle database `UTL_SMTP` package can be used to send email from the
server where the Oracle instance is installed. The user `PUBLIC` should not be
able to execute `UTL_SMTP`.
    - The Oracle database `UTL_DBWS` package can be used to read/write file to
web-based applications on the server where the Oracle instance is installed.
This package is not automatically installed for security reasons.
    - The Oracle database `UTL_ORAMTS` package can be used to perform HTTP
requests. This could be used to send information to the outside.
    - The Oracle database `UTL_HTTP` package can be used to perform HTTP
requests. This could be used to send information to the outside.
    - The Oracle database `HTTPURITYPE` object type can be used to perform HTTP
requests.
  "
  desc 'rationale', "
    As described below, Oracle Database PL/SQL packages - `DBMS_LDAP`,
`UTL_INADDR`, `UTL_TCP`, `UTL_MAIL`, `UTL_SMTP`, `UTL_DBWS`, `UTL_ORAMTS`,
`UTL_HTTP` and type `HTTPURITYPE` can be used by unauthorized users to create
specially crafted error messages or send information to external servers. The
`PUBLIC` should not be able to execute these packages.
    - The use of the `DBMS_LDAP` package can be used to create specially
crafted error messages or send information via DNS to the outside.
    - The `UTL_INADDR` package can be used to create specially crafted error
messages or send information via DNS to the outside.
    - The `UTL_TCP` package could allow an unauthorized user to corrupt the TCP
stream used to carry the protocols that communicate with the instance's
external communications.
    - The `UTL_MAIL` package could allow an unauthorized user to corrupt the
SMTP function to accept or generate junk mail that can result in a
denial-of-service condition due to network saturation.
    - The `UTL_SMTP` package could allow an unauthorized user to corrupt the
SMTP function to accept or generate junk mail that can result in a
denial-of-service condition due to network saturation.
    - The `UTL_DBWS` package could allow an unauthorized user to corrupt the
HTTP stream used to carry the protocols that communicate for the instance's
web-based external communications.
    - The `UTL_ORAMTS` package could be used to send (sensitive) information to
external websites. The use of this package should be restricted according to
the needs of the organization.
    - The `UTL_HTTP` package could be used to send (sensitive) information to
external websites.
    - The use of this package should be restricted according to the needs of
the organization.
    - The ability to perform HTTP requests could be used to leak information
from the database to an external destination.
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
('DBMS_LDAP','UTL_INADDR','UTL_TCP','UTL_MAIL','UTL_SMTP','UTL_DBWS','UTL_ORAMTS','UTL_HTTP','HTTPURITYPE');
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
('DBMS_LDAP','UTL_INADDR','UTL_TCP','UTL_MAIL','UTL_SMTP','UTL_DBWS','UTL_ORAMTS','UTL_HTTP','HTTPURITYPE')
    ORDER BY CON_ID, TABLE_NAME;

    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ON DBMS_LDAP FROM PUBLIC;
    REVOKE EXECUTE ON UTL_INADDR FROM PUBLIC;
    REVOKE EXECUTE ON UTL_TCP FROM PUBLIC;
    REVOKE EXECUTE ON UTL_MAIL FROM PUBLIC;
    REVOKE EXECUTE ON UTL_SMTP FROM PUBLIC;
    REVOKE EXECUTE ON UTL_DBWS FROM PUBLIC;
    REVOKE EXECUTE ON UTL_ORAMTS FROM PUBLIC;
    REVOKE EXECUTE ON UTL_HTTP FROM PUBLIC;
    REVOKE EXECUTE ON HTTPURITYPE FROM PUBLIC;
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
  tag cis_rid: '5.1.1.1'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE
      FROM DBA_TAB_PRIVS
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN
  ('DBMS_LDAP','UTL_INADDR','UTL_TCP','UTL_MAIL','UTL_SMTP','UTL_DBWS','UTL_ORAMTS','UTL_HTTP','HTTPURITYPE');
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
  ('DBMS_LDAP','UTL_INADDR','UTL_TCP','UTL_MAIL','UTL_SMTP','UTL_DBWS','UTL_ORAMTS','UTL_HTTP','HTTPURITYPE')
      ORDER BY CON_ID, TABLE_NAME;
    "
                 end
  parameter = sql.query(query_string)
  describe 'Public users should not be able to execute the `DBMS_LDAP`, `UTL_INADDR`, `UTL_TCP`, `UTL_MAIL`, `UTL_SMTP`, `UTL_DBWS`,
`UTL_ORAMTS`, `UTL_HTTP` or `HTTPURITYPE` packages -- list of Network packages with public execute privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
