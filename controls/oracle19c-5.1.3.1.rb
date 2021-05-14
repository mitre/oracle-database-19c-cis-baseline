# encoding: UTF-8

control 'oracle19c-5.1.3.1' do
  title "Ensure 'ALL' Is Revoked from Unauthorized 'GRANTEE' on 'AUD$'"
  desc  "The Oracle database `SYS.AUD$` table contains all the audit records
for the database of the non-Data Manipulation Language (DML) events, such as
`ALTER`, `DROP`, and `CREATE`, and so forth. (DML changes need trigger-based
audit events to record data alterations.) Unauthorized grantees should not have
full access to that table."
  desc  'rationale', "Permitting non-privileged users the authorization to
manipulate the `SYS.AUD$` table can allow distortion of the audit records,
hiding unauthorized activities."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_TAB_PRIVS
    WHERE TABLE_NAME='AUD$'
    AND OWNER = 'SYS';
    ```
    Lack of results implies compliance.

    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_TAB_PRIVS A
    WHERE TABLE_NAME='AUD$'
    AND OWNER = 'SYS';
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE ALL ON AUD$ FROM <grantee>;
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
  tag nist: ['AC-3 (3)', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['14.6', 'Rev_7']
  tag cis_rid: '5.1.3.1'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT GRANTEE, PRIVILEGE
      FROM DBA_TAB_PRIVS
      WHERE TABLE_NAME='AUD$'
      AND OWNER = 'SYS';
    "
  else
    query_string = "
      SELECT GRANTEE, PRIVILEGE,
      DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_TAB_PRIVS A
      WHERE TABLE_NAME='AUD$'
      AND OWNER = 'SYS';
    "
  end
  parameter = sql.query(query_string)
  describe 'Unauthorized grantees should not have access to SYS.AUD$ -- list of GRANTEES in AUD$'  do
    subject { parameter }
    it { should be_empty }
  end 
end

