control 'oracle19c-5.3.3' do
  title "Ensure 'DBA' Is Revoked from Unauthorized 'GRANTEE'"
  desc  "The Oracle database `DBA` role is the default database administrator
role provided for the allocation of administrative privileges. Unauthorized
grantees should not have that role."
  desc  'rationale', "Assignment of the `DBA` role to an ordinary user can
provide a great number of unnecessary privileges to that user and open the door
to data breaches, integrity violations, and denial-of-service conditions."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT 'GRANT' AS PATH, GRANTEE, GRANTED_ROLE
    FROM DBA_ROLE_PRIVS
    WHERE GRANTED_ROLE = 'DBA' AND GRANTEE NOT IN ('SYS', 'SYSTEM')
    UNION
    SELECT 'PROXY', PROXY || '-' || CLIENT, 'DBA'
    FROM DBA_PROXIES
    WHERE CLIENT IN (SELECT GRANTEE
     FROM DBA_ROLE_PRIVS
     WHERE GRANTED_ROLE = 'DBA');
    ```
    **Multi-tenant in the container database**: This query will also give you
the name of the CDB/PDB that has the issue. To assess this recommendation,
execute the following SQL statement.
    ```
    SELECT 'GRANT' AS PATH, GRANTEE, GRANTED_ROLE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) CON
    FROM CDB_ROLE_PRIVS A
    WHERE GRANTED_ROLE='DBA'
    AND GRANTEE NOT IN ('SYS', 'SYSTEM')
    UNION
    SELECT 'PROXY', PROXY || '-' || CLIENT, 'DBA',
     DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID)) CON
    FROM CDB_PROXIES A
    WHERE CLIENT IN (SELECT GRANTEE
     FROM CDB_ROLE_PRIVS B
     WHERE GRANTED_ROLE = 'DBA'
     AND A.CON_ID = B.CON_ID);
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE DBA FROM <grantee>;
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
  tag cis_rid: '5.3.3'

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
