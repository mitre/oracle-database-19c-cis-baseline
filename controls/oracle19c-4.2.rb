control 'oracle19c-4.2' do
  title 'Ensure All Sample Data And Users Have Been Removed'
  desc  "Oracle sample schemas can be used to create sample users
(`BI`,`HR`,`IX`,`OE`,`PM`,`SCOTT`,`SH`), with well-known default passwords,
particular views, and procedures/functions, in addition to tables and
fictitious data. The sample schemas should be removed."
  desc  'rationale', "The sample schemas are typically not required for
production operations of the database. The default users, views, and/or
procedures/functions created by sample schemas could be used to launch exploits
against production environments."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT USERNAME
    FROM DBA_USERS
    WHERE USERNAME IN ('BI','HR','IX','OE','PM','SCOTT','SH');
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT DISTINCT A.USERNAME,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_USERS A
    WHERE A.USERNAME IN ('BI','HR','IX','OE','PM','SCOTT','SH');
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to run the drop script.
    ```
    $ORACLE_HOME/demo/schema/drop_sch.sql
    ```
    Then, execute the following SQL statement.
    ```
    DROP USER SCOTT CASCADE;
    ```
    **Note:** The `recyclebin` is not set to `OFF` within the default drop
script, which means that the data will still be present in your environment
until the `recyclebin` is emptied.
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
  tag cis_controls: ['18.9']
  tag cis_rid: '4.2'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT USERNAME
      FROM DBA_USERS
      WHERE USERNAME IN ('BI','HR','IX','OE','PM','SCOTT','SH');
    "
                 else
                   "
      SELECT DISTINCT A.USERNAME,
      DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_USERS A
      WHERE A.USERNAME IN ('BI','HR','IX','OE','PM','SCOTT','SH');
    "
                 end
  parameter = sql.query(query_string)
  describe 'Sample data should be removed -- sample schema and users' do
    subject { parameter }
    it { should be_empty }
  end
end
