control 'oracle19c-4.6' do
  title 'Ensure No Public Database Links Exist'
  desc  'Public Database links are used to allow connections between databases.'
  desc  'rationale', "Using public database links in the database can allow
anyone with a connection to the database to query, update, insert, delete data
on a remote database depending on the userid that is part of the link."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT DB_LINK, HOST FROM DBA_DB_LINKS WHERE OWNER = 'PUBLIC';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT DB_LINK, HOST,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_DB_LINKS A
    WHERE OWNER = 'PUBLIC';
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    DROP PUBLIC DATABASE LINK <DB_LINK>;
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
  tag cis_rid: '4.6'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
      SELECT DB_LINK, HOST FROM DBA_DB_LINKS WHERE OWNER = 'PUBLIC';
    "
                 else
                   "
      SELECT DB_LINK, HOST,
      DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_DB_LINKS A
      WHERE OWNER = 'PUBLIC';
    "
                 end
  parameter = sql.query(query_string)
  describe 'Ensure no public database links exist -- DBA_DB_LINKS with PUBLIC owner' do
    subject { parameter }
    it { should be_empty }
  end
end
