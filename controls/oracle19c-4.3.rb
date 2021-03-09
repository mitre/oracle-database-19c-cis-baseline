# encoding: UTF-8

control 'oracle19c-4.3' do
  title "Ensure 'DBA_USERS.AUTHENTICATION_TYPE' Is Not Set to 'EXTERNAL' for
Any User"
  desc  "The `authentication_type='EXTERNAL'` setting determines whether or not
a user can be authenticated by a remote OS to allow access to the database with
full authorization. This setting should not be used."
  desc  'rationale', "Allowing remote OS authentication of a user to the
database can potentially allow supposed \"privileged users\" to connect as
\"authenticated,\" even when the remote system is compromised."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT USERNAME FROM DBA_USERS WHERE AUTHENTICATION_TYPE = 'EXTERNAL';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT A.USERNAME,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B
     WHERE A.CON_ID = B.CON_ID))
    FROM CDB_USERS A
    WHERE AUTHENTICATION_TYPE = 'EXTERNAL';
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    ALTER USER <username> IDENTIFIED BY <password>;
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
  tag nist: ['AC-2', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['16', 'Rev_6']
  tag cis_rid: '4.3'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select username from dba_users where authentication_type = 'EXTERNAL';").column('value')

  describe 'ATYPE' do
    subject { parameter }
    it { should be_empty }
  end
end
