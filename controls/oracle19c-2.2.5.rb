control 'oracle19c-2.2.5' do
  title "Ensure 'REMOTE_LISTENER' Is Empty"
  desc  "The `remote_listener` setting determines whether or not a valid
listener can be established on a system separate from the database instance.
This setting should be empty unless the organization specifically needs a valid
listener on a separate system or on nodes running Oracle RAC instances."
  desc  'rationale', "Permitting a remote listener for connections to the
database instance can allow for the potential spoofing of connections and that
could compromise data confidentiality and integrity."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='REMOTE_LISTENER' AND VALUE IS NOT NULL;
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT DISTINCT UPPER(V.VALUE),
    DECODE (V.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B
     WHERE V.CON_ID = B.CON_ID))
    FROM V$SYSTEM_PARAMETER V
    WHERE UPPER(NAME) = 'REMOTE_LISTENER' AND VALUE IS NOT NULL;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET REMOTE_LISTENER = '' SCOPE = SPFILE;
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
  tag nist: %w(SC-7 Rev_4)
  tag cis_level: 1
  tag cis_controls: %w(9 Rev_6)
  tag cis_rid: '2.2.5'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT UPPER(VALUE)
      FROM V$SYSTEM_PARAMETER
      WHERE UPPER(NAME)='REMOTE_LISTENER' AND VALUE IS NOT NULL;
    "
    val = 'upper(value)'
  else
    query_string = "
      SELECT DISTINCT UPPER(V.VALUE),
      DECODE (V.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B
       WHERE V.CON_ID = B.CON_ID))
      FROM V$SYSTEM_PARAMETER V
      WHERE UPPER(NAME) = 'REMOTE_LISTENER' AND VALUE IS NOT NULL;
    "
    val = 'upper(v.value)'
  end

  parameter = sql.query(query_string).column(val)

  describe 'Remote listener for connections to the database instance should not be permitted -- REMOTE_LISTENERS' do
    subject { parameter }
    it { should be_empty }
  end
end
