control 'oracle19c-2.2.3' do
  title "Ensure 'GLOBAL_NAMES' Is Set to 'TRUE'"
  desc  "The `global_names` setting requires that the name of a database link
matches that of the remote database it will connect to. This setting should
have a value of `TRUE`."
  desc  'rationale', "Not requiring database connections to match the domain
that is being called remotely could allow unauthorized domain sources to
potentially connect via brute-force tactics."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='GLOBAL_NAMES';
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
    WHERE UPPER(NAME) = 'GLOBAL_NAMES';
    ```
    Ensure `VALUE` is set to `TRUE`.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET GLOBAL_NAMES = TRUE SCOPE = SPFILE;
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
  tag nist: %w(SC-7 )
  tag cis_level: 1
  tag cis_controls: %w(9 Rev_6)
  tag cis_rid: '2.2.3'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT UPPER(VALUE)
      FROM V$SYSTEM_PARAMETER
      WHERE UPPER(NAME)='GLOBAL_NAMES';
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
      WHERE UPPER(NAME) = 'GLOBAL_NAMES';
    "
    val = 'upper(v.value)'
  end

  parameter = sql.query(query_string).column(val)

  describe 'Database connections should match the domain that is being called remotely -- GLOBAL_NAMES' do
    subject { parameter.first }
    it { should cmp 'TRUE' }
  end
end
