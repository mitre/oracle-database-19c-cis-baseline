control 'oracle19c-2.2.16' do
  title "Ensure 'RESOURCE_LIMIT' Is Set to 'TRUE'"
  desc  "`RESOURCE_LIMIT` determines whether resource limits are enforced in
database profiles. This setting should have a value of `TRUE`."
  desc  'rationale', "If `RESOURCE_LIMIT` is set to `FALSE`, none of the system
resource limits that are set in any database profiles are enforced. If
`RESOURCE_LIMIT` is set to `TRUE`, the limits set in database profiles are
enforced."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='RESOURCE_LIMIT';
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
    WHERE UPPER(NAME) = 'RESOURCE_LIMIT';
    ```
    Ensure `VALUE` is set to `TRUE`.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET RESOURCE_LIMIT = TRUE SCOPE = SPFILE;
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
  tag nist: %w(SC-8 )
  tag cis_level: 1
  tag cis_controls: ['14.4']
  tag cis_rid: '2.2.16'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT UPPER(VALUE)
      FROM V$SYSTEM_PARAMETER
      WHERE UPPER(NAME)='RESOURCE_LIMIT';
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
      WHERE UPPER(NAME) = 'RESOURCE_LIMIT';
    "
    val = 'upper(v.value)'
  end

  parameter = sql.query(query_string).column(val)

  describe 'Resource limits should be set in database profiles -- RESOURCE_LIMIT' do
    subject { parameter.first }
    it { should cmp 'TRUE' }
  end
end
