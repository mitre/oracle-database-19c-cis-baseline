control 'oracle19c-2.2.14' do
  title "Ensure 'SQL92_SECURITY' Is Set to 'TRUE'"
  desc  "The `SQL92_SECURITY` parameter setting `TRUE` requires that a user
must also be granted the `SELECT` object privilege before being able to perform
`UPDATE` or `DELETE` operations on tables that have `WHERE` or `SET` clauses.
The setting should have a value of TRUE."
  desc  'rationale', "A user without `SELECT` privilege can still infer the
value stored in a column by referring to that column in a `DELETE` or `UPDATE`
statement. This setting prevents inadvertent information disclosure by ensuring
that only users who already have `SELECT` privilege can execute the statements
that would allow them to infer the stored values."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SQL92_SECURITY';
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
    WHERE UPPER(NAME) = 'SQL92_SECURITY';
    ```
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET SQL92_SECURITY = TRUE SCOPE = SPFILE;
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
  tag nist: %w(AC-6 )
  tag cis_level: 1
  tag cis_controls: %w(18 Rev_6)
  tag cis_rid: '2.2.14'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT UPPER(VALUE)
      FROM V$SYSTEM_PARAMETER
      WHERE UPPER(NAME)='SQL92_SECURITY';
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
      WHERE UPPER(NAME) = 'SQL92_SECURITY';
    "
    val = 'upper(v.value)'
  end

  parameter = sql.query(query_string).column(val)

  describe 'Database should not return patch/update release info -- SQL92_SECURITY' do
    subject { parameter.first }
    it { should cmp 'TRUE' }
  end
end
