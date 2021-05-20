control 'oracle19c-2.2.4' do
  title "Ensure 'OS_ROLES' Is Set to 'FALSE'"
  desc  "The `os_roles` setting permits externally created groups to be applied
to database management."
  desc  'rationale', "Allowing the OS to use external groups for database
management could cause privilege overlaps and generally weaken security."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='OS_ROLES';
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
    WHERE UPPER(NAME) = 'OS_ROLES';
    ```
    Ensure `VALUE` is set to `FALSE`.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET OS_ROLES = FALSE SCOPE = SPFILE;
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
  tag nist: %w(AC-2 )
  tag cis_level: 1
  tag cis_controls: %w(16 Rev_6)
  tag cis_rid: '2.2.4'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT UPPER(VALUE)
      FROM V$SYSTEM_PARAMETER
      WHERE UPPER(NAME)='OS_ROLES';
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
      WHERE UPPER(NAME) = 'OS_ROLES';
    "
    val = 'upper(v.value)'
  end
  parameter = sql.query(query_string).column(val)

  describe 'External groups should not be allowed for database management -- OS_ROLES' do
    subject { parameter.first }
    it { should cmp 'FALSE' }
  end
end
