control 'oracle19c-2.2.8' do
  title "Ensure 'REMOTE_OS_ROLES' Is Set to 'FALSE'"
  desc  "The `remote_os_roles` setting permits remote users' OS roles to be
applied to database management. This setting should have a value of `FALSE`."
  desc  'rationale', "Allowing remote clients OS roles to have permissions for
database management could cause privilege overlaps and generally weaken
security."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='REMOTE_OS_ROLES';
    ```
    Ensure `VALUE` is set to `FALSE`.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET REMOTE_OS_ROLES = FALSE SCOPE = SPFILE;
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
  tag nist: %w(AC-2 Rev_4)
  tag cis_level: 1
  tag cis_controls: %w(16 Rev_6)
  tag cis_rid: '2.2.8'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='REMOTE_OS_ROLES';"
  ).column('upper(value)')

  describe 'OS roles for database management should not be permitted -- REMOTE_OS_ROLES' do
    subject { parameter }
    it { should cmp 'FALSE' }
  end
end
