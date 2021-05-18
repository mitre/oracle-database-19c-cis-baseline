control 'oracle19c-2.2.1' do
  title "Ensure 'AUDIT_SYS_OPERATIONS' Is Set to 'TRUE'"
  desc  "The `AUDIT_SYS_OPERATIONS` setting provides for the auditing of all
user activities conducted under the `SYSOPER` and `SYSDBA` accounts. The
setting should be set to `TRUE` to enable this auditing."
  desc  'rationale', "If the parameter `AUDIT_SYS_OPERATIONS` is `FALSE`, all
statements except for Startup/Shutdown and Logon by `SYSDBA`/`SYSOPER` users
are not audited."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.

    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME) = 'AUDIT_SYS_OPERATIONS';
    ```

    Ensure `VALUE` is set to `TRUE`.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement and restart
the instance.
    ```
    ALTER SYSTEM SET AUDIT_SYS_OPERATIONS = TRUE SCOPE=SPFILE;
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
  tag nist: %w(AU-12 Rev_4)
  tag cis_level: 1
  tag cis_controls: ['6.2', 'Rev_6']
  tag cis_rid: '2.2.1'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME) = 'AUDIT_SYS_OPERATIONS';"
  ).column('upper(value)')

  describe 'AUDIT_SYS_OPERATIONS should be enabled -- AUDIT_SYS_OPERATIONS' do
    subject { parameter }
    it { should cmp 'TRUE' }
  end
end
