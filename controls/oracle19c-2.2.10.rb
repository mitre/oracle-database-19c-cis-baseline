control 'oracle19c-2.2.10' do
  title "Ensure 'SEC_MAX_FAILED_LOGIN_ATTEMPTS' Is '#{input('sec_max_failed_login_attempts')}' or Less"
  desc  "The `SEC_MAX_FAILED_LOGIN_ATTEMPTS` parameter determines how many
failed login attempts are allowed before Oracle closes the login connection."
  desc  'rationale', "Allowing an unlimited number of login attempts for a user
connection can facilitate both brute-force login attacks and the occurrence of
denial-of-service."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SEC_MAX_FAILED_LOGIN_ATTEMPTS';
    ```
    Ensure `VALUE` is set to `#{input('sec_max_failed_login_attempts')}`.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET SEC_MAX_FAILED_LOGIN_ATTEMPTS = #{input('sec_max_failed_login_attempts')} SCOPE = SPFILE;
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
  tag cis_controls: ['16.7']
  tag cis_rid: '2.2.10'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME) = 'SEC_MAX_FAILED_LOGIN_ATTEMPTS';"
  ).column('upper(value)')

  describe 'SEC_MAX_FAILED_LOGIN_ATTEMPTS should be less than or equal to #{input('sec_max_failed_login_attempts')} -- SEC_MAX_FAILED_LOGIN_ATTEMPTS' do
    subject { parameter.first }
    it { should cmp <= #{input('sec_max_failed_login_attempts')} }
  end
end
