# encoding: UTF-8

control 'oracle19c-2.2.6' do
  title "Ensure 'REMOTE_LOGIN_PASSWORDFILE' Is Set to 'NONE'"
  desc  "The `remote_login_passwordfile` setting specifies whether or not
Oracle checks for a password file during login and how many databases can use
the password file. The setting should have a value of `NONE` or in the event
you are running DR/Data Guard, `EXCLUSIVE` is an allowable value."
  desc  'rationale', "The use of this sort of password login file could permit
unsecured, privileged connections to the database."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='REMOTE_LOGIN_PASSWORDFILE';
    ```
    Ensure `VALUE` is set to `NONE` or in the event you are running DR/Data
Guard, `EXCLUSIVE` is an allowable VALUE.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET REMOTE_LOGIN_PASSWORDFILE = 'NONE' SCOPE = SPFILE;
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
  tag cis_rid: '2.2.6'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='REMOTE_LOGIN_PASSWORDFILE';"
  ).column('upper(value)')

  describe 'Oracle should not use a password file during login -- REMOTE_LOGIN_PASSWORDFILE' do
    subject { parameter }
    it { should be_in ['NONE', 'EXCLUSIVE'] }
  end
end

