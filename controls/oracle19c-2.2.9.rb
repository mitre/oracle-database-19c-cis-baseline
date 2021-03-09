# encoding: UTF-8

control 'oracle19c-2.2.9' do
  title "Ensure 'SEC_CASE_SENSITIVE_LOGON' Is Set to 'TRUE'"
  desc  "The `SEC_CASE_SENSITIVE_LOGON` information determines whether or not
case-sensitivity is required for passwords during login.

    **Note:** This parameter has been deprecated in 12.1 and higher versions.
  "
  desc  'rationale', "Oracle database password case-sensitivity increases the
pool of characters that can be chosen for the passwords, making brute-force
password attacks quite difficult."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SEC_CASE_SENSITIVE_LOGON';
    ```
    Ensure `VALUE` is set to `TRUE`.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET SEC_CASE_SENSITIVE_LOGON = TRUE SCOPE = SPFILE;
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
  tag cis_rid: '2.2.9'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("select value from v$parameter where name = 'sec_case_sensitive_logon';").column('value')

  describe 'LOGO' do
    subject { parameter }
    it { should cmp 'TRUE' }
  end
end
