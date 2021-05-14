# encoding: UTF-8

control 'oracle19c-2.2.7' do
  title "Ensure 'REMOTE_OS_AUTHENT' Is Set to 'FALSE'"
  desc  "The `remote_os_authent` setting determines whether or not OS 'roles'
with the attendant privileges are allowed for remote client connections. This
setting should have a value of `FALSE`.

    **Note:** This parameter has been deprecated in 12.1 and higher versions.
  "
  desc  'rationale', "Permitting OS roles for database connections can allow
the spoofing of connections and permit granting the privileges of an OS role to
unauthorized users to make connections, this value should be restricted
according to the needs of the organization."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='REMOTE_OS_AUTHENT';
    ```
    Ensure `VALUE` is set to `FALSE`.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET REMOTE_OS_AUTHENT = FALSE SCOPE = SPFILE;
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
  tag cis_rid: '2.2.7'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='REMOTE_OS_AUTHENT';"
  ).column('upper(value)')

  describe 'OS roles for database connections should not be permitted -- REMOTE_OS_AUTHENT' do
    subject { parameter }
    it { should cmp 'FALSE' }
  end
end

