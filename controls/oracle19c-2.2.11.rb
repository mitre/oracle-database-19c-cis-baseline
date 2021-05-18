control 'oracle19c-2.2.11' do
  title "Ensure 'SEC_PROTOCOL_ERROR_FURTHER_ACTION' Is Set to '(DROP,3)'"
  desc  "The `SEC_PROTOCOL_ERROR_FURTHER_ACTION` setting determines the Oracle
server's response to bad/malformed packets received from the client. This
setting should have a value of `(DROP,3)`, which will cause a connection to be
dropped after three bad/malformed packets."
  desc  'rationale', "Bad packets received from the client can potentially
indicate packet-based attacks on the system, such as \"TCP SYN Flood\" or
\"Smurf\" attacks, which could result in a denial-of-service condition, this
value should be set according to the needs of the organization."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_FURTHER_ACTION';
    ```
    Ensure `VALUE` is set to `(DROP,3)`.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET SEC_PROTOCOL_ERROR_FURTHER_ACTION = '(DROP,3)' SCOPE =
SPFILE;
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
  tag nist: %w(AC-6 Rev_4)
  tag cis_level: 1
  tag cis_controls: %w(18 Rev_6)
  tag cis_rid: '2.2.11'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_FURTHER_ACTION';"
  ).column('upper(value)')

  describe 'SEC_PROTOCOL_ERROR_FURTHER_ACTION should drop connections after three bad packets -- SEC_PROTOCOL_ERROR_FURTHER_ACTION' do
    subject { parameter }
    it { should cmp '(DROP, 3)' }
  end
end
