control 'oracle19c-2.2.2' do
  title "Ensure 'AUDIT_TRAIL' Is Set to 'DB', 'XML', 'OS', 'DB,EXTENDED', or
'XML,EXTENDED'"
  desc  "The `audit_trail` setting determines whether or not Oracle's basic
audit features are enabled. It can be set to \"Operating System\"(`OS`); `DB`;
`DB,EXTENDED`; `XML`; or `XML,EXTENDED`. The value should be set according to
the needs of the organization."
  desc  'rationale', "Enabling the basic auditing features for the Oracle
instance permits the collection of data to troubleshoot problems, as well as
provides valuable forensic logs in the case of a system breach this value
should be set according to the needs of the organization."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='AUDIT_TRAIL';
    ```
    Ensure `VALUE` is set to `DB` or `OS` or `XML` or `DB,EXTENDED` or
`XML,EXTENDED`.
  "
  desc 'fix', "
    To remediate this setting, execute one of the following SQL statements and
restart the instance.
    ```
    ALTER SYSTEM SET AUDIT_TRAIL = DB, EXTENDED SCOPE = SPFILE;
    ALTER SYSTEM SET AUDIT_TRAIL = OS SCOPE = SPFILE;
    ALTER SYSTEM SET AUDIT_TRAIL = XML, EXTENDED SCOPE = SPFILE;
    ALTER SYSTEM SET AUDIT_TRAIL = DB SCOPE = SPFILE;
    ALTER SYSTEM SET AUDIT_TRAIL = XML SCOPE = SPFILE;
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
  tag nist: %w(AU-6 )
  tag cis_level: 1
  tag cis_controls: %w(6 Rev_6)
  tag cis_rid: '2.2.2'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='AUDIT_TRAIL';"
  ).column('upper(value)')

  describe 'Basic audit features should be enabled -- AUDIT_TRAIL' do
    subject { parameter.first }
    it { should be_in ['DB', 'XML', 'OS', 'DB,EXTENDED', 'XML,EXTENDED'] }
  end
end
