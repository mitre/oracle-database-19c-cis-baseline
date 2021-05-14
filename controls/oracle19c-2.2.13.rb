# encoding: UTF-8

control 'oracle19c-2.2.13' do
  title "Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set to 'FALSE'"
  desc  "The information about patch/update release number provides information
about the exact patch/update release that is currently running on the database.
This is sensitive information that should not be revealed to anyone who
requests it."
  desc  'rationale', "Allowing the database to return information about the
patch/update release number could facilitate unauthorized users' attempts to
gain access based upon known patch weaknesses."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SEC_RETURN_SERVER_RELEASE_BANNER';
    ```
    Ensure `VALUE` is set to `FALSE`.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET SEC_RETURN_SERVER_RELEASE_BANNER = FALSE SCOPE = SPFILE;
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
  tag nist: ['SC-7', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['9', 'Rev_6']
  tag cis_rid: '2.2.13'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SEC_RETURN_SERVER_RELEASE_BANNER';"
  ).column('upper(value)')

  describe 'Database should not return patch/update release info -- SEC_RETURN_SERVER_RELEASE_BANNER' do
    subject { parameter }
    it { should cmp 'FALSE' }
  end
end
