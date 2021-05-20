control 'oracle19c-6.1.14' do
  title "Ensure the 'ALL' Audit Option on 'SYS.AUD$' Is Enabled"
  desc  "The logging of attempts to alter the audit trail in the `SYS.AUD$`
table (open for read/update/delete/view) will provide a record of any
activities that may indicate unauthorized attempts to access the audit trail.
Enabling the audit option will cause these activities to be audited."
  desc  'rationale', "As the logging of attempts to alter the `SYS.AUD$` table
can provide forensic evidence of the initiation of a pattern of unauthorized
activities, this logging capability should be enabled."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT *
    FROM CDB_OBJ_AUDIT_OPTS
    WHERE OBJECT_NAME='AUD$'
    AND ALT='A/A'
    AND AUD='A/A'
    AND COM='A/A'
    AND DEL='A/A'
    AND GRA='A/A'
    AND IND='A/A'
    AND INS='A/A'
    AND LOC='A/A'
    AND REN='A/A'
    AND SEL='A/A'
    AND UPD='A/A'
    AND FBK='A/A';
    ```
    Lack of results implies a finding.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT ALL ON SYS.AUD$ BY ACCESS;
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
  tag nist: %w(AU-12 )
  tag cis_level: 1
  tag cis_controls: ['6.2']
  tag cis_rid: '6.1.14'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  audit_options = sql.query("
  SELECT *
  FROM CDB_OBJ_AUDIT_OPTS
  WHERE OBJECT_NAME='AUD$'
  AND ALT='A/A'
  AND AUD='A/A'
  AND COM='A/A'
  AND DEL='A/A'
  AND GRA='A/A'
  AND IND='A/A'
  AND INS='A/A'
  AND LOC='A/A'
  AND REN='A/A'
  AND SEL='A/A'
  AND UPD='A/A'
  AND FBK='A/A';").column('OBJECT_NAME')

  describe 'Ensure ALL audit option is enabled on AUD$ system packages' do
    subject { audit_options }
    it { should_not be_empty }
  end
end
