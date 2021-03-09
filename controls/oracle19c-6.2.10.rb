# encoding: UTF-8

control 'oracle19c-6.2.10' do
  title "Ensure the 'ALTER PROFILE' Action Audit Is Enabled"
  desc  "Oracle database profiles are used to enforce resource usage limits and
implement password policies such as password complexity rules and reuse
restrictions. Enabling this unified action audit enables logging of all `ALTER
PROFILE` statements, whether successful or unsuccessful, issued by the users
regardless of the privileges held by the users to issue such statements."
  desc  'rationale', "Logging and monitoring of all attempts to alter profiles,
whether successful or unsuccessful, may provide forensic evidence about
potential suspicious/unauthorized activities. Any such activities may be a
cause for further investigation. In addition, organization security policies
and industry/government regulations may require logging of all user activities
involving alteration of database profiles."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    WITH
    CIS_AUDIT(AUDIT_OPTION) AS
    (
    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER PROFILE' ) )
    ),
    AUDIT_ENABLED AS
    ( SELECT DISTINCT AUDIT_OPTION
     FROM AUDIT_UNIFIED_POLICIES AUD
     WHERE AUD.AUDIT_OPTION IN ('ALTER PROFILE' )
     AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION'
     AND EXISTS (SELECT *
     FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED
     WHERE ENABLED.SUCCESS = 'YES'
     AND ENABLED.FAILURE = 'YES'
     AND ENABLED.ENABLED_OPTION = 'BY USER'
     AND ENABLED.ENTITY_NAME = 'ALL USERS'
     AND ENABLED.POLICY_NAME = AUD.POLICY_NAME)
    )
    SELECT C.AUDIT_OPTION
    FROM CIS_AUDIT C
    LEFT JOIN AUDIT_ENABLED E
    ON C.AUDIT_OPTION = E.AUDIT_OPTION
    WHERE E.AUDIT_OPTION IS NULL;
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    Execute the following SQL statement to remediate this setting.
    ```
    ALTER AUDIT POLICY CIS_UNIFIED_AUDIT_POLICY
    ADD
    ACTIONS
    ALTER PROFILE;
    ```
    **Note:** If you do not have `CIS_UNIFIED_AUDIT_POLICY`, please create one
using the `CREATE AUDIT POLICY` statement.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['AU-12', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['6.2', 'Rev_6']
  tag cis_rid: '6.2.10'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("WITH CIS_AUDIT(AUDIT_OPTION) AS (SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('ALTER PROFILE' ) ) ), AUDIT_ENABLED AS (SELECT DISTINCT AUDIT_OPTION FROM AUDIT_UNIFIED_POLICIES AUD WHERE AUD.AUDIT_OPTION IN ('ALTER PROFILE') AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION' AND EXISTS (SELECT * FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED WHERE ENABLED.SUCCESS = 'YES' AND ENABLED.FAILURE = 'YES' AND ENABLED.ENABLED_OPTION = 'BY USER' AND ENABLED.ENTITY_NAME = 'ALL USERS' AND ENABLED.POLICY_NAME = AUD.POLICY_NAME) ) SELECT C.AUDIT_OPTION FROM CIS_AUDIT C LEFT JOIN AUDIT_ENABLED E ON C.AUDIT_OPTION = E.AUDIT_OPTION WHERE E.AUDIT_OPTION IS NULL;").column('audit_option')

  describe 'APAO' do
    subject { parameter }
    it { should be_empty }
  end
end
