# encoding: UTF-8

control 'oracle19c-6.2.7' do
  title "Ensure the 'GRANT' Action Audit Is Enabled"
  desc  "`GRANT` statements are used to grant privileges to Oracle database
users and roles, including the most powerful privileges and roles typically
available to the database administrators. Enabling this unified action audit
enables logging of all `GRANT` statements, whether successful or unsuccessful,
issued by the users regardless of the privileges held by the users to issue
such statements."
  desc  'rationale', "With unauthorized grants and permissions, a malicious
user may be able to change the security of the database, access/update
confidential data, or compromise the integrity of the database. Logging and
monitoring of all attempts to grant system privileges, object privileges or
roles, whether successful or unsuccessful, may provide forensic evidence about
potential suspicious/unauthorized activities as well as privilege escalation
activities. Any such activities may be a cause for further investigation. In
addition, organization security policies and industry/government regulations
may require logging of all user activities involving `GRANT`."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    WITH
    CIS_AUDIT(AUDIT_OPTION) AS
    (
    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY('GRANT' ) )
    ),
    AUDIT_ENABLED AS
    ( SELECT DISTINCT AUDIT_OPTION
     FROM AUDIT_UNIFIED_POLICIES AUD
     WHERE AUD.AUDIT_OPTION IN ('GRANT' )
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
    GRANT;
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
  tag cis_rid: '6.2.7'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("WITH CIS_AUDIT(AUDIT_OPTION) AS (SELECT * FROM TABLE(DBMSOUTPUT_LINESARRAY('GRANT') ) ), AUDIT_ENABLED AS (SELECT DISTINCT AUDIT_OPTION FROM AUDIT_UNIFIED_POLICIES AUD WHERE AUD.AUDIT_OPTION IN ('GRANT') AND AUD.AUDIT_OPTION_TYPE = 'STANDARD ACTION' AND EXISTS (SELECT * FROM AUDIT_UNIFIED_ENABLED_POLICIES ENABLED WHERE ENABLED.SUCCESS = 'YES' AND ENABLED.FAILURE = 'YES' AND ENABLED.ENABLED_OPTION = 'BY USER' AND ENABLED.ENTITY_NAME = 'ALL USERS' AND  ENABLED.POLICY_NAME = AUD.POLICY_NAME)) SELECT C.AUDIT_OPTION FROM CIS_AUDIT C LEFT JOIN AUDIT_ENABLED E ON C.AUDIT_OPTION = E.AUDIT_OPTION WHERE E.AUDIT_OPTION IS NULL;").column('audit_option')

  describe 'GRANT action should be audited' do
    subject { parameter }
    it { should be_empty }
  end
end
