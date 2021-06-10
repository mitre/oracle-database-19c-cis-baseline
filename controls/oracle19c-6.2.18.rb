control 'oracle19c-6.2.18' do
  title "Ensure the 'SELECT ANY DICTIONARY' Privilege Audit Is Enabled"
  desc  "The `SELECT ANY DICTIONARY` system privilege allows the user to view
the definition of all schema objects in the database. It grants `SELECT`
privileges on the data dictionary objects to the grantees, including `SELECT
`on `DBA_` views, `V$` views, `X$` views and underlying `SYS` tables such as
`TAB$` and `OBJ$`. This privilege also allows grantees to create stored objects
such as procedures, packages and views on the underlying data dictionary
objects. Please note that this privilege does not grant `SELECT` on tables with
password hashes such as `USER$`, `DEFAULT_PWD$`, `LINK$`, and `USER_HISTORY$`.
Enabling this audit causes logging of activities that exercise this privilege."
  desc  'rationale', "Logging and monitoring of all attempts to access a data
dictionary, whether successful or unsuccessful, may provide clues and forensic
evidence about potential suspicious/unauthorized activities. Any such
activities may be a cause for further investigation. In addition, organization
security policies and industry/government regulations may require logging of
all user activities involving access to the database."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    WITH
    CIS_AUDIT(AUDIT_OPTION) AS
    (
    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'SELECT ANY DICTIONARY' ) )
    ),
    AUDIT_ENABLED AS
    ( SELECT DISTINCT AUDIT_OPTION
     FROM AUDIT_UNIFIED_POLICIES AUD
     WHERE AUD.AUDIT_OPTION IN ('SELECT ANY DICTIONARY' )
     AND AUD.AUDIT_OPTION_TYPE = 'SYSTEM PRIVILEGE'
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
    WHERE E.AUDIT_OPTION IS NULL ;
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    Execute the following SQL statement to remediate this setting.
    ```
    ALTER AUDIT POLICY CIS_UNIFIED_AUDIT_POLICY
    ADD
    PRIVILEGES
    SELECT ANY DICTIONARY;
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
  tag nist: %w(AU-12 )
  tag cis_level: 1
  tag cis_controls: ['6.2']
  tag cis_rid: '6.2.18'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query("
    WITH
    CIS_AUDIT(AUDIT_OPTION) AS
    (
    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'SELECT ANY DICTIONARY' ) )
    ),
    AUDIT_ENABLED AS
    ( SELECT DISTINCT AUDIT_OPTION
     FROM AUDIT_UNIFIED_POLICIES AUD
     WHERE AUD.AUDIT_OPTION IN ('SELECT ANY DICTIONARY' )
     AND AUD.AUDIT_OPTION_TYPE = 'SYSTEM PRIVILEGE'
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
    WHERE E.AUDIT_OPTION IS NULL ;
  ")

  describe 'Ensure SELECT ANY DICTIONARY audit option is enabled -- SELECT ANY DICTIONARY Privilege Audit' do
    subject { parameter }
    it { should be_empty }
  end
end
