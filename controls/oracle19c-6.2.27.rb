# encoding: UTF-8

control 'oracle19c-6.2.27' do
  title "Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled"
  desc  "Oracle database users log on to the database to perform their work.
Enabling this unified audit causes logging of all `LOGON` actions, whether
successful or unsuccessful, issued by the users regardless of the privileges
held by the users to log into the database. In addition, `LOGOFF` action audit
captures logoff activities. This audit action also captures logon/logoff to the
open database by `SYSDBA` and `SYSOPER`."
  desc  'rationale', "Logging and monitoring of all attempts to logon to the
database, whether successful or unsuccessful, may provide forensic evidence
about potential suspicious/unauthorized activities. Any such activities may be
a cause for further investigation. In addition, organization security policies
and industry/government regulations may require logging of all user activities
involving `LOGON` and `LOGOFF`."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    WITH
    CIS_AUDIT(AUDIT_OPTION) AS
    (
    SELECT * FROM TABLE( DBMSOUTPUT_LINESARRAY( 'LOGON','LOGOFF' ) )
    ),
    AUDIT_ENABLED AS
    ( SELECT DISTINCT AUDIT_OPTION
     FROM AUDIT_UNIFIED_POLICIES AUD
     WHERE AUD.AUDIT_OPTION IN ('LOGON','LOGOFF' )
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
    LOGON,
    LOGOFF;
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
  tag cis_rid: '6.2.27'

end
