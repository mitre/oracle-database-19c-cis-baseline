# encoding: UTF-8

control 'oracle19c-3.1' do
  title "Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5'"
  desc  "The `FAILED_LOGIN_ATTEMPTS` setting determines how many failed login
attempts are permitted before the system locks the user's account. While
different profiles can have different and more restrictive settings, such as
`USERS` and `APPS`, the minimum(s) recommended here should be set on the
`DEFAULT` profile."
  desc  'rationale', "Repeated failed login attempts can indicate the
initiation of a brute-force login attack, this value should be set according to
the needs of the organization. (See the **Notes** for a warning on a known bug
that can make this security measure backfire.)"
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT
    FROM DBA_PROFILES P
    WHERE TO_NUMBER(DECODE(P.LIMIT,
     'DEFAULT',(SELECT DISTINCT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
     FROM DBA_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS'),
     'UNLIMITED','9999',
     P.LIMIT)) > 5
    AND P.RESOURCE_NAME = 'FAILED_LOGIN_ATTEMPTS'
    AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE ) ;

    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT P.PROFILE, P.RESOURCE_NAME, P.LIMIT,
    DECODE (P.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B
     WHERE P.CON_ID = B.CON_ID)) DATABASE
    FROM CDB_PROFILES P
    WHERE TO_NUMBER(DECODE(P.LIMIT,
     'DEFAULT',(SELECT DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
     FROM CDB_PROFILES
     WHERE PROFILE='DEFAULT'
     AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS'
     AND CON_ID = P.CON_ID),
     'UNLIMITED','9999',P.LIMIT)) > 5
    AND P.RESOURCE_NAME = 'FAILED_LOGIN_ATTEMPTS'
    AND EXISTS ( SELECT 'X' FROM CDB_USERS U WHERE U.PROFILE = P.PROFILE )
    ORDER BY CON_ID, PROFILE, RESOURCE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    Remediate this setting by executing the following SQL statement for each
`PROFILE` returned by the audit procedure.
    ```
    ALTER PROFILE <profile_name> LIMIT FAILED_LOGIN_ATTEMPTS 5;
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
  tag cis_controls: ['16.7', 'Rev_6']
  tag cis_rid: '3.1'
end

