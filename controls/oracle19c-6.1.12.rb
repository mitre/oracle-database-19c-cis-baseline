# encoding: UTF-8

control 'oracle19c-6.1.12' do
  title "Ensure the 'GRANT ANY PRIVILEGE' Audit Option Is Enabled"
  desc  "`GRANT ANY PRIVILEGE` allows a user to grant any system privilege,
including the most powerful privileges typically available only to
administrators - to change the security infrastructure, to drop/add/modify
users and more."
  desc  'rationale', "Auditing the use of this privilege is part of a
comprehensive auditing policy that can help in detecting issues and can be
useful in forensics."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT AUDIT_OPTION,SUCCESS,FAILURE
    FROM DBA_STMT_AUDIT_OPTS
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='GRANT ANY PRIVILEGE';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has auditing
turned on. To assess this recommendation, execute the following SQL statement.
    ```
    SELECT AUDIT_OPTION,SUCCESS,FAILURE,
     DECODE (A.CON_ID,
     0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_STMT_AUDIT_OPTS A
    WHERE USER_NAME IS NULL
    AND PROXY_NAME IS NULL
    AND SUCCESS = 'BY ACCESS'
    AND FAILURE = 'BY ACCESS'
    AND AUDIT_OPTION='GRANT ANY PRIVILEGE';
    ```
    Lack of results implies a finding.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement in either
the non multi-tenant or container database, it does NOT need run in the
pluggable.
    ```
    AUDIT GRANT ANY PRIVILEGE;
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
  tag nist: ['CM-6 (2)', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['5.4', 'Rev_6']
  tag cis_rid: '6.1.12'
end

