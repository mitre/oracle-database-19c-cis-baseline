control 'oracle19c-5.2.9' do
  title "Ensure 'BECOME USER' Is Revoked from Unauthorized 'GRANTEE'"
  desc  "The Oracle database `BECOME USER` privilege allows the designated user
to inherit the rights of another user. Unauthorized grantees should not have
that privilege."
  desc  'rationale', "The `BECOME USER` privilege can allow the unauthorized
use of another user's privileges, this capability should be restricted
according to the needs of the organization."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='BECOME USER'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT GRANTEE, PRIVILEGE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_SYS_PRIVS A
    WHERE PRIVILEGE='BECOME USER'
    AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    ```
    Lack of results implies compliance.
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE BECOME USER FROM <grantee>;
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
  tag nist: ['AC-3 (3)', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['14.6', 'Rev_7']
  tag cis_rid: '5.2.9'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  query_string = if !input('multitenant')
                   "
    SELECT GRANTEE, PRIVILEGE
    FROM DBA_SYS_PRIVS
    WHERE PRIVILEGE='BECOME USER'
    AND GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
                 else
                   "
    SELECT GRANTEE, PRIVILEGE,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_SYS_PRIVS A
    WHERE PRIVILEGE='BECOME USER'
    AND GRANTEE NOT IN (SELECT USERNAME FROM CDB_USERS WHERE
ORACLE_MAINTAINED='Y')
    AND GRANTEE NOT IN (SELECT ROLE FROM CDB_ROLES WHERE ORACLE_MAINTAINED='Y');
    "
                 end
  parameter = sql.query(query_string).rows

  exempted_privileged_accounts = input('exempted_privileged_accounts').map { |account| 
    account.upcase
  }

  if input('exempted_privileged_accounts')
    parameter = parameter.reject { |account| 
      exempted_privileged_accounts.include?(account['grantee'].upcase)
    }
  end

  describe 'Unauthorized users should not be able to become other users -- list of GRANTEES with `BECOME USER` privileges' do
    subject { parameter }
    it { should be_empty }
  end
end
