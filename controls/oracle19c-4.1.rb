# encoding: UTF-8

control 'oracle19c-4.1' do
  title 'Ensure All Default Passwords Are Changed'
  desc  'Default passwords should not be used by Oracle database users.'
  desc  'rationale', "Default passwords should be considered \"well known\" to
attackers. Consequently, if default passwords remain in place, any attacker
with access to the database can authenticate as the user with that default
password."
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT DISTINCT A.USERNAME
    FROM DBA_USERS_WITH_DEFPWD A, DBA_USERS B
    WHERE A.USERNAME = B.USERNAME
    AND B.ACCOUNT_STATUS = 'OPEN';
    ```
    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.
    ```
    SELECT DISTINCT A.USERNAME,
    DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_USERS_WITH_DEFPWD A, CDB_USERS C
    WHERE A.USERNAME = C.USERNAME
    AND C.ACCOUNT_STATUS = 'OPEN';
    ```
    Lack of results implies compliance.

    The view called `CDB_USERS_WITH_DEFPWD and DBA_USERS_WITH_DEFPWD` shows a
list of all database users making use of default passwords. Lack of results
implies compliance.

    **Note:** Per Oracle Support Document 2173962.1, \"after creation of a
new...database, the `SYS` and `SYSTEM` accounts [may be] listed in
`DBA_USERS_WITH_DEFPWD` even though the accounts were created with non-default
passwords. Setting the same passwords again with `ALTER USER` correctly
recognizes that the accounts do not have default passwords.\"

    **Note:** If you have set remote_password_file=NONE, then you won't be able
to change SYS password through `ALTER USER`. Since remote_password_file is set
to NONE, SYS account is effectively disabled. However, if you would like to
change SYS password, then you will need to change remote_password_file to
exclusive and then change SYS password.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    - Manually issue the following SQL statement for each USERNAME returned in
the Audit Procedure:
    - Execute the following SQL script to assign a randomly generated password
to each account using a default password:
     ```
     begin
     for r_user in (select username
     from dba_users_with_defpwd
     where username not like '%XS$NULL%')
     loop
     DBMS_OUTPUT.PUT_LINE('Password for user '||r_user.username||' will be
changed.');
     execute immediate 'alter user \"'||r_user.username||'\" identified by \"'||
     DBMS_RANDOM.string('a',16)||'\"account lock password expire';
     end loop;
     end;
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
  tag nist: ['CM-2 (2)', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['5.3', 'Rev_6']
  tag cis_rid: '4.1'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT DISTINCT A.USERNAME
      FROM DBA_USERS_WITH_DEFPWD A, DBA_USERS B
      WHERE A.USERNAME = B.USERNAME
      AND B.ACCOUNT_STATUS = 'OPEN';
    "
  else
    query_string = "
      SELECT DISTINCT A.USERNAME,
      DECODE (A.CON_ID,0,(SELECT NAME FROM V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_USERS_WITH_DEFPWD A, CDB_USERS C
      WHERE A.USERNAME = C.USERNAME
      AND C.ACCOUNT_STATUS = 'OPEN';
    "
  end
  parameter = sql.query(query_string)
  describe 'Default passwords should be changed -- profiles with default passwords'  do
    subject { parameter }
    it { should be_empty }
  end 
end

