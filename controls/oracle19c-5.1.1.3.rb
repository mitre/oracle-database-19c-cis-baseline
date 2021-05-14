# encoding: UTF-8

control 'oracle19c-5.1.1.3' do
  title "Ensure 'EXECUTE' is revoked from 'PUBLIC' on \"Encryption\" Packages"
  desc  "As described below, Oracle Database PL/SQL \"Encryption\" packages -
`DBMS_CRYPTO`, `DBMS_OBFUSCATION_TOOLKIT` and `DBMS_RANDOM` – provide PL/SQL
APIs to perform functions related to cryptography. The `PUBLIC` should not be
able to execute these packages.
    - The `DBMS_CRYPTO` settings provide a toolset that determines the strength
of the encryption algorithm used to encrypt application data and is part of the
`SYS` schema. The `DES` (56-bit key), `3DES` (168-bit key), `3DES-2KEY`
(112-bit key), `AES` (128/192/256-bit keys), and `RC4` are available.
    - The `DBMS_OBFUSCATION_TOOLKIT` provides one of the tools that determine
the strength of the encryption algorithm used to encrypt application data and
is part of the SYS schema. The `DES` (56-bit key) and `3DES` (168-bit key) are
the only two types available.
    - The Oracle database `DBMS_RANDOM` package is used for generating random
numbers but should not be used for cryptographic purposes.
  "
  desc  'rationale', "
    As described below, Oracle Database PL/SQL Encryption packages -
`DBMS_CRYPTO`, `DBMS_OBFUSCATION_TOOLKIT` and `DBMS_RANDOM` – should not be
granted to `PUBLIC`.
    - Execution of the `DBMS_CRYPTO` procedures by the `PUBLIC` can potentially
endanger portions of or all of the data storage.
    - Allowing the `PUBLIC` privileges to access this capability can be
potentially harm data storage.
    - Use of the `DBMS_RANDOM` package can allow the unauthorized application
of the random number-generating function.
  "
  desc  'check', "
    **Non multi-tenant or pluggable database only:**

    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE
    FROM DBA_TAB_PRIVS
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN ('DBMS_CRYPTO','DBMS_OBFUSCATION_TOOLKIT', 'DBMS_RANDOM');
    ```
    Lack of results implies compliance.

    **Multi-tenant in the container database:**

    This query will also give you the name of the CDB/PDB that has the issue.
To assess this recommendation, execute the following SQL statement.

    ```
    SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
V$DATABASE),
     1,(SELECT NAME FROM V$DATABASE),
     (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
    FROM CDB_TAB_PRIVS A
    WHERE GRANTEE='PUBLIC'
    AND PRIVILEGE='EXECUTE'
    AND TABLE_NAME IN ('DBMS_CRYPTO','DBMS_OBFUSCATION_TOOLKIT', 'DBMS_RANDOM')
    ORDER BY CON_ID, TABLE_NAME;
    ```
    Lack of results implies compliance.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement, keeping in
mind if this is granted in both container and pluggable database, you must
connect to both places to revoke.
    ```
    REVOKE EXECUTE ON DBMS_CRYPTO FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_OBFUSCATION_TOOLKIT FROM PUBLIC;
    REVOKE EXECUTE ON DBMS_RANDOM FROM PUBLIC;
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
  tag nist: ['CM-6', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['5.1', 'Rev_6']
  tag cis_rid: '5.1.1.3'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  if !input('multitenant')
    query_string = "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE
      FROM DBA_TAB_PRIVS
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN ('DBMS_CRYPTO','DBMS_OBFUSCATION_TOOLKIT', 'DBMS_RANDOM');
    "
  else
    query_string = "
      SELECT TABLE_NAME, PRIVILEGE, GRANTEE,DECODE (A.CON_ID,0,(SELECT NAME FROM
  V$DATABASE),
       1,(SELECT NAME FROM V$DATABASE),
       (SELECT NAME FROM V$PDBS B WHERE A.CON_ID = B.CON_ID))
      FROM CDB_TAB_PRIVS A
      WHERE GRANTEE='PUBLIC'
      AND PRIVILEGE='EXECUTE'
      AND TABLE_NAME IN ('DBMS_CRYPTO','DBMS_OBFUSCATION_TOOLKIT', 'DBMS_RANDOM')
      ORDER BY CON_ID, TABLE_NAME;
    "
  end
  parameter = sql.query(query_string)
  describe 'Public users should not be able to execute the `DBMS_CRYPTO`, `DBMS_OBFUSCATION_TOOLKIT` or `DBMS_RANDOM` packages -- list of Encryption packages with public execute privileges'  do
    subject { parameter }
    it { should be_empty }
  end 
end
