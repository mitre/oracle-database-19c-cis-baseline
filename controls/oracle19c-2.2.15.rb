control 'oracle19c-2.2.15' do
  title "Ensure '_trace_files_public' Is Set to 'FALSE'"
  desc  "The `_trace_files_public` setting determines whether or not the
system's trace file is world readable. This setting should have a value of
FALSE to restrict trace file access."
  desc  'rationale', "Making the file world readable means anyone can read the
instance's trace file, which could contain sensitive information about instance
operations."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT A.KSPPINM, B.KSPPSTVL
    FROM SYS.X_$KSPPI a, SYS.X_$KSPPCV b
    WHERE A.INDX=B.INDX
    AND A.KSPPINM LIKE '\\_%trace_files_public' escape '\\';
    ```
    A `VALUE` equal to `FALSE` or lack of results implies compliance.

    Please note that the assessment SQL relies on `X_$` views which should be
created per Appendix 7.

    BELOW SQL NO LONGER WORKS FOR Oracle12c FOR UNDOCUMENTED PARAMETERS.
    ```
    SELECT VALUE
    FROM V$SYSTEM_PARAMETER
    WHERE NAME='_trace_files_public';
    ```
  "
  desc 'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET \"_trace_files_public\" = FALSE SCOPE = SPFILE;
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
  tag nist: %w(SC-8 Rev_4)
  tag cis_level: 1
  tag cis_controls: ['14.4', 'Rev_6']
  tag cis_rid: '2.2.15'

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  parameter = sql.query(
    "SELECT A.KSPPINM, B.KSPPSTVL
    FROM SYS.X_$KSPPI a, SYS.X_$KSPPCV b
    WHERE A.INDX=B.INDX
    AND A.KSPPINM LIKE '\\_\%trace_files_public' escape '\\';"
  ).column('upper(value)')

  describe.one do
    describe parameter do
      it { should be_empty }
    end
    describe parameter do
      it { should be 'FALSE' }
    end
  end
end
