control 'oracle19c-2.1.1' do
  title "Ensure 'extproc' Is Not Present in 'listener.ora'"
  desc  "`extproc` should be removed from the `listener.ora` to mitigate the
risk that OS libraries can be invoked by the Oracle instance."
  desc  'rationale', "`extproc` allows the database to run procedures from OS
libraries. These library calls can, in turn, run any OS command."
  desc  'check', "
    To audit this recommendation, execute the following shell commands as
appropriate for your Linux/Windows environment.

    Linux environment:
    ```
    grep -i extproc $ORACLE_HOME/network/admin/listener.ora
    ```
    Windows environment:
    ```
    find /I \"extproc\" %ORACLE_HOME%\
    etwork\\admin\\listener.ora
    ```
    Ensure `extproc` does not exist.
  "
  desc 'fix', "
    To remediate this recommendation:

    Remove `extproc` from the `listener.ora` file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: %w(AC-6 )
  tag cis_level: 2
  tag cis_controls: ['18.9']
  tag cis_rid: '2.1.1'

  describe 'Extproc should not be present -- listener.ora' do
    subject { file(input('listener_file')) }
    its('content') { should_not be_nil }
    its('content') { should_not match /extproc/i }
  end
end
