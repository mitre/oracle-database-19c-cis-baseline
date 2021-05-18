control 'oracle19c-2.1.2' do
  title "Ensure 'ADMIN_RESTRICTIONS_<listener_name>' Is Set to 'ON'"
  desc  "The `admin_restrictions_`_`<listener_name>`_ setting in the
`listener.ora` file can require that any attempted real-time alteration of the
parameters in the listener via the set command file be refused unless the
`listener.ora` file is manually altered, then restarted by a privileged user."
  desc  'rationale', "Blocking unprivileged users from making alterations of
the `listener.ora` file, where remote data/service settings are specified, will
help protect data confidentiality."
  desc  'check', "
    To audit this recommendation, execute the following shell commands as
appropriate for your Linux/Windows environment.

    Linux environment:
    ```
    grep -i admin_restrictions $ORACLE_HOME/network/admin/listener.ora
    ```
    Windows environment:
    ```
    find /I \"admin_restrictions\" %ORACLE_HOME%|\
    etwork\\admin\\listener.ora
    ```
    Ensure `admin_restrictions_`_`<listener_name>`_ is set to `ON` for all
listeners.
  "
  desc 'fix', "
    To remediate this recommendation:

    Use a text editor such as `vi` to set the
`admin_restrictions_`_`<listener_name>`_ to the value `ON`.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: %w(CM-6 Rev_4)
  tag cis_level: 2
  tag cis_controls: ['5.1', 'Rev_6']
  tag cis_rid: '2.1.2'

  describe 'Admin restrictions should be enabled -- listener.ora' do
    subject { file(input('listener_file')) }
    its('content') { should_not be_nil }
    its('content') { should match /^ADMIN_RESTRICTIONS.*=\s*on\s*$/i }
  end
end
