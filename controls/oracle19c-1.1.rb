# encoding: UTF-8

control 'oracle19c-1.1' do
  title "Ensure the Appropriate Version/Patches for Oracle Software Is
Installed"
  desc  "The Oracle installation version and patches should be the most recent
that are compatible with the organization's operational needs."
  desc  'rationale', "Using the most recent Oracle database software, along
with all applicable patches can help limit the possibilities for
vulnerabilities in the software, the installation version and/or patches
applied during setup should be established according to the needs of the
organization. Ensure you are using a release that is covered by a level of
support that includes the generation of Critical Patch Updates."
  desc  'check', "
    To assess this recommendation, use the following example shell command as
appropriate for your environment.

    For example, on Linux systems:
    ```
    opatch lsinventory | grep -e \"^.*<latest_patch_version_numer>\\s*.*$\"
    ```
    For example, on Windows systems:
    ```
    opatch lsinventory | find \"<latest_patch_version_number>\"
    ```
  "
  desc  'fix', "
    Perform the following step for remediation:

    Download and apply the latest quarterly Critical Patch Update patches.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ['SC-32', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['2', 'Rev_6']
  tag cis_rid: '1.1'

  command = os.windows? ? 'opatch lsinventory | find \"' + input('version') + '"' : 'opatch lsinventory | grep -e "^.*' + input('version') + '\s*.*$"'

  version = inspec.command(command)

  describe 'Check Oracle installation version and patches' do
    subject { version }
    its('stdout') { should_not be_empty }
  end
end

