# encoding: UTF-8

control 'oracle19c-2.2.12' do
  title "Ensure 'SEC_PROTOCOL_ERROR_TRACE_ACTION' Is Set to 'LOG'"
  desc  "The `SEC_PROTOCOL_ERROR_TRACE_ACTION` setting determines the Oracle's
server's logging response level to bad/malformed packets received from the
client by generating `ALERT`, `LOG`, or `TRACE` levels of detail in the log
files. This setting should have a value of `LOG` unless the organization has a
compelling reason to use a different value because `LOG` should cause the
necessary information to be logged. Setting the value as `TRACE` can generate
an enormous amount of log output and should be reserved for debugging only."
  desc  'rationale', "Bad packets received from the client can potentially
indicate packet-based attacks on the system, which could result in a
denial-of-service condition."
  desc  'check', "
    To assess this recommendation, execute the following SQL statement.
    ```
    SELECT UPPER(VALUE)
    FROM V$SYSTEM_PARAMETER
    WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_TRACE_ACTION';
    ```
    Ensure `VALUE` is set to `LOG`.
  "
  desc  'fix', "
    To remediate this setting, execute the following SQL statement.
    ```
    ALTER SYSTEM SET SEC_PROTOCOL_ERROR_TRACE_ACTION=LOG SCOPE = SPFILE;
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
  tag nist: ['AU-12', 'Rev_4']
  tag cis_level: 1
  tag cis_controls: ['6.2', 'Rev_6']
  tag cis_rid: '2.2.12'
end

