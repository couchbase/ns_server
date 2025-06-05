%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(ns_error_messages).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-export([decode_json_response_error/3,
         connection_error_message/3,
         engage_cluster_error/1,
         bad_memory_size_error/4,
         incompatible_cluster_version_error/3,
         too_old_version_error/2,
         verify_otp_connectivity_port_error/3,
         verify_otp_connectivity_connection_error/4,
         unsupported_services_error/2,
         topology_limitation_error/1,
         cert_validation_error_message/1,
         reload_node_certificate_error/1,
         node_certificate_warning/1,
         not_absolute_path/1,
         empty_param/1,
         preview_cluster_join_error/0,
         address_check_error/2,
         load_CAs_from_inbox_error/1,
         incompatible_product_add_node_error/2,
         too_old_prod_version_error/3,
         too_new_prod_version_error/3]).

-spec connection_error_message(term(), string(), string() | integer()) -> binary() | undefined.
connection_error_message({tls_alert, "bad record mac"}, Host, Port) ->
    list_to_binary(io_lib:format("Failed to establish TLS connection to ~s. "
                                 "Please check that you are connecting to a "
                                 "TLS / HTTPS endpoint.",
                                 [misc:join_host_port(Host, Port)]));
connection_error_message({tls_alert, {unexpected_message, Str}}, Host, Port) ->
    list_to_binary(io_lib:format("Failed to establish TLS connection to ~s. "
                                 "Please check that you are connecting to a "
                                 "TLS / HTTPS endpoint (~s)",
                                 [misc:join_host_port(Host, Port), Str]));
connection_error_message({tls_alert, {handshake_failure, Str}}, Host, Port)
                                                            when is_list(Str) ->
    list_to_binary(io_lib:format("Failed to establish TLS connection to ~s. "
                                 "TLS handshake failure (~s)",
                                 [misc:join_host_port(Host, Port), Str]));
connection_error_message({tls_alert, {unknown_ca, Str}}, Host, Port)
                                                            when is_list(Str) ->
    list_to_binary(io_lib:format("Failed to establish TLS connection to ~s. "
                                 "The certificate is issued by unknown CA or "
                                 "some of the intermediate certificates are "
                                 "missing (~s)",
                                 [misc:join_host_port(Host, Port), Str]));
connection_error_message({tls_alert, {certificate_required, Str}}, Host, Port) ->
    list_to_binary(io_lib:format("Failed to establish TLS connection to ~s. "
                                 "Certificate is required (~s)",
                                 [misc:join_host_port(Host, Port), Str]));
connection_error_message({tls_alert, M}, Host, Port) ->
    list_to_binary(io_lib:format("Failed to establish TLS connection to ~s: ~p",
                                 [misc:join_host_port(Host, Port), M]));
connection_error_message({AFamily, nxdomain}, Host, _Port) ->
    list_to_binary(io_lib:format("Unable to resolve ~s address for ~p.  "
                                 "The hostname may be incorrect or not "
                                 "resolvable.",
                                 [misc:afamily2str(AFamily), Host]));
connection_error_message({Error, _}, Host, Port) ->
    connection_error_message(Error, Host, Port);
connection_error_message(nxdomain, Host, _Port) ->
    list_to_binary(io_lib:format("Failed to resolve address for ~p.  "
                                 "The hostname may be incorrect or not resolvable.", [Host]));
connection_error_message(econnrefused, Host, Port) ->
    list_to_binary(io_lib:format("Could not connect to ~p on port ~p.  "
                                 "This could be due to an incorrect host/port combination or a "
                                 "firewall in place between the servers.", [Host, Port]));
connection_error_message(timeout, Host, Port) ->
    list_to_binary(io_lib:format("Timeout connecting to ~p on port ~p.  "
                                 "This could be due to an incorrect host/port combination or a "
                                 "firewall in place between the servers.", [Host, Port]));
connection_error_message("bad certificate", Host, Port) ->
    list_to_binary(io_lib:format("Got certificate mismatch while trying to "
                                 "send https request to ~s",
                                 [misc:join_host_port(Host, Port)]));
connection_error_message(keyfile, _, _) ->
     <<"Invalid or encrypted keyfile.">>;
connection_error_message(_, _, _) -> undefined.

-spec decode_json_response_error({ok, term()} | {error, term()},
                                 atom(),
                                 {atom(), string(), string() | integer(),
                                  string(), string(), iolist()}) ->
                                        %% English error message and nested error
                                        {error, rest_error, binary(), {error, term()} | {bad_status, integer(), string()}}.
decode_json_response_error({ok, {{200 = _StatusCode, _} = _StatusLine,
                               _Headers, _Body} = _Result},
                         _Method, _Request) ->
    %% 200 is not error
    erlang:error(bug);

decode_json_response_error({ok, {{401 = StatusCode, _}, _, Body}},
                         _Method,
                         _Request) ->
    TrimmedBody = string:substr(erlang:binary_to_list(Body), 1, 48),
    M = <<"Invalid credentials.">>,
    {error, rest_error, M, {bad_status, StatusCode, list_to_binary(TrimmedBody)}};

decode_json_response_error({ok, {{StatusCode, _}, _, Body}},
                         Method,
                         {Scheme, Host, Port, Path, _MimeType, _Payload}) ->
    TrimmedBody = string:substr(erlang:binary_to_list(Body), 1, 48),
    RealPort = if is_integer(Port) -> integer_to_list(Port);
                  true -> Port
               end,
    M = list_to_binary(io_lib:format("Got HTTP status ~p from REST call ~p to ~p://~s:~s~s. Body was: ~p",
                                     [StatusCode, Method, Scheme, Host, RealPort, Path, TrimmedBody])),
    {error, rest_error, M, {bad_status, StatusCode, list_to_binary(TrimmedBody)}};

decode_json_response_error({error, Reason} = E,
                           Method,
                           {Scheme, Host, Port, Path, _MimeType, _Payload}) ->
    M = case connection_error_message(Reason, Host, Port) of
            undefined ->
                RealPort = if is_integer(Port) -> integer_to_list(Port);
                              true -> Port
                           end,
                list_to_binary(io_lib:format("Error ~p happened during REST call ~p to ~p://~s:~s~s.",
                                             [Reason, Method, Scheme, Host, RealPort, Path]));
            X -> X
        end,
    {error, rest_error, M, E}.

engage_cluster_error({json, undefined}) ->
    <<"Cluster join prepare call returned invalid json.">>;
engage_cluster_error({json, {unexpected_json, _Where, Field}} = _Exc) ->
    list_to_binary(io_lib:format("Cluster join prepare call returned invalid "
                                 "json. Invalid field is ~s.", [Field]));
engage_cluster_error({engage_cluster_failed,
                      {Source, {tls_alert, {unknown_ca, _Str}}, DefaultMsg,
                       Hostname, _}}) ->
    list_to_binary(io_lib:format("~s. Please review the CAs "
                                 "available on the ~s (~s) and "
                                 "add a new one if required",
                                 [DefaultMsg, Source, Hostname]));
engage_cluster_error({engage_cluster_failed,
                      {_Source, Reason, DefaultMsg, Hostname, {AFamily}}})
    when Reason =:= {AFamily, nxdomain}; Reason =:= nxdomain ->
    case {misc:is_raw_ipv4(Hostname),
          misc:is_raw_ipv6(Hostname),
          AFamily} of
        {true, _, inet6} ->
            list_to_binary(io_lib:format(
              "Node is using IP version 4, and cluster is using IP "
              "version 6: ~s", [DefaultMsg]));
        {_, true, inet} ->
            list_to_binary(io_lib:format(
              "Node is using IP version 6, and cluster is using IP "
              "version 4: ~s", [DefaultMsg]));
        {_, _, _} ->
            iolist_to_binary(DefaultMsg)
    end;
engage_cluster_error({engage_cluster_failed,
                      {_Source, _Reason, DefaultMsg, _Hostname,
                       _OtherParams}}) ->
    iolist_to_binary(DefaultMsg).

bad_memory_size_error(Services0, TotalQuota, MaxQuota, Node) ->
    Services1 = lists:sort(Services0),
    Services = string:join([atom_to_list(S) || S <- Services1], ", "),

    Msg = io_lib:format("This server does not have sufficient memory to "
                        "support requested memory quota. "
                        "Total quota is ~bMB (services: ~s), "
                        "maximum allowed quota for the node ~p is ~bMB.",
                        [TotalQuota, Services, Node, MaxQuota]),
    iolist_to_binary(Msg).

incompatible_cluster_version_error(MyVersion, OtherVersion, OtherNode) ->
    case MyVersion > 1 of
        true ->
            RequiredVersion = [MyVersion div 16#10000,
                               MyVersion rem 16#10000],
            OtherVersionExpand = case OtherVersion > 1 of
                                     true ->
                                         [OtherVersion div 16#10000,
                                          OtherVersion rem 16#10000];
                                     false ->
                                         [1,8]
                                 end,
            list_to_binary(io_lib:format("This node cannot add another node (~p)"
                                         " because of cluster version compatibility mismatch. Cluster works in ~0p mode and node only supports ~0p",
                                         [OtherNode, RequiredVersion, OtherVersionExpand]));
        false ->
            list_to_binary(io_lib:format("This node cannot add another node (~p)"
                                         " because of cluster version compatibility mismatch (~p =/= ~p).",
                                         [OtherNode, MyVersion, OtherVersion]))
    end.

too_old_version_error(Node, Version) ->
    MinSupported0 = lists:map(fun integer_to_list/1,
                              cluster_compat_mode:min_supported_compat_version()),
    MinSupported = string:join(MinSupported0, "."),
    Msg = io_lib:format("Joining ~s node ~s is not supported. "
                        "Upgrade node to Couchbase Server "
                        "version ~s or greater and retry.",
                        [Version, Node, MinSupported]),
    iolist_to_binary(Msg).

too_old_prod_version_error(Node, Version, MinVersion) ->
    ProdName = cluster_compat_mode:prod_name(),
    MinSupported = binary_to_list(MinVersion),
    Msg = io_lib:format("Joining ~s ~s node ~s is not supported. "
                        "Upgrade node to version ~s or greater and retry.",
                        [Version, ProdName, Node, MinSupported]),
    iolist_to_binary(Msg).

too_new_prod_version_error(Node, Version, WantedVersion) ->
    ProdName = cluster_compat_mode:prod_name(),
    MaxSupported = binary_to_list(WantedVersion),
    Msg = io_lib:format("Joining ~s ~s node ~s is not supported. "
                        "The maximum supported version of this node is ~s.",
                        [Version, ProdName, Node, MaxSupported]),
    iolist_to_binary(Msg).

verify_otp_connectivity_port_error(_OtpNode, Host, {error, nxdomain}) ->
    list_to_binary(
      io_lib:format("Failed to resolve address for ~p. The hostname may be "
                    "incorrect or not resolvable.", [Host]));
verify_otp_connectivity_port_error(OtpNode, _Host, _Port) ->
    list_to_binary(io_lib:format("Failed to obtain otp port from erlang port mapper for node ~p."
                                 " This can be network name resolution or firewall problem.", [OtpNode])).

verify_otp_connectivity_connection_error(Reason, OtpNode, Host, Port) ->
    Detail = case connection_error_message(Reason, Host, Port) of
                 undefined -> [];
                 X -> [" ", X]
             end,
    list_to_binary(io_lib:format("Failed to reach otp port ~p for node ~p.~s",
                                 [Port, OtpNode, Detail])).

unsupported_services_error(AvailableServices, RequestedServices) ->
    list_to_binary(io_lib:format("Node doesn't support requested services: ~s. Supported services: ~s",
                                 [services_to_iolist(RequestedServices),
                                  services_to_iolist(AvailableServices)])).

services_to_iolist(Services) ->
    OrderedServices = sort_services(Services),
    ServiceToStr = ns_cluster_membership:user_friendly_service_name(_),
    misc:intersperse([ServiceToStr(S) || S <- OrderedServices], ", ").

sort_services(Services) ->
    Order = [kv, index, n1ql, fts, cbas, eventing],
    Weights = lists:zip(Order, lists:seq(1, length(Order))),
    OrderFun = fun (S1, S2) ->
                   W1 = proplists:get_value(S1, Weights, S1),
                   W2 = proplists:get_value(S2, Weights, S2),
                   W1 =< W2
               end,
    lists:usort(OrderFun, Services).

topology_limitation_error(Combinations) ->
    CombinationsStr = misc:intersperse([[$", services_to_iolist(C), $"] ||
                                           C <- Combinations], ", "),
    Msg = io_lib:format("Unsupported service combination. "
                        "Community edition supports only the following combinations: ~s",
                        [CombinationsStr]),
    iolist_to_binary(Msg).

cert_validation_error_message(empty_cert) ->
    <<"Certificate should not be empty">>;
cert_validation_error_message(not_valid_at_this_time) ->
    <<"Certificate is not valid at this time">>;
cert_validation_error_message(malformed_cert) ->
    <<"Malformed certificate">>;
cert_validation_error_message(too_many_entries) ->
    <<"Only one certificate per request is allowed.">>;
cert_validation_error_message(encrypted_certificate) ->
    <<"Encrypted certificates are not supported.">>;
cert_validation_error_message({invalid_certificate_type, BadType}) ->
    list_to_binary(io_lib:format("Invalid certificate type: ~s", [BadType]));
cert_validation_error_message(already_in_use) ->
    <<"This certificate is already in use">>.

file_read_error(enoent) ->
    "The file does not exist.";
file_read_error(eacces) ->
    "Missing permission for reading the file, or for searching one of the parent directories.";
file_read_error(eisdir) ->
    "The named file is a directory.";
file_read_error(enotdir) ->
    "A component of the file name is not a directory.";
file_read_error(enomem) ->
    "There is not enough memory for the content of the file.";
file_read_error(Reason) ->
    atom_to_list(Reason).

load_CAs_from_inbox_error({Path, empty}) ->
    list_to_binary(io_lib:format("Directory ~s is empty", [Path]));
load_CAs_from_inbox_error({File, {read, Error}}) ->
    list_to_binary(io_lib:format("Couldn't load CA certificate from ~s. ~s",
                                 [File, file_read_error(Error)]));
load_CAs_from_inbox_error({File, {bad_cert, Error}}) ->
    list_to_binary(io_lib:format("Couldn't load CA certificate from ~s. ~s",
                                 [File, cert_validation_error_message(Error)])).

reload_node_certificate_error(no_cluster_ca) ->
    <<"Cluster CA needs to be set before setting node certificate.">>;
reload_node_certificate_error(no_ca) ->
    <<"CA certificate for this chain is not found "
      "in the list of trusted CA's">>;
reload_node_certificate_error({bad_cert, {invalid_root_issuer, Subject, RootSubject}}) ->
    list_to_binary(io_lib:format("Last certificate of the chain ~p is not issued by the "
                                 "cluster root certificate ~p",
                                 [Subject, RootSubject]));
reload_node_certificate_error({bad_cert, {invalid_issuer, Subject, LastSubject}}) ->
    list_to_binary(io_lib:format("Certificate ~p is not issued by the next certificate in chain ~p",
                                 [Subject, LastSubject]));
reload_node_certificate_error({bad_cert, {Error, Subject}}) ->
    list_to_binary(io_lib:format("Incorrectly configured certificate chain. Error: ~p. Certificate: ~p",
                                 [Error, Subject]));
reload_node_certificate_error({bad_cert, max_path_length_reached}) ->
    <<"The certificate chain is too long">>;
reload_node_certificate_error({bad_chain, Error}) ->
    iolist_to_binary([<<"Incorrectly configured certificate chain. ">>,
                      cert_validation_error_message(Error)]);
reload_node_certificate_error({read_pkey, Path, Reason}) ->
    list_to_binary(io_lib:format("Unable to read private key file ~s. ~s",
                                 [Path, file_read_error(Reason)]));
reload_node_certificate_error({read_chain, Path, Reason}) ->
    list_to_binary(io_lib:format("Unable to read certificate chain file ~s. ~s",
                                 [Path, file_read_error(Reason)]));
reload_node_certificate_error({invalid_pkey_cipher, {_, _}}) ->
    <<"Invalid private key cipher. Only PKCS#5 v2.0 algorithms are supported">>;
reload_node_certificate_error({invalid_pkey, BadType}) ->
    list_to_binary(io_lib:format("Invalid private key type: ~s.",
                                 [BadType]));
reload_node_certificate_error(cert_pkey_mismatch) ->
    <<"Provided certificate doesn't match provided private key">>;
reload_node_certificate_error(no_ec_parameters) ->
    <<"Provided certificate doesn't seem to contain EC parameters">>;
reload_node_certificate_error(too_many_pkey_entries) ->
    <<"Provided private key contains incorrect number of entries">>;
reload_node_certificate_error(malformed_pkey) ->
    <<"Malformed or unsupported private key format">>;
reload_node_certificate_error(n2n_enabled) ->
    <<"Operation requires node-to-node encryption to be disabled">>;
reload_node_certificate_error({test_cert_failed, client, Host, Msg}) ->
    iolist_to_binary(io_lib:format(
      "TLS connection to ~s with provided client certificates failed. "
      "Please make sure that the client certificate is issued by a trusted CA. "
      "Details: ~s",
      [Host, Msg]));
reload_node_certificate_error({test_cert_failed, server, Host, Msg}) ->
    iolist_to_binary(io_lib:format(
      "TLS connection to a test server with provided certificates failed. "
      "Please make sure the node certificate contains '~s' in SAN. Details: ~s",
      [Host, Msg]));
reload_node_certificate_error({test_server_error, Reason}) ->
    iolist_to_binary(io_lib:format("Failed to start a test server with "
                                   "provided certificates: ~0p", [Reason],
                                   [{chars_limit, 80}]));
reload_node_certificate_error(could_not_decrypt) ->
    <<"Failed to decrypt provided private key. Check password">>;
reload_node_certificate_error({script_execution_failed,
                               {status, Status, Output}}) ->
    iolist_to_binary(io_lib:format("Script exited with status ~p:~n~s",
                                   [Status, Output]));
reload_node_certificate_error({script_execution_failed, {reason, Reason}}) ->
    iolist_to_binary(io_lib:format(
      "Script execution failed: ~s. See logs for more details.", [Reason]));
reload_node_certificate_error({script_execution_failed, exception}) ->
    <<"Script executor crashed, see logs for details">>;
reload_node_certificate_error({rest_failed, URL, {status, Status}}) ->
    iolist_to_binary(io_lib:format("REST API call ~s returned ~p",
                                   [URL, Status]));
reload_node_certificate_error({rest_failed, URL, {error, Reason}}) ->
    StrippedReason =
        case Reason of
            {Reason2, Stacktrace} when is_list(Stacktrace) -> Reason2;
            _ -> Reason
        end,
    ReasonStr = ssl:format_error(StrippedReason),
    iolist_to_binary(io_lib:format("REST API call ~s failed (~s)",
                                   [URL, ReasonStr]));
reload_node_certificate_error({rest_failed, URL, exception}) ->
    iolist_to_binary(io_lib:format("REST API call ~s crashed, see logs for "
                                   "details", [URL]));
reload_node_certificate_error({p12cert, Path, Reason}) ->
    ReasonStr = reload_node_certificate_error(Reason),
    iolist_to_binary(io_lib:format("Failed to extract certificate chain from "
                                   "p12 file \"~s\" (~s)",
                                   [Path, ReasonStr]));
reload_node_certificate_error({p12key, Path, Reason}) ->
    ReasonStr = reload_node_certificate_error(Reason),
    iolist_to_binary(io_lib:format("Failed to extract key from p12 file \"~s\" "
                                   "(~s)", [Path, ReasonStr]));
reload_node_certificate_error({openssl_error, _, {Status, Output}}) ->
    iolist_to_binary(io_lib:format("OpenSSL returned status ~b: ~s",
                                   [Status, string:trim(Output)]));
reload_node_certificate_error({openssl_error, _, Reason}) ->
    iolist_to_binary(io_lib:format("OpenSSL call failed: ~p", [Reason]));
reload_node_certificate_error({no_openssl, Path}) ->
    iolist_to_binary(io_lib:format("Openssl executable not found: ~s",
                                   [Path]));
reload_node_certificate_error({conflicting_certs, PemFile, P12File}) ->
    iolist_to_binary(io_lib:format(
                       "Conflicting cerificate files in the inbox directory: "
                       "PEM(~s) and PKCS12(~s). Please remove one of them",
                       [PemFile, P12File]));
reload_node_certificate_error(empty_pass) ->
    <<"Empty PKCS12 passwords are not supported for security reasons">>;
reload_node_certificate_error(bad_cert_identity) ->
    "@" ++ Name = ?INTERNAL_CERT_USER,
    NameBin = list_to_binary(Name),
    <<"Internal client certificate must contain "
    "SAN.email=", NameBin/binary ,"@"?INTERNAL_CERT_EMAIL_DOMAIN>>;

reload_node_certificate_error(bad_server_cert_san) ->
    reload_node_certificate_error(
        {bad_server_cert_san, misc:extract_node_address(node())});

reload_node_certificate_error({bad_server_cert_san, HostName}) ->
    iolist_to_binary(io_lib:format(
                        "Unable to validate certificate on host: ~s. "
                        "Please make sure the certificate on this host "
                        "contains host name '~s' in Subject Alternative Name. "
                        "Refer to Couchbase docs for more info on how to "
                        "create node certificates",
                        [HostName, HostName])).

node_certificate_warning(unused) ->
    <<"This certificate is auto-generated and doesn't seem to be used by any "
      "node anymore.">>;
node_certificate_warning(mismatch) ->
    <<"Certificate is not signed with cluster CA.">>;
node_certificate_warning(expired) ->
    <<"Certificate is expired.">>;
node_certificate_warning(expires_soon) ->
    <<"Certificate will expire soon.">>;
node_certificate_warning(self_signed) ->
    <<"Out-of-the-box certificates are self-signed. To further secure your system, you must create new X.509 certificates signed by a trusted CA.">>;
node_certificate_warning(cert_san_invalid) ->
    <<"Address specified in cert SAN part can't be verified.">>.

not_absolute_path(Param) ->
    Msg = io_lib:format("An absolute path is required for ~p", [Param]),
    iolist_to_binary(Msg).

empty_param(Param) ->
    iolist_to_binary(io_lib:format("~p cannot contain empty string", [Param])).

preview_cluster_join_error() ->
    <<"Can't join a developer preview cluster">>.

incompatible_product_add_node_error(undefined, LocalProdName) ->
    incompatible_product_add_node_error(?DEFAULT_PROD_NAME, LocalProdName);
incompatible_product_add_node_error(RemoteProdName, LocalProdName) ->
    iolist_to_binary(io_lib:format("~s nodes are not compatible with ~s nodes",
                                   [RemoteProdName, LocalProdName])).

%% The function returns error messages associated with calls to
%% misc:is_good_address
address_check_error(Address, {cannot_resolve, {Errno, AFamily}}) ->
    iolist_to_binary(
      io_lib:format("Unable to resolve ~s address for ~p: ~p",
                    [misc:afamily2str(AFamily), Address, Errno]));
address_check_error(Address, {cannot_listen, Errno}) ->
    iolist_to_binary(io_lib:format("Could not listen on address \"~s\": ~p",
                     [Address, Errno]));
address_check_error(Address, {address_not_allowed, ErrorMsg}) ->
    iolist_to_binary(
      io_lib:format("Requested hostname \"~s\" is not allowed: ~s",
                    [Address, ErrorMsg])).
