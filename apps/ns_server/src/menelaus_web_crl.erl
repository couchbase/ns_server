%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included
%% in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
%% in that file, in accordance with the Business Source License, use of this
%% software will be governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.
%%
%% @doc REST handlers for CRL configuration and diagnostics.
%%
-module(menelaus_web_crl).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-export([handle_get_settings/1,
         handle_post_settings/1,
         handle_reload_crl/1,
         handle_get_diagnostics_status/1,
         handle_post_diagnostics_status/1,
         handle_post_diagnostics_validate/1,
         handle_get_crl_files/1,
         handle_post_crl_file/1,
         handle_delete_crl_file/2]).

%%%===================================================================
%%% GET /settings/crl
%%%===================================================================

handle_get_settings(Req) ->
    assert_supported(),
    Cfg = cb_crl_manager:get_config(),
    menelaus_util:reply_json(Req, config_to_json(Cfg)).

config_to_json(Cfg) ->
    {[{policyPerScope,
       {[{scope_to_json(K), mode_to_json(V)}
         || {K, V} <- maps:to_list(maps:get(policy_per_scope, Cfg, #{}))]}},
      {dirPollIntervalMs, maps:get(poll_interval_ms, Cfg, undefined)},
      {directory, dir_to_json(maps:get(poll_directory, Cfg, undefined))},
      {checkIntermediateCerts, maps:get(check_intermediate_certs, Cfg, false)},
      {urls, [iolist_to_binary(U) || U <- maps:get(crl_urls, Cfg, [])]},
      {urlPollIntervalMs, maps:get(url_poll_interval_ms, Cfg, undefined)}]}.

scope_to_json(client_auth) -> <<"clientAuth">>;
scope_to_json(node_to_node) -> <<"nodeToNode">>.

mode_to_json(disabled) -> <<"Disabled">>;
mode_to_json(permissive) -> <<"Permissive">>;
mode_to_json(require) -> <<"Require">>.

dir_to_json(undefined) -> <<>>;
dir_to_json(P) -> iolist_to_binary(P).

%%%===================================================================
%%% POST /settings/crl
%%%===================================================================

handle_post_settings(Req) ->
    assert_supported(),
    validator:handle(
      fun (Values) ->
              Cfg = build_config(Values),
              case cb_crl_manager:set_config(Cfg) of
                  ok ->
                      %% Wait for the new config to be applied before
                      %% returning, so subsequent requests see the new state.
                      cb_crl_manager:sync(),
                      %% Re-read to get the fully merged config with defaults.
                      menelaus_util:reply_json(
                        Req, config_to_json(cb_crl_manager:get_config()));
                  {error, R} ->
                      menelaus_util:reply_json(
                        Req,
                        {[{error, iolist_to_binary(
                                    io_lib:format("~p", [R]))}]}, 400)
              end
      end, Req, json, post_validators()).

post_validators() ->
    [validator:string(directory, _),
     validator:integer(dirPollIntervalMs, 1000, 24 * 3600 * 1000, _),
     validator:validate(fun (V) -> parse_pps_value(V) end,
                        policyPerScope, _),
     validator:boolean(checkIntermediateCerts, _),
     validator:validate(fun parse_urls_value/1, urls, _),
     validator:integer(urlPollIntervalMs, 1000, 24 * 3600 * 1000, _),
     validator:unsupported(_)].

parse_pps_value({Props}) when is_list(Props) ->
    parse_pps(Props, #{});
parse_pps_value(_) ->
    {error, "policyPerScope must be a JSON object"}.

parse_pps([], Acc) -> {value, Acc};
parse_pps([{K, V} | T], Acc) when is_binary(K), is_binary(V) ->
    case {scope_atom(K), mode_atom(V)} of
        {undefined, _} -> {error, "unknown scope: " ++ binary_to_list(K)};
        {_, undefined} -> {error, "unknown mode: " ++ binary_to_list(V)};
        {S, M} -> parse_pps(T, Acc#{S => M})
    end;
parse_pps(_, _) ->
    {error, "policyPerScope entries must be string:string"}.

scope_atom(<<"clientAuth">>) -> client_auth;
scope_atom(<<"nodeToNode">>) -> node_to_node;
scope_atom(_) -> undefined.

parse_urls_value(Arr) when is_list(Arr) ->
    parse_url_list(Arr, []);
parse_urls_value(_) ->
    {error, "urls must be a JSON array"}.

parse_url_list([], Acc) ->
    Res = lists:uniq(lists:reverse(Acc)),
    Max = ?get_param(max_crl_url_num, 100),
    case length(Res) =< Max of
        true -> {value, Res};
        false -> {error, io_lib:format("maximum number of URLs is ~b", [Max])}
    end;
parse_url_list([U | Rest], Acc) when is_binary(U) ->
    Validation = fun (S) ->
                     case lists:member(S, [<<"http">>, <<"https">>]) of
                         true  -> valid;
                         false -> {error, invalid_scheme}
                     end
                 end,
    case misc:parse_url(binary_to_list(U),
                        [{scheme_validation_fun, Validation}]) of
        {ok, _} ->
            parse_url_list(Rest, [U | Acc]);
        {error, _} ->
            {error, io_lib:format("invalid URL: ~s", [U])}
    end;
parse_url_list(_, _) ->
    {error, "urls entries must be strings"}.

mode_atom(<<"Disabled">>) -> disabled;
mode_atom(<<"Permissive">>) -> permissive;
mode_atom(<<"Require">>) -> require;
mode_atom(_) -> undefined.

%% Build a config map from POST values using SET semantics.
%% Missing fields are omitted (will get defaults from merge_config).
build_config(Values) ->
    Cfg0 = #{},
    Cfg1 = case proplists:get_value(directory, Values) of
               undefined -> Cfg0;
               "" -> Cfg0#{poll_directory => undefined};
               D -> Cfg0#{poll_directory => iolist_to_binary(D)}
           end,
    Cfg2 = case proplists:get_value(policyPerScope, Values) of
               undefined -> Cfg1;
               PPS when is_map(PPS) -> Cfg1#{policy_per_scope => PPS}
           end,
    Cfg3 = case proplists:get_value(dirPollIntervalMs, Values) of
               undefined -> Cfg2;
               I -> Cfg2#{poll_interval_ms => I}
           end,
    Cfg4 = case proplists:get_value(checkIntermediateCerts, Values) of
               undefined -> Cfg3;
               V -> Cfg3#{check_intermediate_certs => V}
           end,
    Cfg5 = case proplists:get_value(urls, Values) of
               undefined -> Cfg4;
               Urls -> Cfg4#{crl_urls => Urls}
           end,
    case proplists:get_value(urlPollIntervalMs, Values) of
        undefined -> Cfg5;
        I2 -> Cfg5#{url_poll_interval_ms => I2}
    end.

%%%===================================================================
%%% POST /node/controller/reloadCrl
%%%===================================================================

handle_reload_crl(Req) ->
    assert_supported(),
    StatusList = cb_crl_manager:reload(),
    menelaus_util:reply_json(Req, format_status_map(StatusList)).

%%%===================================================================
%%% POST /settings/crl/diagnostics/status
%%%===================================================================

%% Timeout for each per-node cb_crl_manager:get_status() RPC call.
-define(STATUS_CALL_TIMEOUT_MS, ?get_timeout(status_call_timeout, 60000)).

%% GET: nodes as a comma-separated query parameter.
%%   ?nodes=node0.localhost%3A9000%2Cnode1.localhost%3A9001
handle_get_diagnostics_status(Req) ->
    assert_supported(),
    do_diagnostics_status(Req, qs, diag_status_validators_qs(Req)).

%% POST: nodes as a JSON array in the request body, for when the list
%% is too long to fit in a query string.
handle_post_diagnostics_status(Req) ->
    assert_supported(),
    do_diagnostics_status(Req, json, diag_status_validators_json(Req)).

do_diagnostics_status(Req, ParseMode, Validators) ->
    validator:handle(
      fun (Values) ->
              NodePairs =
                  case proplists:get_value(nodes, Values) of
                      undefined ->
                          %% Default: every active node in the cluster.
                          %% get_hostnames/2 returns [{ErlNode, HostnameBin}].
                          Nodes = ns_node_disco:nodes_actual(),
                          menelaus_web_node:get_hostnames(Req, Nodes);
                      Pairs when is_list(Pairs) ->
                          %% Already resolved to {ErlNode, HostnameBin}
                          %% by the respective validator.
                          Pairs
                  end,
              UniqPairs = lists:uniq(fun ({Node, _}) -> Node end, NodePairs),
              Results = collect_crl_status(UniqPairs),
              menelaus_util:reply_json(Req, {Results})
      end, Req, ParseMode, Validators).

%% GET: split the single comma-separated string into individual
%% hostnames, then resolve each one.
diag_status_validators_qs(Req) ->
    [validator:validate(
       fun (NodesStr) ->
               Hostnames = [string:trim(H)
                            || H <- string:tokens(NodesStr, ","),
                               string:trim(H) =/= ""],
               resolve_hostnames(Hostnames, Req)
       end, nodes, _),
     validator:unsupported(_)].

%% POST: nodes arrives as a JSON array of strings.
diag_status_validators_json(Req) ->
    [validator:string_array(
       nodes,
       fun (Hostname) ->
               case menelaus_web_node:find_node_hostname(
                      Hostname, Req, any) of
                   {ok, Node} ->
                       {value, {Node, list_to_binary(Hostname)}};
                   {error, _} ->
                       {error, "unknown node"}
               end
       end, true, _),
     validator:unsupported(_)].

resolve_hostnames([], _Req) ->
    {value, []};
resolve_hostnames(Hostnames, Req) ->
    Results = [case menelaus_web_node:find_node_hostname(H, Req, any) of
                   {ok, Node} -> {ok, {Node, list_to_binary(H)}};
                   {error, _} -> {error, "unknown node: " ++ H}
               end || H <- Hostnames],
    case [E || {error, E} <- Results] of
        [Err | _] -> {error, Err};
        []        -> {value, [P || {ok, P} <- Results]}
    end.

%% Call cb_crl_manager:get_status() on each target node in parallel and
%% return an ejson proplist keyed by hostname binary.
%%
%% Per-node errors (node down, RPC timeout) are surfaced as
%% {"error": "<reason>"} objects rather than failing the whole request,
%% so the caller can tell which nodes responded and which did not.
-spec collect_crl_status([{node(), binary()}]) -> [{binary(), term()}].
collect_crl_status(NodePairs) ->
    Results =
        misc:parallel_map(
          fun ({Node, _Hostname}) ->
                  rpc:call(Node, cb_crl_manager, get_status, [],
                           ?STATUS_CALL_TIMEOUT_MS)
          end, NodePairs, ?STATUS_CALL_TIMEOUT_MS + 1000),
    lists:zipwith(
      fun ({_Node, Hostname}, NodeResult) ->
              NodeJson =
                  case NodeResult of
                      StatusList when is_list(StatusList) ->
                          format_status_map(StatusList);
                      {badrpc, Reason} ->
                          {[{error,
                             iolist_to_binary(
                               io_lib:format("~p", [Reason]))}]}
                  end,
              {Hostname, NodeJson}
      end, NodePairs, Results).

%%%===================================================================
%%% POST /settings/crl/diagnostics/validate
%%%===================================================================

%% Diagnostic/test endpoint for exercising CRL revocation checking with
%% greater flexibility than /_cbauth/crlsValidate.
%%
%% Unlike the regular CRL check, this endpoint IGNORES the policy currently
%% configured for any scope (even when that policy is 'Disabled') and uses a
%% caller-supplied test policy instead.  The policy defaults to 'Require'
%% (strict) when not specified, and 'Disabled' is not an accepted value (there
%% is nothing to test with a disabled policy).
%%
%% The CRL check itself is scope-agnostic (a cert is checked against the loaded
%% CRLs under the given policy), so there is no scope parameter.
%%
%% All certificates in a chain are checked (not just the leaf).
%% A self-signed root cannot be revoked by a CRL and is reported valid
%% without a CRL lookup.
%%
%% Two modes:
%%   * certs supplied — each supplied entry is decoded and every certificate in
%%     it is checked independently against the loaded CRLs under the test
%%     policy; one result per cert.  Each entry may be a PEM string (whose
%%     whole chain is checked) or a single base64-encoded DER certificate.
%%   * certs omitted  — the cluster's own certificates (every certificate in
%%     the stored chain of both the client and node certs for every node) are
%%     checked.  The response reports whether all are allowed and lists any
%%     that are not.
handle_post_diagnostics_validate(Req) ->
    assert_supported(),
    validator:handle(
      fun (Values) ->
              Policy = proplists:get_value(policy, Values),
              DerCerts = proplists:get_value(certs, Values),
              Body =
                  case DerCerts of
                      undefined -> validate_cluster_certs(Policy);
                      _         -> validate_supplied_certs(DerCerts, Policy)
                  end,
              menelaus_util:reply_json(
                Req, {[{policy, mode_to_json(Policy)} | Body]})
      end, Req, json, validate_post_validators()).

validate_post_validators() ->
    [%% 'Disabled' is intentionally not allowed: the test policy must
     %% actually exercise the CRL check.  Defaults to 'Require' (strict).
     validator:string(policy, _),
     validator:one_of(policy, ["Permissive", "Require"], _),
     validator:convert(policy, fun (P) -> mode_atom(list_to_binary(P)) end, _),
     validator:default(policy, require, _),
     validator:string_array(certs, fun decode_cert_input/1, _),
     validator:validate(
       fun (L) ->
               case length(L) > 100 of
                   true  -> {error, "too many certificates"};
                   false -> ok
               end
       end, certs, _),
     validator:unsupported(_)].

%% Accept a certificate (or chain) either as a PEM string or as base64-encoded
%% DER.  PEM is detected by its "-----BEGIN" header, in which case every
%% certificate in the chain is returned; base64 DER is a single certificate.
%% Returns a non-empty list of DER binaries.
decode_cert_input(C) ->
    Bin = list_to_binary(C),
    case string:find(Bin, <<"-----BEGIN">>) of
        nomatch ->
            try {value, [base64:decode(Bin)]}
            catch _:_ -> {error, "Invalid base64 encoding"} end;
        _ ->
            case ns_server_cert:decode_cert_chain(Bin) of
                {ok, [_ | _] = DerChain} -> {value, DerChain};
                _                        -> {error, "Invalid PEM certificate"}
            end
    end.

%% Per-cert mode: check every supplied cert independently.  A PEM entry may
%% carry a chain, in which case every certificate in it is checked.
validate_supplied_certs(CertChains, Policy) ->
    Results = [{Props} || {_Allowed, Props}
                              <- [check_der_cert(D, Policy)
                                  || Chain <- CertChains, D <- Chain]],
    [{results, Results}].

%% Cluster mode: check the cluster's own certs (both client and node certs
%% for every node).
validate_cluster_certs(Policy) ->
    Checked =
        [begin
             {Allowed, Props} = check_der_cert(Der, Policy),
             FullProps = [{node, atom_to_binary(Node, utf8)},
                          {certificateType, atom_to_binary(CertType, utf8)}
                          | Props],
             {Allowed, {FullProps}}
         end || {Node, CertType, Der} <- collect_cluster_certs()],
    Results    = [R || {_, R} <- Checked],
    Disallowed = [R || {false, R} <- Checked],
    [{usingClusterCertificates, true},
     {certificatesChecked, length(Results)},
     {allAllowed, Disallowed =:= []},
     {results, Results},
     {disallowed, Disallowed}].

%% Gather every certificate in the stored chain of both types (client_cert and
%% node_cert) from every node in the cluster.  Nodes without a stored cert of a
%% given type are skipped.
collect_cluster_certs() ->
    [{Node, CertType, Der}
     || Node     <- ns_node_disco:nodes_wanted(),
        CertType <- [client_cert, node_cert],
        {ok, DerChain} <- [chain_certs(Node, CertType)],
        Der            <- DerChain].

chain_certs(Node, CertType) ->
    Props = ns_server_cert:get_cert_info(CertType, Node),
    case proplists:get_value(pem, Props) of
        undefined -> error;
        Pem ->
            case ns_server_cert:decode_cert_chain(Pem) of
                {ok, [_ | _] = DerChain} -> {ok, DerChain};
                _                        -> error
            end
    end.

%% Decode a cert and run the CRL check under the explicit test policy.
%% Returns {Allowed :: boolean(), JsonProps :: [{atom(), term()}]}.
%% Only the decode is guarded so that an unexpected failure elsewhere is not
%% mislabelled as a "cert decode error".
check_der_cert(Der, Policy) ->
    try public_key:pkix_decode_cert(Der, otp) of
        OtpCert ->
            Subject = unicode:characters_to_binary(
                        ns_server_cert:get_subject(OtpCert)),
            {Allowed, StatusProps} = check_otp_cert(OtpCert, Policy),
            {Allowed, [{subject, Subject} | StatusProps]}
    catch
        C:E:ST ->
            ?log_error("CRL validate cert decode error ~p:~p~n~p", [C, E, ST]),
            {false, [{status, <<"failed">>},
                     {details, <<"cert decode error">>}]}
    end.

%% A self-signed root cannot be revoked by a CRL (it would have to revoke
%% itself), so it is reported valid without a CRL lookup — matching the
%% production check_intermediate_certs behaviour in cb_crl, which skips
%% self-signed certs.  All other certs (leaf and intermediate CAs) are checked.
check_otp_cert(OtpCert, Policy) ->
    case public_key:pkix_is_self_signed(OtpCert) of
        true ->
            {true, [{status, <<"valid">>},
                    {details, <<"self-signed root; not CRL-checked">>}]};
        false ->
            {Result, _Expiry} = cb_crl:crl_check(OtpCert, Policy),
            crl_result_to_props(Result)
    end.

crl_result_to_props(valid) ->
    {true, [{status, <<"valid">>}]};
crl_result_to_props({fail, {bad_cert, {revoked, Reason}}}) ->
    {false, [{status, <<"revoked">>}, {details, format_crl_term(Reason)}]};
crl_result_to_props({fail, {bad_cert,
                            {revocation_status_undetermined, Info}}}) ->
    {false, [{status, <<"undetermined">>}, {details, format_crl_term(Info)}]};
crl_result_to_props({fail, {bad_cert, Reason}}) ->
    {false, [{status, <<"failed">>}, {details, format_crl_term(Reason)}]};
crl_result_to_props({fail, Reason}) ->
    {false, [{status, <<"failed">>}, {details, format_crl_term(Reason)}]}.

format_crl_term(Term) ->
    iolist_to_binary(io_lib:format("~p", [Term])).

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Convert a [StatusMap] list (from cb_crl_manager:get_status/0) to a
%% JSON array.  Each StatusMap is a plain map produced by build_status_map/1.
-spec format_status_map([map()]) -> [term()].
format_status_map(StatusList) ->
    [file_status_to_json(S) || S <- StatusList].

%% Serialise a single per-file status map to an ejson object.
file_status_to_json(#{filename    := Filename,
                      source      := Source,
                      status      := Status,
                      entries     := Entries,
                      last_reload := LastReload}) ->
    {[{filename,    Filename},
      {source,      file_source_to_json(Source)},
      {cacheStatus, status_to_json(Status)},
      {entries,     [status_entry_to_json(E) || E <- Entries]},
      {lastReload,  last_reload_to_json(LastReload)}]}.

file_source_to_json(local_dir) -> <<"localDir">>;
file_source_to_json(uploaded)  -> <<"uploaded">>;
file_source_to_json(generated) -> <<"generated">>;
file_source_to_json(url)       -> <<"url">>.

%% Serialise the per-entry breakdown of the active copy.
status_entry_to_json(#{issuer      := Issuer,
                       status      := Status,
                       this_update := ThisUpdate,
                       next_update := NextUpdate,
                       checksum    := Checksum,
                       crl_number  := CrlNum}) ->
    {[{issuer,     Issuer},
      {status,     status_to_json(Status)},
      {thisUpdate, format_datetime(ThisUpdate)},
      {nextUpdate, format_datetime(NextUpdate)},
      {checksum,   Checksum},
      {crlNumber,  case CrlNum of undefined -> null; N -> N end}]}.

%% Serialise the last-reload-attempt information.
last_reload_to_json(#{result := Result, time := Time, errors := Errors}) ->
    {[{result, reload_result_to_json(Result)},
      {time,   format_datetime(Time)},
      {errors, Errors}]}.

%% Format a calendar:datetime() as an ISO-8601 UTC string, or null.
format_datetime(undefined) ->
    null;
format_datetime(DateTime) ->
    menelaus_util:format_server_time(DateTime, 0).

%% Map a current-status atom (state of the active config/crls copy) to the
%% string shown in the HTTP response.
status_to_json(active)        -> <<"active">>;
status_to_json(expired)       -> <<"expired">>;
status_to_json(not_yet_valid) -> <<"notYetValid">>;
status_to_json(untrusted)     -> <<"untrusted">>;
status_to_json(invalid)       -> <<"invalid">>;
status_to_json(not_loaded)    -> <<"notLoaded">>;
status_to_json(Other)         -> iolist_to_binary(io_lib:format("~p", [Other])).

%% Map a reload-result atom to the string shown in the HTTP response.
reload_result_to_json(loaded)            -> <<"loaded">>;
reload_result_to_json(failed)            -> <<"failed">>;
reload_result_to_json(not_attempted)     -> <<"notAttempted">>;
reload_result_to_json(uploaded)          -> <<"uploaded">>;
reload_result_to_json(not_downloaded)    -> <<"notDownloaded">>;
reload_result_to_json(checksum_mismatch) -> <<"checksumMismatch">>;
reload_result_to_json(read_error)        -> <<"readError">>;
reload_result_to_json(Other)             ->
    iolist_to_binary(io_lib:format("~p", [Other])).

%%%===================================================================
%%% GET /settings/crl/files
%%%===================================================================

handle_get_crl_files(Req) ->
    assert_supported(),
    Files = cb_crl_manager:get_crl_files_metadata(),
    menelaus_util:reply_json(
      Req, [file_meta_to_json(N, I) || {N, I} <- maps:to_list(Files)]).

%%%===================================================================
%%% POST /settings/crl/files
%%%===================================================================

handle_post_crl_file(Req) ->
    assert_supported(),
    CT = mochiweb_request:get_header_value("content-type", Req),
    maybe
        ok ?= case is_multipart_ct(CT) of
                  true -> ok;
                  false -> {error, not_multipart}
               end,
        Fields = mochiweb_multipart:parse_form(Req),
        %% Keep only file fields (content-type is a tuple);
        %% ignore plain text fields.
        Files = [{Filename, Body} || {_Field, {Filename, _CT, Body}} <- Fields],
        {ok, {Filename, Body}} ?= case Files of
                                      [] -> {error, no_file};
                                      [_, _ | _] -> {error, too_many_files};
                                      [{F, B}] -> {ok, {F, B}}
                                  end,
        ok ?= validate_upload_filename(Filename),
        ok ?= cb_crl_manager:upload_crl_file(Filename, Body),
        handle_get_crl_files(Req)
    else
        {error, Reason} ->
            ReasonBin = format_upload_error(Reason),
            menelaus_util:reply_json(Req, {[{error, ReasonBin}]}, 400)
    end.

is_multipart_ct(undefined) -> false;
is_multipart_ct(CT) ->
    lists:prefix("multipart/form-data", string:to_lower(CT)).

validate_upload_filename(Filename) ->
    case Filename =/= [] andalso length(Filename) =< 255 andalso
         lists:all(fun safe_filename_char/1, Filename) andalso
         Filename /= "." andalso Filename /= ".." of
        true  -> ok;
        false -> {error, invalid_filename}
    end.

safe_filename_char(C) ->
    (C >= $a andalso C =< $z) orelse
    (C >= $A andalso C =< $Z) orelse
    (C >= $0 andalso C =< $9) orelse
    C =:= $. orelse C =:= $- orelse C =:= $_.

format_upload_error(not_multipart) ->
    <<"Content-Type must be multipart/form-data">>;
format_upload_error(no_file) ->
    <<"No file found in multipart form data">>;
format_upload_error(too_many_files) ->
    <<"Multiple files found in multipart form data; only one is allowed">>;
format_upload_error(invalid_filename) ->
    <<"Invalid filename: must be 1-255 characters of letters, digits, dot,"
      " hyphen, or underscore, and cannot be . or ..">>;
format_upload_error({invalid_entries, Errors}) ->
    Joined = lists:join(<<"; ">>, Errors),
    iolist_to_binary(["CRL validation failed: " | Joined]);
format_upload_error({decode_error, Reason}) ->
    misc:format_bin("Failed to decode CRL: ~s", [format_upload_error(Reason)]);
format_upload_error({invalid_crl, _Reason}) ->
    %% Reason contains an asn1 stacktrace, no need to return it
    <<"Invalid CRL">>;
format_upload_error(Reason) ->
    iolist_to_binary(io_lib:format("~p", [Reason])).

%%%===================================================================
%%% DELETE /settings/crl/files/:filename
%%%===================================================================

handle_delete_crl_file(Filename, Req) ->
    assert_supported(),
    case cb_crl_manager:delete_crl_file(Filename) of
        ok ->
            menelaus_util:reply_json(Req, {[]});
        {error, not_found} ->
            menelaus_util:reply_json(
              Req,
              {[{error, <<"CRL file not found">>}]}, 404);
        {error, Reason} ->
            menelaus_util:reply_json(
              Req,
              {[{error, iolist_to_binary(
                          io_lib:format("~p", [Reason]))}]}, 400)
    end.

%%%===================================================================
%%% JSON helpers for file metadata
%%%===================================================================

file_meta_to_json(NameBin,
                  #{checksum         := Sum,
                    upload_timestamp := UpTS,
                    entries          := Entries}) ->
    {[{filename,        NameBin},
      {checksum,        Sum},
      {uploadTimestamp, format_datetime(UpTS)},
      {entries,         [entry_meta_to_json(E) || E <- Entries]}]}.

entry_meta_to_json(#{issuer      := Issuer,
                     this_update := TU,
                     next_update := NU,
                     crl_number  := Num}) ->
    {[{issuer,     Issuer},
      {thisUpdate, format_datetime(TU)},
      {nextUpdate, format_datetime(NU)},
      {crlNumber,  case Num of undefined -> null; N -> N end}]}.

%%%===================================================================
%%% Helpers
%%%===================================================================

assert_supported() ->
    menelaus_util:assert_is_enterprise(),
    case cluster_compat_mode:is_cluster_totoro() of
        true -> ok;
        false ->
            menelaus_util:web_exception(
              404, "CRL feature not yet enabled in this cluster")
    end.
