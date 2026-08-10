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

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

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
                      {NewCfg} = config_to_json(cb_crl_manager:get_config()),
                      ns_audit:settings(Req, crl, {json, NewCfg}),
                      menelaus_util:reply_json(Req, {NewCfg});
                  {error, no_quorum} ->
                      reply_no_quorum();
                  {error, exceeded_retries} ->
                      reply_exceeded_retries();
                  {error, no_ootb_crl} ->
                      reply_no_ootb_crl();
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
    Status = cb_crl_manager:reload(),
    ns_audit:reload_crl(Req),
    menelaus_util:reply_json(Req, format_status_map(Status)).

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
       end, _),
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
                      Status when is_map(Status) ->
                          format_status_map(Status);
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
            {Result, _Expiry} = cb_crl:crl_check_safe(OtpCert, Policy),
            crl_result_to_props(Result)
    end.

crl_result_to_props(valid) ->
    {true, [{status, <<"valid">>}]};
crl_result_to_props({bad_cert, {revoked, Reason}}) ->
    {false, [{status, <<"revoked">>}, {details, format_crl_term(Reason)}]};
crl_result_to_props({bad_cert, {revocation_status_undetermined, Info}}) ->
    %% Not format_crl_term/1: an undetermined verdict's details can carry whole
    %% decoded CRLs (see cb_crl:format_undetermined_details/1), and this is the
    %% same text the log line gets.
    {false, [{status, <<"undetermined">>},
             {details,
              iolist_to_binary(cb_crl:format_undetermined_details(Info))}]};
crl_result_to_props({bad_cert, Reason}) ->
    {false, [{status, <<"failed">>}, {details, format_crl_term(Reason)}]};
crl_result_to_props(Reason) ->
    {false, [{status, <<"failed">>}, {details, format_crl_term(Reason)}]}.

format_crl_term(Term) ->
    iolist_to_binary(io_lib:format("~p", [Term])).

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Convert the cb_crl_manager:crl_status() from get_status/0 (or reload/0) to a
%% JSON object: the per-file statuses under "crlFiles", and the state of the
%% poll directory itself — which is not a CRL file — beside them under
%% "pollDirectory".
-spec format_status_map(cb_crl_manager:crl_status()) -> term().
format_status_map(#{files := Files, poll_directory := PollDir}) ->
    {[{crlFiles, [file_status_to_json(S) || S <- Files]} |
      poll_directory_to_json(PollDir)]}.

%% Serialise a single per-file status map to an ejson object.
-spec file_status_to_json(cb_crl_manager:crl_file_status()) -> term().
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

-spec file_source_to_json(cb_crl_manager:file_source()) -> binary().
file_source_to_json(local_dir) -> <<"localDir">>;
file_source_to_json(uploaded)  -> <<"uploaded">>;
file_source_to_json(generated) -> <<"generated">>;
file_source_to_json(url)       -> <<"url">>;
file_source_to_json(Other)     -> unmapped_to_json(file_source, Other).

%% Serialise how the last scan of the configured poll directory went, as a
%% single-element proplist so an unconfigured directory (no report at all) can
%% simply leave the field out — there is nothing to report on.
%%
%% The directory is not a CRL file: it has no source, no entries and no
%% checksum, and it reports in a vocabulary of its own (dir_status_to_json/1
%% below) rather than borrowing the per-file one.
-spec poll_directory_to_json(cb_crl_manager:dir_report() | undefined) ->
          [{atom(), term()}].
poll_directory_to_json(undefined) ->
    [];
poll_directory_to_json(#{directory := Directory,
                         status    := Status,
                         last_scan := LastScan,
                         errors    := Errors}) ->
    [{pollDirectory,
      {[{directory, Directory},
        {status,    dir_status_to_json(Status)},
        {lastScan,  format_datetime(LastScan)},
        {errors,    Errors}]}}].

%% Map a poll-directory status atom (cb_crl_manager:dir_status()) to the string
%% shown in the HTTP response.  Deliberately its own enum: 'readable' says we
%% could list the directory, not that some CRL in it is usable.  Same catch-all
%% caveat as status_to_json/1 below.
-spec dir_status_to_json(cb_crl_manager:dir_status()) -> binary().
dir_status_to_json(readable)   -> <<"readable">>;
dir_status_to_json(not_found)  -> <<"notFound">>;
dir_status_to_json(unreadable) -> <<"unreadable">>;
dir_status_to_json(Other)      -> unmapped_to_json(dir_status, Other).

%% Serialise the per-entry breakdown of the active copy.
-spec status_entry_to_json(cb_crl_manager:crl_entry()) -> term().
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
-spec last_reload_to_json(cb_crl_manager:last_reload()) -> term().
last_reload_to_json(#{result := Result, time := Time, errors := Errors}) ->
    {[{result, reload_result_to_json(Result)},
      {time,   format_datetime(Time)},
      {errors, Errors}]}.

%% Format a calendar:datetime() as an ISO-8601 UTC string, or null.
format_datetime(undefined) ->
    null;
format_datetime(DateTime) ->
    menelaus_util:format_server_time(DateTime, 0).

%% Map a status atom to the string shown in the HTTP response.  Used for both
%% the file-level status (state of the active config/crls copy) and the
%% per-entry status, which share one vocabulary: see
%% cb_crl_manager:file_status() and cb_crl_manager:entry_status().
%%
%% The catch-all clause is a safety net, not an escape hatch: every atom
%% cb_crl_manager can produce needs a clause of its own, otherwise the raw
%% Erlang atom (say <<"ok">>) leaks into the response and contradicts the
%% documented enum.  Same for reload_result_to_json/1 below.
status_to_json(active)        -> <<"active">>;
status_to_json(expired)       -> <<"expired">>;
status_to_json(not_yet_valid) -> <<"notYetValid">>;
status_to_json(untrusted)     -> <<"untrusted">>;
status_to_json(invalid)       -> <<"invalid">>;
status_to_json(not_loaded)    -> <<"notLoaded">>;
status_to_json(Other)         -> unmapped_to_json(crl_status, Other).

%% Map a reload-result atom (cb_crl_manager:reload_result()) to the string
%% shown in the HTTP response.
reload_result_to_json(loaded)            -> <<"loaded">>;
reload_result_to_json(failed)            -> <<"failed">>;
reload_result_to_json(not_attempted)     -> <<"notAttempted">>;
reload_result_to_json(uploaded)          -> <<"uploaded">>;
reload_result_to_json(not_yet_synced)    -> <<"notYetSynced">>;
reload_result_to_json(checksum_mismatch) -> <<"checksumMismatch">>;
reload_result_to_json(Other)             ->
    unmapped_to_json(reload_result, Other).

%% Reached only if cb_crl_manager grows a status value that was not added here,
%% or if a peer node in a mixed-version cluster reports one we do not know.
%% Keep the response well-formed, but leave a trace: the value that comes out
%% is outside the documented enum.
unmapped_to_json(Field, Value) ->
    ?log_warning("Unmapped CRL ~p value in status response: ~p",
                 [Field, Value]),
    iolist_to_binary(io_lib:format("~p", [Value])).

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
        ok ?= validate_content_length(Req),
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
        ns_audit:upload_crl_file(Req, Filename),
        handle_get_crl_files(Req)
    else
        {error, no_quorum} ->
            reply_no_quorum();
        {error, exceeded_retries} ->
            reply_exceeded_retries();
        {error, Reason} ->
            ReasonBin = format_upload_error(Reason),
            menelaus_util:reply_json(Req, {[{error, ReasonBin}]}, 400)
    end.

is_multipart_ct(undefined) -> false;
is_multipart_ct(CT) ->
    lists:prefix("multipart/form-data", string:to_lower(CT)).

%% mochiweb_multipart:parse_form/1 doesn't support chunked transfer encoding:
%% it feeds the Content-Length header to list_to_integer/1 unconditionally and
%% crashes with badarg if it is missing or malformed.  Check it up front so
%% that we reply with an error instead.
validate_content_length(Req) ->
    case mochiweb_request:get_combined_header_value("content-length", Req) of
        undefined ->
            {error, no_content_length};
        Value ->
            try list_to_integer(Value) of
                N when N >= 0 -> ok;
                _ -> {error, invalid_content_length}
            catch
                error:badarg -> {error, invalid_content_length}
            end
    end.

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
format_upload_error(no_content_length) ->
    <<"Content-Length header is required; chunked transfer encoding is not"
      " supported">>;
format_upload_error(invalid_content_length) ->
    <<"Invalid Content-Length header">>;
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
            ns_audit:delete_crl_file(Req, Filename),
            menelaus_util:reply_json(Req, {[]});
        {error, not_found} ->
            menelaus_util:reply_json(
              Req,
              {[{error, <<"CRL file not found">>}]}, 404);
        {error, no_quorum} ->
            reply_no_quorum();
        {error, exceeded_retries} ->
            reply_exceeded_retries();
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

reply_no_quorum() ->
    menelaus_util:web_exception(
      503, menelaus_web_secrets:format_error(no_quorum)).

reply_exceeded_retries() ->
    menelaus_util:web_exception(
      503, "Exceeded retries due to conflicting operations, please retry").

reply_no_ootb_crl() ->
    menelaus_util:web_json_exception(
      400,
      {[{error,
         <<"Revocation checking of node-to-node traffic requires a "
           "revocation list for the cluster's own CA, and this cluster has "
           "none: a CA generated by an older version has no cRLSign key "
           "usage and cannot issue one.  Regenerate the cluster CA (POST "
           "/controller/regenerateCertificate?forceResetCACertificate=true"
           "&dropUploadedCertificates=false) and try again.">>}]}).

assert_supported() ->
    menelaus_util:assert_is_enterprise(),
    case cluster_compat_mode:is_cluster_totoro() of
        true -> ok;
        false ->
            menelaus_util:web_exception(
              404, "CRL feature not yet enabled in this cluster")
    end.

-ifdef(TEST).

%% Every value cb_crl_manager can report must map to a camelCase name of its
%% own.  A snake_case result means the atom fell through to the catch-all
%% clause, i.e. the response advertises a value outside the documented enum.
status_vocabulary_test() ->
    Statuses = [active, expired, not_yet_valid, untrusted, invalid,
                not_loaded],
    Results  = [loaded, failed, not_attempted, uploaded, not_yet_synced,
                checksum_mismatch],
    Sources  = [local_dir, uploaded, generated, url],
    DirStatuses = [readable, not_found, unreadable],
    StatusJson = [status_to_json(S) || S <- Statuses] ++
                 [reload_result_to_json(R) || R <- Results],
    SourceJson = [file_source_to_json(S) || S <- Sources],
    DirJson    = [dir_status_to_json(S) || S <- DirStatuses],
    ?assertEqual([], [B || B <- StatusJson ++ SourceJson ++ DirJson,
                           binary:match(B, <<"_">>) =/= nomatch]),
    %% Distinct atoms must not collapse onto the same name.  Each enum is
    %% checked on its own: they are separate vocabularies, and reuse across
    %% them is deliberate ('uploaded' is both a source and a reload result).
    ?assertEqual(length(StatusJson), length(lists:usort(StatusJson))),
    ?assertEqual(length(SourceJson), length(lists:usort(SourceJson))),
    ?assertEqual(length(DirJson), length(lists:usort(DirJson))),
    ?assertEqual(<<"notYetValid">>, status_to_json(not_yet_valid)),
    ?assertEqual(<<"notLoaded">>, status_to_json(not_loaded)),
    ?assertEqual(<<"notFound">>, dir_status_to_json(not_found)),
    ?assertEqual(<<"notAttempted">>, reload_result_to_json(not_attempted)),
    ?assertEqual(<<"notYetSynced">>, reload_result_to_json(not_yet_synced)),
    ?assertEqual(<<"checksumMismatch">>,
                 reload_result_to_json(checksum_mismatch)).

%% The poll directory is reported beside the per-file list, never inside it,
%% and in its own vocabulary (MB-72969): a caller reading "crlFiles" gets CRL
%% files and nothing else.  An unconfigured directory leaves the field out
%% entirely.
poll_directory_to_json_test() ->
    Status = fun (PollDir) ->
                     {Json} = format_status_map(#{files          => [],
                                                  poll_directory => PollDir}),
                     Json
             end,
    NoDir = Status(undefined),
    ?assertEqual([], proplists:get_value(crlFiles, NoDir)),
    ?assertEqual(undefined, proplists:get_value(pollDirectory, NoDir)),

    Reported = Status(#{directory => <<"/crls">>,
                        status    => unreadable,
                        last_scan => {{2026, 1, 1}, {0, 0, 0}},
                        errors    => [<<"Failed to list directory">>]}),
    ?assertEqual([], proplists:get_value(crlFiles, Reported)),
    {Dir} = proplists:get_value(pollDirectory, Reported),
    ?assertEqual(<<"/crls">>, proplists:get_value(directory, Dir)),
    ?assertEqual(<<"unreadable">>, proplists:get_value(status, Dir)),
    ?assertEqual([<<"Failed to list directory">>],
                 proplists:get_value(errors, Dir)),
    %% None of the per-file fields apply to a directory.
    ?assertEqual([], [K || K <- [source, cacheStatus, entries, lastReload],
                           proplists:is_defined(K, Dir)]).

%% One response object must not describe the same healthy CRL with
%% two vocabularies — cacheStatus and entries[].status both say "active", and
%% lastReload.result reports how the file arrived rather than a bare "ok".
healthy_file_status_to_json_test() ->
    Entry = #{issuer      => <<"CN=Test CA">>,
              status      => active,
              this_update => undefined,
              next_update => undefined,
              checksum    => <<"abc">>,
              crl_number  => 1},
    {Json} = file_status_to_json(#{filename    => <<"test.pem">>,
                                   source      => uploaded,
                                   status      => active,
                                   entries     => [Entry],
                                   last_reload => #{result => uploaded,
                                                    time   => undefined,
                                                    errors => []}}),
    ?assertEqual(<<"active">>, proplists:get_value(cacheStatus, Json)),
    [{EntryJson}] = proplists:get_value(entries, Json),
    ?assertEqual(<<"active">>, proplists:get_value(status, EntryJson)),
    {Reload} = proplists:get_value(lastReload, Json),
    ?assertEqual(<<"uploaded">>, proplists:get_value(result, Reload)).

-endif.
