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
         handle_post_diagnostics_status/1]).

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
      {directory, dir_to_json(maps:get(poll_directory, Cfg, undefined))}]}.

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
    case proplists:get_value(dirPollIntervalMs, Values) of
        undefined -> Cfg2;
        I -> Cfg2#{poll_interval_ms => I}
    end.

%%%===================================================================
%%% POST /node/controller/reloadCrl
%%%===================================================================

handle_reload_crl(Req) ->
    assert_supported(),
    case cb_crl_manager:reload() of
        {error, not_configured} ->
            menelaus_util:reply_json(
              Req,
              {[{error, <<"No CRL source directory is configured">>}]}, 400);
        {ok, StatusMap} ->
            menelaus_util:reply_json(Req, format_status_map(StatusMap))
    end.

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
                      StatusMap when is_map(StatusMap) ->
                          format_status_map(StatusMap);
                      {badrpc, Reason} ->
                          {[{error,
                             iolist_to_binary(
                               io_lib:format("~p", [Reason]))}]}
                  end,
              {Hostname, NodeJson}
      end, NodePairs, Results).

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Convert a #{LoadDirPath => StatusMap} map (from cb_crl_manager:get_status/0)
%% to an ejson object.  Each StatusMap is a plain map with keys:
%%   status (atom), entries ([EntryMap]), last_reload (map).
-spec format_status_map(#{file:filename_all() => map()}) -> term().
format_status_map(StatusMap) ->
    Props =
        maps:fold(
          fun (Path, FileStatus, Acc) ->
                  PathKey = iolist_to_binary(Path),
                  [{PathKey, file_status_to_json(FileStatus)} | Acc]
          end, [], StatusMap),
    {Props}.

%% Serialise a single per-file status map to an ejson object.
file_status_to_json(#{status      := Status,
                      entries     := Entries,
                      last_reload := LastReload}) ->
    {[{cacheStatus, status_to_json(Status)},
      {entries,     [status_entry_to_json(E) || E <- Entries]},
      {lastReload,  last_reload_to_json(LastReload)}]}.

%% Serialise the per-entry breakdown of the active copy.
status_entry_to_json(#{issuer      := Issuer,
                       status      := Status,
                       this_update := ThisUpdate,
                       next_update := NextUpdate,
                       checksum    := Checksum}) ->
    {[{issuer,     Issuer},
      {status,     status_to_json(Status)},
      {thisUpdate, format_datetime(ThisUpdate)},
      {nextUpdate, format_datetime(NextUpdate)},
      {checksum,   Checksum}]}.

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
reload_result_to_json(loaded)        -> <<"loaded">>;
reload_result_to_json(failed)        -> <<"failed">>;
reload_result_to_json(not_attempted) -> <<"notAttempted">>;
reload_result_to_json(Other)         -> iolist_to_binary(io_lib:format("~p", [Other])).

assert_supported() ->
    menelaus_util:assert_is_enterprise(),
    case cluster_compat_mode:is_cluster_totoro() of
        true -> ok;
        false ->
            menelaus_util:web_exception(
              404, "CRL feature not yet enabled in this cluster")
    end.
