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
         handle_post_settings/1]).

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
               "" -> Cfg0#{poll_directory => <<>>};
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
