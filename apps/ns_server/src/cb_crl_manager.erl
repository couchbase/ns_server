%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_crl_manager).

%% public API
-export([get_config/0,
         set_config/1]).

-define(CHRONICLE_KEY, crl_settings).
-define(DEFAULT_POLL_INTERVAL_MS, 60000).

%%%===================================================================
%%% API
%%%===================================================================

%% Returns the configuration map currently stored in chronicle (or the
%% default if unset / feature disabled).
-spec get_config() -> map().
get_config() ->
    case chronicle_compat:get(?CHRONICLE_KEY, #{default => undefined}) of
        undefined -> default_config();
        Cfg when is_map(Cfg) -> merge_default(Cfg)
    end.

-spec default_config() -> map().
default_config() ->
    #{poll_directory => default_local_crl_source_dir(),
      policy_per_scope =>
          #{client_auth => disabled,
            node_to_node => disabled},
      delta_crls => false,
      poll_interval_ms => ?DEFAULT_POLL_INTERVAL_MS}.

-spec set_config(map()) -> ok | {error, term()}.
set_config(NewCfg0) ->
    Fun =
        fun (Snapshot) ->
                CurrentRaw =
                    case maps:find(?CHRONICLE_KEY, Snapshot) of
                        {ok, {Cfg, _Rev}} -> Cfg;
                        error -> #{}
                    end,
                MergedPPS =
                    maps:merge(
                      maps:get(policy_per_scope, CurrentRaw, #{}),
                      maps:get(policy_per_scope, NewCfg0, #{})),
                Merged0 = maps:merge(CurrentRaw, NewCfg0),
                NewCfg = merge_default(
                           Merged0#{policy_per_scope => MergedPPS}),
                {commit, [{set, ?CHRONICLE_KEY, NewCfg}]}
        end,
    case chronicle_kv:transaction(kv, [?CHRONICLE_KEY], Fun, #{}) of
        {ok, _} -> ok;
        {error, Err} -> {error, Err}
    end.

%% Merge a partial config with defaults.  Performs a deep merge for
%% policy_per_scope so that missing scopes get their default values.
-spec merge_default(map()) -> map().
merge_default(Cfg) ->
    Default = default_config(),
    Merged = maps:merge(Default, Cfg),
    DefaultPPS = maps:get(policy_per_scope, Default),
    CfgPPS = maps:get(policy_per_scope, Cfg, #{}),
    Merged#{policy_per_scope => maps:merge(DefaultPPS, CfgPPS)}.

default_local_crl_source_dir() ->
    filename:join(path_config:component_path(data, "inbox"), "crls").