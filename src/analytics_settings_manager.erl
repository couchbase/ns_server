%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(analytics_settings_manager).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-behavior(json_settings_manager).

-export([start_link/0,
         get/1,
         get_from_config/3,
         update/2,
         config_default/0]).

-export([cfg_key/0,
         is_enabled/0,
         known_settings/0,
         on_update/2,
         config_upgrade_to_elixir/1]).

-import(json_settings_manager,
        [id_lens/1]).

-define(ANALYTICS_CONFIG_KEY, {metakv, <<"/analytics/settings/config">>}).

start_link() ->
    json_settings_manager:start_link(?MODULE).

get(Key) ->
    json_settings_manager:get(?MODULE, Key, []).

get_from_config(Config, Key, Default) ->
    json_settings_manager:get_from_config(?MODULE, Config, Key, Default).

cfg_key() ->
    ?ANALYTICS_CONFIG_KEY.

is_enabled() ->
    cluster_compat_mode:is_cluster_71().

on_update(_Key, _Value) ->
    ok.

update(Key, Value) ->
    json_settings_manager:update(?MODULE, [{Key, Value}]).

default_settings() ->
    [{generalSettings, general_settings_defaults(?LATEST_VERSION_NUM)}].

config_default() ->
    {?ANALYTICS_CONFIG_KEY, json_settings_manager:build_settings_json(
                              default_settings(), dict:new(),
                              known_settings(?LATEST_VERSION_NUM))}.

known_settings() ->
    ClusterVersion = cluster_compat_mode:get_ns_config_compat_version(),
    known_settings(ClusterVersion).

known_settings(ClusterVersion) ->
    [{generalSettings, general_settings_lens(ClusterVersion)}].

general_settings_defaults(ClusterVersion) ->
    [{numReplicas, 0}] ++
        case cluster_compat_mode:is_version_elixir(ClusterVersion) of
            true ->
                [
                 {blobStorageScheme, <<"">>},
                 {blobStorageBucket, <<"">>},
                 {blobStoragePrefix, <<"">>},
                 {blobStorageRegion, <<"">>}];
            false ->
                []
        end.

general_settings_lens(ClusterVersion) ->
    json_settings_manager:props_lens(
      general_settings_lens_props(ClusterVersion)).

general_settings_lens_props(ClusterVersion) ->
    [{numReplicas, id_lens(<<"analytics.settings.num_replicas">>)}] ++
        case cluster_compat_mode:is_version_elixir(ClusterVersion) of
            true ->
                [{blobStorageScheme,
                  id_lens(<<"analytics.settings.blob_storage_scheme">>)},
                 {blobStorageBucket,
                  id_lens(<<"analytics.settings.blob_storage_bucket">>)},
                 {blobStoragePrefix,
                  id_lens(<<"analytics.settings.blob_storage_prefix">>)},
                 {blobStorageRegion,
                  id_lens(<<"analytics.settings.blob_storage_region">>)}];
            false ->
                []
        end.

config_upgrade_settings(Config, OldVersion, NewVersion) ->
    NewSettings = general_settings_defaults(NewVersion) --
        general_settings_defaults(OldVersion),
    json_settings_manager:upgrade_existing_key(
      ?MODULE, Config, [{generalSettings, NewSettings}],
      known_settings(NewVersion)).

config_upgrade_to_elixir(Config) ->
    config_upgrade_settings(Config, ?VERSION_72, ?VERSION_ELIXIR).

-ifdef(TEST).
defaults_test() ->
    Keys = fun (L) -> lists:sort([K || {K, _} <- L]) end,

    ?assertEqual(Keys(known_settings(?LATEST_VERSION_NUM)), Keys(default_settings())),
    ?assertEqual(Keys(general_settings_lens_props(?LATEST_VERSION_NUM)),
                 Keys(general_settings_defaults(?LATEST_VERSION_NUM))).

config_upgrade_test() ->
    CmdList = config_upgrade_to_elixir([]),
    [{set, {metakv, Meta}, Data}] = CmdList,
    ?assertEqual(<<"/analytics/settings/config">>, Meta),
    ?assertEqual(<<"{\"analytics.settings.blob_storage_region\":\"\","
                   "\"analytics.settings.blob_storage_scheme\":\"\","
                   "\"analytics.settings.blob_storage_prefix\":\"\","
                   "\"analytics.settings.blob_storage_bucket\":\"\"}">>,
                 Data).
-endif.