%% @author Couchbase <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(menelaus_web_guardrails).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("ns_test.hrl").
-endif.

-export([handle_get/2, handle_post/2]).

-export([default_for_ns_config/0,
         default_for_metakv/0,
         config_upgrade_to_76/1,
         config_upgrade_to_morpheus/1,
         build_json_for_audit/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

handle_get(Path, Req) ->
    menelaus_util:assert_is_76(),
    case cluster_compat_mode:is_cluster_morpheus() of
        false -> menelaus_util:assert_config_profile_flag({resource_management,
                                                           enabled});
        true -> ok
    end,

    menelaus_web_settings2:handle_get(Path, filtered_params(), undefined,
                                      get_full_config(), Req).

handle_post(Path, Req) ->
    menelaus_util:assert_is_76(),
    case cluster_compat_mode:is_cluster_morpheus() of
        false -> menelaus_util:assert_config_profile_flag({resource_management,
                                                           enabled});
        true -> ok
    end,

    menelaus_web_settings2:handle_post(
      fun (Params, Req2) ->
              case Params of
                  [] -> ok;
                  _ ->
                      Values = update_config(Params),
                      ns_audit:resource_management(Req, Values)
              end,
              handle_get(Path, Req2)
      end, Path, filtered_params(), undefined, get_full_config(), [], Req).

get_full_config() ->
    IndexConfig = index_settings_manager:get(guardrails),
    MetakvConfig = [{index, IndexConfig} || IndexConfig =/= undefined],
    [{metakv, MetakvConfig} | guardrail_monitor:get_config()].

filtered_params() ->
    Configurables = config_profile:search({resource_management, configurables},
                                          []),
    Params = params(),
    lists:filter(
      fun ({ParamPath, _}) ->
              lists:any(
                fun (Prefix) ->
                        %% Filter any path matching the filter prefix
                        lists:sublist(ParamPath, length(Prefix)) =:= Prefix
                end, Configurables)
      end, Params).

params() ->
    [
     %% Bucket resident ratio configuration
     {"bucket.residentRatio.enabled",
      #{type => bool,
        cfg_key => [bucket, resident_ratio, enabled]}},
     {"bucket.residentRatio.couchstoreMinimum",
      #{type => {num, 0, 100},
        cfg_key => [bucket, resident_ratio, couchstore_minimum]}},
     {"bucket.residentRatio.magmaMinimum",
      #{type => {num, 0, 100},
        cfg_key => [bucket, resident_ratio, magma_minimum]}},
     %% Max data per node per bucket configuration
     {"bucket.dataSizePerNode.enabled",
      #{type => bool,
        cfg_key => [bucket, data_size, enabled]}},
     {"bucket.dataSizePerNode.couchstoreMaximum",
      #{type => {num, 0, infinity},
        cfg_key => [bucket, data_size, couchstore_maximum]}},
     {"bucket.dataSizePerNode.magmaMaximum",
      #{type => {num, 0, infinity},
        cfg_key => [bucket, data_size, magma_maximum]}},
     %% Max number of collections per memory quota in MB
     {"bucket.collectionsPerQuota.enabled",
      #{type => bool,
        cfg_key => [collections_per_quota, enabled]}},
     {"bucket.collectionsPerQuota.maximum",
      #{type => {num, 0, infinity},
        cfg_key => [collections_per_quota, maximum]}},
     %% Index service resident ratio configuration
     {"index.indexCreationRR.enabled",
      #{type => bool,
        cfg_key => [metakv, index, index_creation_rr, enabled]}},
     {"index.indexCreationRR.minimum",
      #{type => {num, 0, 100},
        cfg_key => [metakv, index, index_creation_rr, minimum]}},
     {"index.topologyChangeRR.enabled",
      #{type => bool,
        cfg_key => [metakv, index, topology_change_rr, enabled]}},
     {"index.topologyChangeRR.minimum",
      #{type => {num, 0, 100},
        cfg_key => [metakv, index, topology_change_rr, minimum]}},
     {"index.indexGrowthRR.enabled",
      #{type => bool,
        cfg_key => [index, index_growth_rr, enabled]}},
     {"index.indexGrowthRR.critical",
      #{type => {num, 0, 100},
        cfg_key => [index, index_growth_rr, critical]}},
     {"index.indexGrowthRR.serious",
      #{type => {num, 0, 100},
        cfg_key => [index, index_growth_rr, serious]}},
     {"index.indexGrowthRR.warning",
      #{type => {num, 0, 100},
        cfg_key => [index, index_growth_rr, warning]}},
     %% Index service overhead configuration
     {"index.indexOverheadPerNode.enabled",
      #{type => bool,
        cfg_key => [metakv, index, index_overhead_per_node, enabled]}},
     {"index.indexOverheadPerNode.maximum",
      #{type => {num, 0, infinity},
        cfg_key => [metakv, index, index_overhead_per_node, maximum]}},
     %% Disk usage % per node thresholds (for notifying index service)
     {"index.diskUsage.enabled",
      #{type => bool,
        cfg_key => [index, disk_usage, enabled]}},
     {"index.diskUsage.critical",
      #{type => {num, 0, 100},
        cfg_key => [index, disk_usage, critical]}},
     {"index.diskUsage.serious",
      #{type => {num, 0, 100},
        cfg_key => [index, disk_usage, serious]}},
     %% Max disk usage % per node for disabling data service mutations
     {"diskUsage.enabled",
      #{type => bool,
        cfg_key => [disk_usage, enabled]}},
     {"diskUsage.maximum",
      #{type => {num, 0, 100},
        cfg_key => [disk_usage, maximum]}},
     %% Min number of cores per node per bucket
     {"coresPerBucket.enabled",
      #{type => bool,
        cfg_key => [cores_per_bucket, enabled]}},
     {"coresPerBucket.minimum",
      #{type => {num, 0, infinity},
        cfg_key => [cores_per_bucket, minimum]}}
    ].

%% Gets resource management configuration from the config profile, using default
%% values specified below
-spec default_for_ns_config() -> proplists:proplist().
default_for_ns_config() ->
    %% Override defaults with any values specified in the config profile
    lists:foldl(
        fun update_sub_config/2, raw_default_for_ns_config(),
        config_profile:get_value(resource_management, [])).

default_for_metakv() ->
    %% Override defaults with any values specified in the config profile
    lists:foldl(
      fun update_sub_config/2, raw_default_for_metakv(),
      config_profile:get_value(resource_management_metakv, [])).

%% Default config for ns_config, without being overriden by config profile
raw_default_for_ns_config() ->
    [
     %% Bucket level resources
     {bucket,
      %% Resident ratio percentage minimum
      [{resident_ratio,
        [{enabled, false},
         {couchstore_minimum, 1},
         {magma_minimum, 0.2}]},
       %% Max data size per bucket on a node in TB
       {data_size,
        [{enabled, false},
         {couchstore_maximum, 2},
         {magma_maximum, 16}]}
      ]},
     {index,
      %% Resident ratio percentage minimum
      [{index_growth_rr,
        [{enabled, false},
         {warning, 15},
         {serious, 12.5},
         {critical, 10}]},
       {disk_usage,
        [{enabled, false},
         {critical, 85},
         {serious, 80}]}]},
     %% Minimum cores required per bucket
     {cores_per_bucket,
      [{enabled, false},
       {minimum, 0.2}]},
     %% Max disk usage % per node
     {disk_usage,
      [{enabled, false},
       {maximum, 85}]},
     %% Max no. of collections per bucket quota in MB
     {collections_per_quota,
      [{enabled, false},
       {maximum, 1}]}
    ].


%% Default config for metakv, without being overriden by config profile
raw_default_for_metakv() ->
    [
     %% Index service resources
     {index,
      [
       %% The following settings have been commented out as the index service
       %% currently logs errors when these metakv settings are defined
       %%
       %% Minimum estimated resident ratio percentage to permit index creation
       %% {index_creation_rr,
       %%  [{enabled, false},
       %%   {minimum, 10}]},
       %% Minimum resident ratio that a topology change must not breach
       %% {topology_change_rr,
       %%  [{enabled, false},
       %%   {minimum, 10}]},
       %% max index overhead per node
       %% {index_overhead_per_node,
       %%  [{enabled, false},
       %%   {maximum, 1}]}
      ]}
    ].

update_sub_config({[], Value}, _) ->
    Value;
update_sub_config({[Key | Keys], Value}, []) ->
    [{Key, update_sub_config({Keys, Value}, [])}];
update_sub_config({[Key | Keys], Value}, SubConfig) ->
    %% To support additions of guardrails, we need to store new keys that
    %% were not previously in the config
    lists:keystore(Key, 1, SubConfig,
                   {Key,
                    update_sub_config({Keys, Value},
                                      proplists:get_value(Key, SubConfig,
                                                          []))}).

update_config(Changes) ->
    OldConfig = get_full_config(),

    NewConfig = lists:foldl(fun update_sub_config/2, OldConfig, Changes),

    set_services_configs(OldConfig, NewConfig),
    OtherConfig = proplists:delete(metakv, NewConfig),
    ns_config:set(resource_management, OtherConfig),
    NewConfig.

set_services_configs(OldConfigAll, NewConfigAll) ->
    OldConfig = proplists:get_value(metakv, OldConfigAll),
    NewConfig = proplists:get_value(metakv, NewConfigAll),
    lists:foreach(
      fun ({index, NewIndexConfig}) ->
              case proplists:get_value(index, OldConfig, []) of
                  NewIndexConfig ->
                      ok;
                  _ ->
                      %% Config has changed, so we update metakv
                      index_settings_manager:update(guardrails, NewIndexConfig)
              end;
          (_) ->
              ok
      end, NewConfig).

config_upgrade_to_76(_Config) ->
    [{set, resource_management, default_for_ns_config()}].

config_upgrade_to_morpheus(Config) ->
    Current = ns_config:search(Config, resource_management, []),
    Default = default_for_ns_config(),
    Changes = update_disk_usage_maximum_to_new_default(Default, Current) ++
        update_cpu_cores_per_bucket_to_new_default(Default, Current),
    New = misc:update_proplist(Current, Changes),
    [{set, resource_management, New}].

update_disk_usage_maximum_to_new_default(DefaultConfig, CurrentConfig) ->
    Default = proplists:get_value(disk_usage, DefaultConfig),
    Current = proplists:get_value(disk_usage, CurrentConfig),
    case Current of
        undefined ->
            %% Need to populate the value
            [{disk_usage, Default}];
        _ ->
            case proplists:get_value(maximum, Current) of
                96 ->
                    %% If the value is currently 96, and that's not the default,
                    %% then this is a self-managed cluster, so the value needs
                    %% updating to the correct default
                    [{disk_usage, Default}];
                _ ->
                    %% If the maximum has changed from the default and it's not
                    %% a self-managed cluster, then we don't want to override it
                    []
            end
    end.

update_cpu_cores_per_bucket_to_new_default(DefaultConfig, CurrentConfig) ->
    Default = proplists:get_value(cores_per_bucket, DefaultConfig),
    Current = proplists:get_value(cores_per_bucket, CurrentConfig),
    case Current of
        undefined ->
            %% Need to populate the value
            [{cores_per_bucket, Default}];
        _ ->
            case proplists:get_value(minimum, Current) of
                0.4 ->
                    %% Old default, needs updating
                    case proplists:get_value(minimum, Default) of
                        undefined ->
                            %% Default is blank, so don't change it
                            [];
                        New ->
                            Updated = lists:keystore(minimum, 1, Current,
                                                     {minimum, New}),
                            [{cores_per_bucket, Updated}]
                    end;
                _ ->
                    []
            end
    end.

-spec build_json_for_audit(proplists:proplist()) -> proplists:proplist().
build_json_for_audit(Settings) ->
    [{settings, {json, build_json(Settings)}}].

build_json(Settings) ->
    {lists:map(
       fun({Key, Value}) when is_list(Value) ->
               {Key, build_json(Value)};
          ({Key, Value}) ->
               {Key, Value}
       end, Settings)}.

-ifdef(TEST).

meck_modules() ->
    [config_profile, ns_config, ns_bucket].

basic_test_setup() ->
    meck:new(meck_modules(), [passthrough]).

default_config_t() ->
    ?assertProplistsEqualRecursively(
       raw_default_for_ns_config(),
       default_for_ns_config()),
    ?assertProplistsEqualRecursively(
       raw_default_for_metakv(),
       default_for_metakv()),

    ConfigProfile = [{resource_management,
                      [{[bucket, resident_ratio, enabled], true},
                       {[bucket, resident_ratio, couchstore_minimum], 10},
                       {[bucket, resident_ratio, magma_minimum], 1},
                       {[cores_per_bucket, enabled], true},
                       {[bucket, data_size, enabled], true},
                       {[bucket, data_size, couchstore_maximum], 1.6},
                       {[bucket, data_size, magma_maximum], 16},
                       {[index, index_growth_rr, enabled], true},
                       {[index, index_growth_rr, critical], 1},
                       {[index, index_growth_rr, serious], 2},
                       {[index, index_growth_rr, warning], 3},
                       {[disk_usage, enabled], true},
                       {[disk_usage, maximum], 85},
                       {[disk_usage, critical], 80},
                       {[disk_usage, serious], 75},
                       {[collections_per_quota, enabled], true}]
                     },
                     {resource_management_metakv,
                      [{[index, index_creation_rr, enabled], true},
                       {[index, index_creation_rr, minimum], 10},
                       {[index, topology_change_rr, enabled], true},
                       {[index, topology_change_rr, minimum], 10},
                       {[index, index_overhead_per_node, enabled], true},
                       {[index, index_overhead_per_node, maximum], 2}]}],
    meck:expect(config_profile, get_value,
                fun (Key, Default) ->
                        proplists:get_value(Key, ConfigProfile, Default)
                end),

    ?assertProplistsEqualRecursively(
       [{bucket,
         [{resident_ratio,
           [{enabled, true},
            {couchstore_minimum, 10},
            {magma_minimum, 1}]
          },
          {data_size,
           [{enabled, true},
            {couchstore_maximum, 1.6},
            {magma_maximum, 16}]}]
        },
        {index,
         [{index_growth_rr,
           [{enabled, true},
            {critical, 1},
            {serious, 2},
            {warning, 3}]},
          {disk_usage,
           [{enabled, false},
            {serious, 80},
            {critical, 85}]}]},
        {cores_per_bucket,
         [{enabled, true},
          {minimum, 0.2}]},
        {disk_usage,
         [{enabled, true},
          {maximum, 85},
          {critical, 80},
          {serious, 75}]},
        {collections_per_quota,
         [{enabled, true},
          {maximum, 1}]}],
       default_for_ns_config()),

    ?assertProplistsEqualRecursively(
       [{index,
         [{index_creation_rr,
           [{enabled, true},
            {minimum, 10}]},
          {topology_change_rr,
           [{enabled, true},
            {minimum, 10}]},
          {index_overhead_per_node,
           [{enabled, true},
            {maximum, 2}]}]
        }],
       default_for_metakv()).

assert_config_update(Expected, Update, Initial) ->
    InitialServiceConfig = proplists:get_value(metakv, Initial, []),
    InitialIndexConfig = proplists:get_value(index, InitialServiceConfig, []),
    meck:expect(
      index_settings_manager, get,
      fun (guardrails) ->
              InitialIndexConfig
      end),

    InitialOtherConfig = proplists:delete(metakv, Initial),
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, []) ->
                        InitialOtherConfig
                end),

    ExpectedMetakvConfig = proplists:get_value(metakv, Expected, []),
    ExpectedOtherConfig = proplists:delete(metakv, Expected),
    meck:expect(ns_config, set,
                fun (resource_management, Found) ->
                        ?assertProplistsEqualRecursively(ExpectedOtherConfig,
                                                         Found)
                end),

    ExpectedIndexConfig = proplists:get_value(index, ExpectedMetakvConfig, []),
    meck:expect(
      index_settings_manager, update,
      fun (guardrails, Found) ->
              ?assertProplistsEqualRecursively(ExpectedIndexConfig, Found)
      end),
    ?assertProplistsEqualRecursively(Expected, update_config(Update)),

    %% Make sure we call the assertions in the mocks
    ?assert(meck:called(ns_config, set, [resource_management, '_'])),
    case ExpectedIndexConfig of
        InitialIndexConfig ->

            %% Since the index config did not change, we expect the settings
            %% manager not to be updated
            ?assertNot(meck:called(index_settings_manager, update,
                                   [guardrails, '_']));
        _ ->
            %% Since the index config changed, we expect the settings manager
            %% to be updated
            ?assert(meck:called(index_settings_manager, update,
                                [guardrails, '_']))
    end.

update_configs_t() ->
    %% Test update_sub_config alone
    ?assertEqual(value1,
                 update_sub_config({[], value1}, [])),
    ?assertProplistsEqualRecursively([{key1, value1}],
                                     update_sub_config({[key1], value1}, [])),
    ?assertProplistsEqualRecursively([{key1, [{key2, value2}]}],
                                     update_sub_config({[key1, key2], value2},
                                                       [])),
    ?assertProplistsEqualRecursively([{key1, [{key2, value2}]}],
                                     update_sub_config({[key1, key2], value2},
                                                       [{key1, []}])),
    ?assertProplistsEqualRecursively(
       [{key1, [{key2, value2}]},
        {key3, [{key4, value4}]}],
       update_sub_config({[key1, key2], value2},
                         [{key1, []},
                          {key3, [{key4, value4}]}])),

    %% Test update_configs
    assert_config_update([{bucket, [{resident_ratio, [{enabled, true}]}]},
                          {metakv, [{index, []}]}],
                         [{[bucket, resident_ratio, enabled], true}],
                         []),

    assert_config_update([{bucket, [{resident_ratio, [{enabled, true}]}]},
                          {metakv, [{index, []}]}],
                         [{[bucket, resident_ratio, enabled], true}],
                         [{bucket, [{resident_ratio, [{enabled, false}]}]}]),

    assert_config_update([{bucket, [{resident_ratio,
                                     [{enabled, true},
                                      {couchstore_minimum, 10}]}]},
                          {metakv, [{index, []}]}],
                         [{[bucket, resident_ratio, enabled], true}],
                         [{bucket, [{resident_ratio,
                                     [{enabled, false},
                                      {couchstore_minimum, 10}]}]}]),

    assert_config_update([{metakv,
                           [{index,
                             [{index_creation_rr,
                               [{enabled, true},
                                {minimum, 5}]}]}]}],
                         [{[metakv, index, index_creation_rr, enabled], true}],
                         [{metakv,
                           [{index,
                             [{index_creation_rr,
                               [{enabled, false},
                                {minimum, 5}]}]}]}]).

basic_test_teardown() ->
    meck:unload(meck_modules()).

basic_test_() ->
    {setup,
     fun () ->
             basic_test_setup()
     end,
     fun(_) ->
             basic_test_teardown()
     end,
     [{"default config test", fun () -> default_config_t() end},
      {"update configs test", fun () -> update_configs_t() end}]}.

test_build_json(ExpectedEJson, Proplist) ->
    [{settings, {json, EJson}}] = Result = build_json_for_audit(Proplist),
    ?assertEqual(ExpectedEJson, EJson),
    %% Test that the output can be converted to json by ns_audit
    ejson:encode({json_builder:prepare_list(Result)}).

build_json_test() ->
    test_build_json({[]}, []),

    test_build_json({[{key, value}]}, [{key, value}]),

    test_build_json({[{key, {[]}}]}, [{key, []}]),

    test_build_json({[{key0, {[{key1, value1}]}}]}, [{key0, [{key1, value1}]}]),

    test_build_json({[{key0, {[{key1, {[{key2, value2}]}}, {key3, value3}]}}]},
                    [{key0, [{key1, [{key2, value2}]}, {key3, value3}]}]),

    ok.

-endif.
