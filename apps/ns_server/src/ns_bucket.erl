%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(ns_bucket).

-include("ns_common.hrl").
-include("ns_bucket.hrl").
-include_lib("ns_common/include/cut.hrl").
-include("cb_cluster_secrets.hrl").

-ifdef(TEST).
-include("ns_test.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.

%% These timeouts were initally present in ns_orchestrator
%% - therefore the slight bit of ugliness here.
%%
%% Check if the timeout is currently configured via {timeout, {ns_bucket,
%% delete_bucket} key in ns_config; if not check if it was previously
%% configured via {timeout, {ns_orchestrator, delete_bucket}}; else use the
%% default value.

-define(DELETE_BUCKET_TIMEOUT,
        ?get_timeout(delete_bucket,
                     ns_config:get_timeout({ns_orchestrator, delete_bucket},
                                           30000))).
-define(DELETE_MAGMA_BUCKET_TIMEOUT,
        ?get_timeout(delete_magma_bucket,
                     ns_config:get_timeout({ns_orchestrator, delete_bucket},
                                           300000))).

%% API
-export([get_servers/1,
         bucket_type/1,
         kv_bucket_type/1,
         node_kv_backend_type/1,
         num_replicas_changed/1,
         create_bucket/3,
         restore_bucket/4,
         delete_bucket/1,
         display_type/1,
         display_type/2,
         external_bucket_type/1,
         durability_min_level/1,
         durability_impossible_fallback/1,
         warmup_behavior/1,
         failover_warnings/1,
         root/0,
         sub_key/2,
         get_snapshot/1,
         get_snapshot/2,
         fetch_snapshot/2,
         fetch_snapshot/3,
         sub_key_match/1,
         buckets_change/1,
         names_change/1,
         remove_from_snapshot/2,
         toy_buckets/1,
         bucket_exists/2,
         get_bucket/1,
         get_bucket/2,
         ensure_bucket/1,
         get_bucket_names/0,
         get_bucket_names/1,
         get_bucket_names_of_type/1,
         get_bucket_names_of_type/2,
         get_buckets/0,
         get_buckets/1,
         get_buckets_by_rank/0,
         get_buckets_by_rank/1,
         is_named_bucket_persistent/1,
         is_persistent/1,
         is_ephemeral_bucket/1,
         is_valid_bucket_name/1,
         memcached_buckets_in_use/0,
         live_bucket_nodes/1,
         live_bucket_nodes_from_config/1,
         map_to_replicas/1,
         replicated_vbuckets/3,
         name_conflict/1,
         name_conflict/2,
         node_locator/1,
         num_replicas/1,
         num_replicas/2,
         attribute_default/1,
         attribute_min/1,
         attribute_max/1,
         ram_quota/1,
         conflict_resolution_type/1,
         drift_thresholds/1,
         history_retention_seconds/1,
         history_retention_bytes/1,
         history_retention_collection_default/1,
         rank/1,
         eviction_policy/1,
         default_storage_mode/1,
         storage_mode/1,
         storage_backend/1,
         raw_ram_quota/1,
         magma_max_shards/2,
         magma_key_tree_data_blocksize/1,
         magma_seq_tree_data_blocksize/1,
         update_maps/3,
         update_buckets_for_delta_recovery/2,
         multi_prop_update/2,
         set_bucket_config/2,
         update_servers_and_map/4,
         validate_map/1,
         set_fast_forward_map/2,
         set_map/2,
         set_initial_map/4,
         set_map_opts/2,
         set_servers/2,
         set_restored_attributes/3,
         remove_servers_from_bucket/2,
         clear_hibernation_state/1,
         update_bucket_props/2,
         update_bucket_props/4,
         storage_mode_migration_in_progress/1,
         node_bucket_names/1,
         node_bucket_names/2,
         node_bucket_names_of_type/2,
         node_bucket_names_of_type/3,
         all_node_vbuckets/1,
         store_last_balanced_vbmap/3,
         past_vbucket_maps/1,
         past_vbucket_maps/2,
         maybe_remove_vbucket_map_history/0,
         config_to_map_options/1,
         can_have_views/1,
         is_magma/1,
         get_view_nodes/1,
         get_default_num_vbuckets/1,
         allow_variable_num_vbuckets/0,
         get_cc_versioning_enabled/1,
         get_access_scanner_enabled/1,
         get_expiry_pager_sleep_time/1,
         get_memory_low_watermark/1,
         get_memory_high_watermark/1,
         get_vbuckets_max_cas/1,
         get_vp_window_hrs/1,
         get_num_vbuckets/1,
         get_max_buckets_supported/0,
         get_max_buckets/0,
         get_min_replicas/0,
         get_continuous_backup_enabled/1,
         get_continuous_backup_interval/1,
         get_continuous_backup_location/1,
         get_invalid_hlc_strategy/1,
         get_num_dcp_connections/1,
         uuid_key/1,
         uuid/2,
         uuids/0,
         uuids/1,
         buckets_with_data_on_this_node/0,
         activate_bucket_data_on_this_node/1,
         deactivate_bucket_data_on_this_node/1,
         chronicle_upgrade_to_72/1,
         chronicle_upgrade_to_76/1,
         chronicle_upgrade_to_morpheus/1,
         extract_bucket_props/1,
         build_bucket_props_json/1,
         build_compaction_settings_json/1,
         get_width/1,
         get_weight/1,
         get_desired_servers/1,
         get_hibernation_state/1,
         update_desired_servers/2,
         update_servers/2,
         get_expected_servers/1,
         get_buckets_marked_for_shutdown/0,
         get_bucket_names_marked_for_shutdown/0,
         del_marked_for_shutdown/1,
         get_shutdown_timeout/1,
         wait_for_bucket_shutdown/3,
         remove_bucket/1,
         node_storage_mode/1,
         node_storage_mode/2,
         node_storage_mode_override/2,
         node_autocompaction_settings/1,
         node_magma_fragmentation_percentage/1,
         remove_override_props/2,
         remove_override_props_many/2,
         get_commits_from_snapshot/2,
         update_bucket_config/2,
         update_buckets_config/1,
         all_keys/1,
         get_encryption/2,
         get_dek_lifetime/2,
         get_dek_rotation_interval/2,
         get_drop_keys_timestamp/2,
         validate_encryption_secret/3,
         magma_fusion_logstore_uri/1,
         magma_fusion_metadatastore_uri/1]).

-import(json_builder,
        [to_binary/1,
         prepare_list/1]).

%%%===================================================================
%%% API
%%%===================================================================

root() ->
    bucket_names.

sub_key(Bucket, SubKey) ->
    {bucket, Bucket, SubKey}.

sub_key_match({bucket, Bucket, SubKey}) ->
    {true, Bucket, SubKey};
sub_key_match(_) ->
    false.

%% do not detect changes bucket_names because it is always in the same
%% transaction with props key
buckets_change(buckets) ->
    true;
buckets_change(Key) ->
    case sub_key_match(Key) of
        {true, _, props} ->
            true;
        _ ->
            false
    end.

names_change(buckets) ->
    true;
names_change(bucket_names) ->
    true;
names_change(_) ->
    false.


all_sub_keys() ->
    [uuid, props, collections].

all_keys(Bucket) ->
    all_keys([Bucket], all_sub_keys()).

all_keys(Names, SubKeys) ->
    [sub_key(B, SubKey) || B <- Names, SubKey <- SubKeys].

fetch_snapshot(Bucket, Txn) ->
    fetch_snapshot(Bucket, Txn, all_sub_keys()).

fetch_snapshot(_Bucket, {ns_config, Config}, _SubKeys) ->
    Converted = bucket_configs_to_chronicle(get_buckets(Config)),
    maps:from_list([{K, {V, no_rev}} || {K, V} <- Converted]);
fetch_snapshot(all, Txn, SubKeys) ->
    {ok, {Names, _} = NamesRev} = chronicle_compat:txn_get(root(), Txn),
    Snapshot = chronicle_compat:txn_get_many(all_keys(Names, SubKeys), Txn),
    Snapshot#{root() => NamesRev};
fetch_snapshot(Bucket, Txn, SubKeys) ->
    chronicle_compat:txn_get_many([root() | all_keys([Bucket], SubKeys)], Txn).

get_snapshot(Bucket) ->
    get_snapshot(Bucket, all_sub_keys()).

get_snapshot(Bucket, SubKeys) ->
    chronicle_compat:get_snapshot([fetch_snapshot(Bucket, _, SubKeys)], #{}).

bucket_configs_to_chronicle(BucketConfigs) ->
    [{root(), [N || {N, _} <- BucketConfigs]} |
     lists:flatmap(
       fun ({B, BC}) ->
               {value, {uuid, UUID}, BC1} = lists:keytake(uuid, 1, BC),
               [{sub_key(B, props), BC1},
                {uuid_key(B), UUID}]
       end, BucketConfigs)].

remove_from_snapshot(BucketName, Snapshot) ->
    functools:chain(
      Snapshot,
      [maps:remove(sub_key(BucketName, props), _),
       maps:remove(uuid_key(BucketName), _),
       maps:remove(collections:key(BucketName), _),
       maps:update_with(root(), fun ({List, Rev}) ->
                                        {List -- [BucketName], Rev}
                                end, _)]).

toy_buckets(List) ->
    maps:from_list(
      [{root(), {[N || {N, _} <- List], no_rev}} |
       lists:flatmap(
         fun ({Bucket, Props}) ->
                 [{sub_key(Bucket, K), {V, no_rev}} || {K, V} <- Props]
         end, List)]).

bucket_exists(Bucket, Snapshot) ->
    case get_bucket(Bucket, Snapshot) of
        {ok, _} ->
            true;
        not_present ->
            false
    end.

get_bucket(Bucket) ->
    get_bucket(Bucket, direct).

get_bucket(Bucket, Snapshot) ->
    case chronicle_compat:get(Snapshot, sub_key(Bucket, props), #{}) of
        {ok, Props} ->
            {ok, Props};
        {error, not_found} ->
            not_present
    end.

ensure_bucket(Bucket) ->
    case get_bucket(Bucket) of
        not_present ->
            exit({bucket_not_present, Bucket});
        {ok, BucketConfig} ->
            BucketConfig
    end.

get_bucket_names() ->
    get_bucket_names(direct).

get_bucket_names(Snapshot) ->
    chronicle_compat:get(Snapshot, root(), #{required => true}).

-type bucket_type_mode() :: memcached|membase|persistent|auto_compactable|
                            {membase, couchstore}|
                            {membase, magma}|
                            {membase, ephemeral}| {memcached, undefined}.

-spec get_bucket_names_of_type(bucket_type_mode()) -> list().
get_bucket_names_of_type(Type) ->
    get_bucket_names_of_type(Type, get_buckets()).

-spec get_bucket_names_of_type(bucket_type_mode(), list()) -> list().
get_bucket_names_of_type({Type, Mode}, BucketConfigs) ->
    [Name || {Name, Config} <- BucketConfigs, bucket_type(Config) == Type,
             storage_mode(Config) == Mode];
get_bucket_names_of_type(persistent, BucketConfigs) ->
    [Name || {Name, Config} <- BucketConfigs,
             is_persistent(Config)];
get_bucket_names_of_type(auto_compactable, BucketConfigs) ->
    [Name || {Name, Config} <- BucketConfigs,
             is_auto_compactable(Config)];
get_bucket_names_of_type(Type, BucketConfigs) ->
    [Name || {Name, Config} <- BucketConfigs, bucket_type(Config) == Type].

%% extracted s/t it can be unit tested
rank_sorting_fn() ->
    fun ({KeyA, PlistA}, {KeyB, PlistB}) ->
            case {rank(PlistA), rank(PlistB)} of
                {RankA, RankB} when RankA =:= RankB -> KeyA < KeyB;
                {RankA, RankB} -> RankA > RankB
            end
    end.

-spec get_buckets_by_rank() -> proplists:proplist().
get_buckets_by_rank() ->
    get_buckets_by_rank(get_buckets()).

-spec get_buckets_by_rank(proplists:proplist() | map()) ->
          proplists:proplist().
get_buckets_by_rank(BucketsConfig) ->
    JustBuckets = maybe_isolate_bucket_props(BucketsConfig),
    case cluster_compat_mode:is_cluster_76() of
        true ->
            lists:sort(rank_sorting_fn(), JustBuckets);
        false ->
            JustBuckets
    end.

%% we need an extra level of extraction in some code paths but not others
maybe_isolate_bucket_props(Snapshot) when is_map(Snapshot) ->
    get_buckets(Snapshot);
maybe_isolate_bucket_props(List) when is_list(List) ->
    List.

get_buckets() ->
    get_buckets(direct).

get_buckets(direct) ->
    get_buckets(get_snapshot(all, [props]));
get_buckets(Snapshot) when is_map(Snapshot) ->
    lists:map(fun (N) ->
                      Props = chronicle_compat:get(Snapshot, sub_key(N, props),
                                                   #{required => true}),
                      {N, Props}
              end, get_bucket_names(Snapshot)).

live_bucket_nodes(Bucket) ->
    {ok, BucketConfig} = get_bucket(Bucket),
    live_bucket_nodes_from_config(BucketConfig).

live_bucket_nodes_from_config(BucketConfig) ->
    Servers = get_servers(BucketConfig),
    LiveNodes = [node()|nodes()],
    [Node || Node <- Servers, lists:member(Node, LiveNodes) ].

-spec conflict_resolution_type(proplists:proplist()) -> atom().
conflict_resolution_type(BucketConfig) ->
    proplists:get_value(conflict_resolution_type, BucketConfig, seqno).

drift_thresholds(BucketConfig) ->
    ReturnThresholds =
        case {conflict_resolution_type(BucketConfig),
              history_retention_seconds(BucketConfig)} of
            {lww, _} -> true;
            {_, Num} when is_number(Num), Num > 0 -> true;
            {seqno, _} -> false;
            {custom, _} -> false
        end,
    case ReturnThresholds of
        true ->
            {proplists:get_value(drift_ahead_threshold_ms, BucketConfig),
             proplists:get_value(drift_behind_threshold_ms, BucketConfig)};
        false -> undefined
    end.

-spec rank(proplists:proplist()) -> integer().
rank(BucketConfig) ->
    proplists:get_value(rank, BucketConfig, ?DEFAULT_BUCKET_RANK).

-spec history_retention_seconds(proplists:proplist()) -> integer().
history_retention_seconds(BucketConfig) ->
    proplists:get_value(history_retention_seconds, BucketConfig,
                        ?HISTORY_RETENTION_SECONDS_DEFAULT).

-spec history_retention_bytes(proplists:proplist()) -> integer().
history_retention_bytes(BucketConfig) ->
    proplists:get_value(history_retention_bytes, BucketConfig,
                        ?HISTORY_RETENTION_BYTES_DEFAULT).

-spec history_retention_collection_default(proplists:proplist()) -> boolean().
history_retention_collection_default(BucketConfig) ->
    %% History can only be true for a magma bucket.
    proplists:get_value(history_retention_collection_default, BucketConfig,
                        ?HISTORY_RETENTION_COLLECTION_DEFAULT_DEFAULT)
    andalso is_magma(BucketConfig)
    andalso cluster_compat_mode:is_cluster_72().

eviction_policy(BucketConfig) ->
    Default = case storage_mode(BucketConfig) of
                  undefined -> value_only;
                  couchstore -> value_only;
                  magma -> full_eviction;
                  ephemeral -> no_eviction
              end,
    proplists:get_value(eviction_policy, BucketConfig, Default).

-spec node_storage_mode_override(node(), proplists:proplist()) -> atom().
node_storage_mode_override(Node, BucketConfig) ->
    proplists:get_value({node, Node, storage_mode}, BucketConfig).

-spec node_storage_mode(proplists:proplist()) -> atom().
node_storage_mode(BucketConfig) ->
    node_storage_mode(node(), BucketConfig).

-spec node_storage_mode(node(), proplists:proplist()) -> atom().
node_storage_mode(Node, BucketConfig) ->
    NodeStorageMode = node_storage_mode_override(Node, BucketConfig),
    case NodeStorageMode of
        undefined ->
            storage_mode(BucketConfig);
        _ ->
            NodeStorageMode
    end.

-spec default_storage_mode(memcached|membase) -> atom().
default_storage_mode(memcached) ->
    undefined;
default_storage_mode(membase) ->
    case cluster_compat_mode:is_cluster_morpheus() andalso
         cluster_compat_mode:is_enterprise() of
        true ->
            magma;
        false ->
            couchstore
    end.

-spec storage_mode(proplists:proplist()) -> atom().
storage_mode(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            undefined;
        membase ->
            proplists:get_value(storage_mode, BucketConfig,
                                default_storage_mode(membase))
    end.

autocompaction_settings(BucketConfig) ->
    proplists:get_value(autocompaction, BucketConfig).

-spec storage_backend(proplists:proplist()) -> atom().
storage_backend(BucketConfig) ->
    BucketType = bucket_type(BucketConfig),
    StorageMode = storage_mode(BucketConfig),
    case BucketType of
        membase ->
            case StorageMode of
                ephemeral ->
                    undefined;
                SM ->
                    SM
            end;
        memcached ->
            undefined
    end.

durability_min_level(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            undefined;
        membase ->
            case proplists:get_value(durability_min_level, BucketConfig,
                                     none) of
                none ->
                    none;
                majority ->
                    majority;
                majorityAndPersistActive ->
                    majority_and_persist_on_master;
                persistToMajority ->
                    persist_to_majority
            end
    end.

durability_impossible_fallback(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached -> undefined;
        membase ->
            proplists:get_value(durability_impossible_fallback, BucketConfig,
                                disabled)
    end.

warmup_behavior(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached -> undefined;
        membase ->
            proplists:get_value(warmup_behavior, BucketConfig,
                                background)
    end.

%% The default value of the attribute.
attribute_default(Name) ->
    case Name of
        version_pruning_window_hrs -> 720;  % 30 days
        expiry_pager_sleep_time -> 600;     % 10 minutes
        memory_low_watermark -> 75;         % percentage
        memory_high_watermark -> 85;        % percentage
        cross_cluster_versioning_enabled -> % boolean
            false;
        access_scanner_enabled -> true;     % boolean
        continuous_backup_enabled -> false; % boolean
        continuous_backup_interval -> 2;    % minutes
        continuous_backup_location -> "";   % path or URI
        invalid_hlc_strategy -> error;      % atom
        dcp_connections_between_nodes -> 1  % pos_integer
    end.

%% The minimum value of the attribute.
attribute_min(Name) ->
    case Name of
        version_pruning_window_hrs -> 24;   % 24 hours
        expiry_pager_sleep_time -> 0;       % unit seconds
        memory_low_watermark -> 50;         % percentage
        memory_high_watermark -> 51;        % percentage
        continuous_backup_interval -> 2;    % minutes
        dcp_connections_between_nodes -> 1  % pos_integer
    end.

%% The maximum value of the attribute.
attribute_max(Name) ->
    case Name of
        version_pruning_window_hrs ->
            ?MAX_32BIT_SIGNED_INT;                  % unit hours
        expiry_pager_sleep_time ->
            ?MAX_64BIT_UNSIGNED_INT;                  % unit seconds
        memory_low_watermark -> 89;                   % percentage
        memory_high_watermark -> 90;                  % percentage
        continuous_backup_interval ->
            ?MAX_32BIT_SIGNED_INT;                    % minutes
        dcp_connections_between_nodes -> 64           % pos_integer
    end.

membase_bucket_config_value_getter(Key, BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            undefined;
        membase ->
            proplists:get_value(Key, BucketConfig, attribute_default(Key))
    end.

-spec get_expiry_pager_sleep_time(proplists:proplist()) -> integer() |
                                                           undefined.
get_expiry_pager_sleep_time(BucketConfig) ->
    membase_bucket_config_value_getter(expiry_pager_sleep_time, BucketConfig).

-spec get_memory_low_watermark(proplists:proplist()) -> integer() | undefined.
get_memory_low_watermark(BucketConfig) ->
    membase_bucket_config_value_getter(memory_low_watermark, BucketConfig).

-spec get_memory_high_watermark(proplists:proplist()) -> integer() | undefined.
get_memory_high_watermark(BucketConfig) ->
    membase_bucket_config_value_getter(memory_high_watermark, BucketConfig).

-spec get_continuous_backup_enabled(proplists:proplist()) -> undefined |
                                                             boolean().
get_continuous_backup_enabled(BucketConfig) ->
    case is_magma(BucketConfig) of
        false ->
            undefined;
        true ->
            membase_bucket_config_value_getter(continuous_backup_enabled,
                                               BucketConfig)
    end.

-spec get_continuous_backup_interval(proplists:proplist()) -> undefined |
                                                              non_neg_integer().
get_continuous_backup_interval(BucketConfig) ->
    case is_magma(BucketConfig) of
        false ->
            undefined;
        true ->
            membase_bucket_config_value_getter(continuous_backup_interval,
                                               BucketConfig)
    end.

-spec get_continuous_backup_location(proplists:proplist()) -> undefined |
                                                              string().
get_continuous_backup_location(BucketConfig) ->
    case is_magma(BucketConfig) of
        false ->
            undefined;
        true ->
            membase_bucket_config_value_getter(continuous_backup_location,
                                               BucketConfig)
    end.

-spec get_invalid_hlc_strategy(proplists:proplist()) ->
    undefined | error | ignore | replace.
get_invalid_hlc_strategy(BucketConfig) ->
    membase_bucket_config_value_getter(invalid_hlc_strategy, BucketConfig).

-spec get_num_dcp_connections(proplists:proplist()) -> pos_integer().
get_num_dcp_connections(BucketConfig) ->
    case proplists:get_value(dcp_connections_between_nodes, BucketConfig) of
        undefined -> ?DEFAULT_DCP_CONNECTIONS;
        Other -> Other
    end.

%% returns bucket ram quota multiplied by number of nodes this bucket
%% will reside after initial cleanup. I.e. gives amount of ram quota that will
%% be used by across the cluster for this bucket.
-spec ram_quota(proplists:proplist()) -> integer().
ram_quota(Bucket) ->
    case proplists:get_value(ram_quota, Bucket) of
        X when is_integer(X) ->
            X * length(get_expected_servers(Bucket))
    end.

%% returns bucket ram quota for _single_ node. Each node will subtract
%% this much from it's node quota.
-spec raw_ram_quota(proplists:proplist()) -> integer().
raw_ram_quota(Bucket) ->
    case proplists:get_value(ram_quota, Bucket) of
        X when is_integer(X) ->
            X
    end.

node_autocompaction_settings(BucketConfig) ->
    %% If the per node override setting exists on this node use that,
    %% else use the setting on the bucket.
    case proplists:get_value({node, node(), autocompaction},
                             BucketConfig) of
        false ->
            [];
        undefined ->
            case proplists:get_value(autocompaction, BucketConfig, []) of
                false -> [];
                SomeValue -> SomeValue
            end;
        Settings ->
            Settings
    end.

node_magma_fragmentation_percentage(BucketConfig) ->
    AutoCompactionSettings = node_autocompaction_settings(BucketConfig),
    GlobalMagmaFragPercent = compaction_daemon:global_magma_frag_percent(),
    proplists:get_value(
      magma_fragmentation_percentage, AutoCompactionSettings,
      GlobalMagmaFragPercent).

magma_max_shards(BucketConfig, Default) ->
    proplists:get_value(magma_max_shards, BucketConfig, Default).

-spec magma_key_tree_data_blocksize(proplists:proplist()) -> integer().
magma_key_tree_data_blocksize(BucketConfig) ->
    proplists:get_value(magma_key_tree_data_blocksize, BucketConfig,
                        ?MAGMA_KEY_TREE_DATA_BLOCKSIZE).

-spec magma_seq_tree_data_blocksize(proplists:proplist()) -> integer().
magma_seq_tree_data_blocksize(BucketConfig) ->
    proplists:get_value(magma_seq_tree_data_blocksize, BucketConfig,
                        ?MAGMA_SEQ_TREE_DATA_BLOCKSIZE).

-spec magma_fusion_logstore_uri(proplists:proplist()) -> string() | undefined.
magma_fusion_logstore_uri(BucketConfig) ->
    proplists:get_value(magma_fusion_logstore_uri, BucketConfig).

is_fusion(BucketConfig) ->
    magma_fusion_logstore_uri(BucketConfig) =/= undefined.

-spec magma_fusion_metadatastore_uri(proplists:proplist()) ->
          string() | undefined.
magma_fusion_metadatastore_uri(BucketConfig) ->
    case is_fusion(BucketConfig) of
        true ->
            ns_config:read_key_fast(
              magma_fusion_metadatastore_uri,
              "chronicle://localhost:" ++
                  integer_to_list(service_ports:get_port(rest_port)));
        false ->
            undefined
    end.

-define(FS_HARD_NODES_NEEDED, 4).
-define(FS_FAILOVER_NEEDED, 3).
-define(FS_REBALANCE_NEEDED, 2).
-define(FS_SOFT_REBALANCE_NEEDED, 1).
-define(FS_OK, 0).

bucket_failover_safety(Bucket, BucketConfig, ActiveNodes, LiveNodes,
                       MaxReplicas) ->
    ReplicaNum = num_replicas(BucketConfig),
    case ReplicaNum of
        %% if replica count for bucket is 0 we cannot failover at all
        0 -> {?FS_OK, ok};
        _ ->
            MinLiveCopies = min_live_copies(LiveNodes, BucketConfig),
            BucketNodes = get_servers(BucketConfig),
            BaseSafety =
                if
                    MinLiveCopies =:= undefined -> % janitor run pending
                        case LiveNodes of
                            [_,_|_] -> ?FS_OK;
                            _ -> ?FS_HARD_NODES_NEEDED
                        end;
                    MinLiveCopies =< 1 ->
                        %% we cannot failover without losing data
                        %% is some of chain nodes are down ?
                        DownBucketNodes = lists:any(fun (N) -> not lists:member(N, LiveNodes) end,
                                                    BucketNodes),
                        if
                            DownBucketNodes ->
                                %% yes. User should bring them back or failover/replace them (and possibly add more)
                                ?FS_FAILOVER_NEEDED;
                            %% Can we replace missing chain nodes with other live nodes ?
                            LiveNodes =/= [] andalso tl(LiveNodes) =/= [] -> % length(LiveNodes) > 1, but more efficent
                                %% we're generally fault tolerant, just not balanced enough
                                ?FS_REBALANCE_NEEDED;
                            true ->
                                %% we have one (or 0) of live nodes, need at least one more to be fault tolerant
                                ?FS_HARD_NODES_NEEDED
                        end;
                    true ->
                        case ns_rebalancer:bucket_needs_rebalance(
                               Bucket, BucketConfig, ActiveNodes) of
                            true ->
                                ?FS_SOFT_REBALANCE_NEEDED;
                            false ->
                                ?FS_OK
                        end
                end,
            ExtraSafety = bucket_extra_safety(
                            BaseSafety, ReplicaNum, ActiveNodes, MaxReplicas),
            {BaseSafety, ExtraSafety}
    end.

bucket_extra_safety(BaseSafety, _ReplicaNum, _ActiveNodes, _MaxReplicas)
  when BaseSafety =:= ?FS_HARD_NODES_NEEDED ->
    ok;
bucket_extra_safety(_BaseSafety, ReplicaNum, ActiveNodes, MaxReplicas) ->
    case length(ActiveNodes) =< ReplicaNum orelse MaxReplicas < ReplicaNum of
        true ->
            softNodesNeeded;
        false ->
            ok
    end.

failover_safety_rec(?FS_HARD_NODES_NEEDED, _ExtraSafety, _,
                    _ActiveNodes, _LiveNodes, _MaxReplicas) ->
    {?FS_HARD_NODES_NEEDED, ok};
failover_safety_rec(BaseSafety, ExtraSafety, [],
                    _ActiveNodes, _LiveNodes, _MaxReplicas) ->
    {BaseSafety, ExtraSafety};
failover_safety_rec(BaseSafety, ExtraSafety,
                    [{Bucket, BucketConfig} | RestConfigs],
                    ActiveNodes, LiveNodes, MaxReplicas) ->
    {ThisBaseSafety, ThisExtraSafety} =
        bucket_failover_safety(Bucket, BucketConfig, ActiveNodes, LiveNodes,
                               MaxReplicas),
    NewBaseSafety = case BaseSafety < ThisBaseSafety of
                        true -> ThisBaseSafety;
                        _ -> BaseSafety
                    end,
    NewExtraSafety = if ThisExtraSafety =:= softNodesNeeded
                        orelse ExtraSafety =:= softNodesNeeded ->
                             softNodesNeeded;
                        true ->
                             ok
                     end,
    failover_safety_rec(NewBaseSafety, NewExtraSafety,
                        RestConfigs, ActiveNodes, LiveNodes, MaxReplicas).

-spec failover_warnings(map()) -> [failoverNeeded | rebalanceNeeded |
                                   hardNodesNeeded | softNodesNeeded |
                                   unbalancedServerGroups].
failover_warnings(Snapshot) ->
    ActiveNodes = ns_cluster_membership:service_active_nodes(Snapshot, kv),
    LiveNodes = ns_cluster_membership:service_actual_nodes(Snapshot, kv),

    ServerGroups = ns_cluster_membership:server_groups(Snapshot),
    KvGroups = ns_cluster_membership:get_nodes_server_groups(
                 ActiveNodes, ServerGroups),

    MaxReplicas =
        case ns_cluster_membership:rack_aware(KvGroups) of
            true ->
                ns_cluster_membership:get_max_replicas(
                  length(ActiveNodes), KvGroups);
            false ->
                length(ActiveNodes) - 1
        end,

    {BaseSafety0, ExtraSafety}
        = failover_safety_rec(?FS_OK, ok,
                              [{B, C} || {B, C} <- get_buckets(Snapshot),
                                         membase =:= bucket_type(C)],
                              ActiveNodes,
                              LiveNodes,
                              MaxReplicas),
    BaseSafety = case BaseSafety0 of
                     ?FS_HARD_NODES_NEEDED -> hardNodesNeeded;
                     ?FS_FAILOVER_NEEDED -> failoverNeeded;
                     ?FS_REBALANCE_NEEDED -> rebalanceNeeded;
                     ?FS_SOFT_REBALANCE_NEEDED -> softRebalanceNeeded;
                     ?FS_OK -> ok
                 end,

    Warnings = [S || S <- [BaseSafety, ExtraSafety], S =/= ok],
    case not racks_balanced(KvGroups) of
        true ->
            [unbalancedServerGroups | Warnings];
        false ->
            Warnings
    end.

racks_balanced([]) ->
    true;
racks_balanced([Group | Rest]) ->
    Nodes = proplists:get_value(nodes, Group),
    GroupSize = length(Nodes),

    lists:all(
      fun (OtherGroup) ->
              OtherNodes = proplists:get_value(nodes, OtherGroup),
              length(OtherNodes) =:= GroupSize
      end, Rest).

map_to_replicas(Map) ->
    lists:foldr(
      fun ({VBucket, [Master | Replicas]}, Acc) ->
              case Master of
                  undefined ->
                      Acc;
                  _ ->
                      [{Master, R, VBucket} || R <- Replicas, R =/= undefined] ++
                          Acc
              end
      end, [], misc:enumerate(Map, 0)).

%% returns _sorted_ list of vbuckets that are replicated from SrcNode
%% to DstNode according to given Map.
replicated_vbuckets(Map, SrcNode, DstNode) ->
    VBuckets = [V || {S, D, V} <- map_to_replicas(Map),
                     S =:= SrcNode, DstNode =:= D],
    lists:sort(VBuckets).

%% @doc Return the minimum number of live copies for all vbuckets.
-spec min_live_copies([node()], list()) -> non_neg_integer() | undefined.
min_live_copies(LiveNodes, Config) ->
    case proplists:get_value(map, Config) of
        undefined -> undefined;
        Map ->
            lists:foldl(
              fun (Chain, Min) ->
                      NumLiveCopies =
                          lists:foldl(
                            fun (Node, Acc) ->
                                    case lists:member(Node, LiveNodes) of
                                        true -> Acc + 1;
                                        false -> Acc
                                    end
                            end, 0, Chain),
                      erlang:min(Min, NumLiveCopies)
              end, length(hd(Map)), Map)
    end.

node_locator(BucketConfig) ->
    case proplists:get_value(type, BucketConfig) of
        membase ->
            vbucket;
        memcached ->
            ketama
    end.

-spec num_replicas(proplists:proplist()) -> integer().
num_replicas(Bucket) ->
    case proplists:get_value(num_replicas, Bucket) of
        X when is_integer(X) ->
            X
    end.

-spec num_replicas(proplists:proplist(), Default) -> pos_integer() | Default
              when Default :: pos_integer() | undefined.
num_replicas(Bucket, Default) ->
    proplists:get_value(num_replicas, Bucket, Default).

%% ns_server type (membase vs memcached)
%% Once morpheus is the oldest supported release all vestiges of 'memcached'
%% can be removed. Until then it's possible for a morpheus node to see a
%% memcached bucket and thus must be able to return info about such bucket.
bucket_type(Bucket) ->
    proplists:get_value(type, Bucket).

%% KV type (persistent vs ephemeral)
kv_bucket_type(BucketConfig) ->
    case is_persistent(BucketConfig) of
        true -> persistent;
        false -> ephemeral
    end.

node_kv_backend_type(BucketConfig) ->
    StorageMode = node_storage_mode(BucketConfig),
    case StorageMode of
        couchstore -> couchdb;
        magma -> magma;
        %% KV requires a value but only accepts: couchdb, magma, rocksdb.
        %% So we've always passed couchdb for ephemeral buckets which KV
        %% will parse as an acceptable value but not use it.
        ephemeral -> couchdb;
        %% No storage for memcached buckets
        undefined -> undefined
    end.

%% Used for REST API compatibility.  This transforms the internal
%% representation of bucket types to externally known bucket types.
%% Ideally the 'display_type' function should suffice here but there
%% is too much reliance on the atom membase by other modules (ex: xdcr).
external_bucket_type(BucketConfig) ->
    BucketType = bucket_type(BucketConfig),
    case BucketType of
        memcached -> memcached;
        membase ->
            case storage_mode(BucketConfig) of
                couchstore -> membase;
                magma -> membase;
                ephemeral -> ephemeral
            end
    end.

%% Default bucket type is now couchbase and not membase. Ideally, we should
%% change the default bucket type atom to couchbase but the bucket type membase
%% is used/checked at multiple locations. For similar reasons, the ephemeral
%% bucket type also gets stored as 'membase' and to differentiate between the
%% couchbase and ephemeral buckets we store an extra parameter called
%% 'storage_mode'. So to fix the log message to display the correct bucket type
%% we use both type and storage_mode parameters of the bucket config.
display_type(BucketConfig) ->
    BucketType = bucket_type(BucketConfig),
    StorageMode = storage_mode(BucketConfig),
    display_type(BucketType, StorageMode).

display_type(membase = _Type, couchstore = _StorageMode) ->
    couchbase;
display_type(membase = _Type, magma = _StorageMode) ->
    couchbase;
display_type(membase = _Type, ephemeral = _StorageMode) ->
    ephemeral;
display_type(Type, _) ->
    Type.

get_servers(BucketConfig) ->
    proplists:get_value(servers, BucketConfig).

set_bucket_config(Bucket, NewConfig) ->
    update_bucket_config(Bucket, fun (_) -> NewConfig end).

%% Here's code snippet from bucket-engine.  We also disallow '.' &&
%% '..' which cause problems with browsers even when properly
%% escaped. See bug 953
%%
%% static bool has_valid_bucket_name(const char *n) {
%%     bool rv = strlen(n) > 0;
%%     for (; *n; n++) {
%%         rv &= isalpha(*n) || isdigit(*n) || *n == '.' || *n == '%' || *n == '_' || *n == '-';
%%     }
%%     return rv;
%% }
%%
%% Now we also disallow bucket names starting with '.'. It's because couchdb
%% creates (at least now) auxiliary directories which start with dot. We don't
%% want to conflict with them
is_valid_bucket_name([]) -> {error, empty};
is_valid_bucket_name([$. | _]) -> {error, starts_with_dot};
is_valid_bucket_name(BucketName) ->
    case is_valid_bucket_name_inner(BucketName) of
        {error, _} = X ->
            X;
        true ->
            Reserved =
                string:str(string:to_lower(BucketName), "_users.couch.") =:= 1 orelse
                string:str(string:to_lower(BucketName), "_replicator.couch.") =:= 1,
            case Reserved of
                true ->
                    {error, reserved};
                false ->
                    true
            end
    end.

is_valid_bucket_name_inner([Char | Rest]) ->
    case ($A =< Char andalso Char =< $Z)
        orelse ($a =< Char andalso Char =< $z)
        orelse ($0 =< Char andalso Char =< $9)
        orelse Char =:= $. orelse Char =:= $%
        orelse Char =:= $_ orelse Char =:= $- of
        true ->
            case Rest of
                [] -> true;
                _ -> is_valid_bucket_name_inner(Rest)
            end;
        _ -> {error, invalid}
    end.

-spec memcached_buckets_in_use() -> boolean().
memcached_buckets_in_use() ->
    Snapshot = chronicle_compat:get_snapshot(
              [ns_bucket:fetch_snapshot(all, _, [props])],
              #{}),

    BucketConfigs = ns_bucket:get_buckets(Snapshot),
    case ns_bucket:get_bucket_names_of_type(memcached, BucketConfigs) of
        [] ->
            false;
        Names ->
            ?log_error("Found unsupported memcached buckets: ~p", [Names]),
            true
    end.

get_max_buckets_supported() ->
    Default = config_profile:get_value(max_buckets_supported,
                                       ?MAX_BUCKETS_SUPPORTED),
    ns_config:read_key_fast(max_bucket_count, Default).

-spec get_max_buckets() -> integer().
get_max_buckets() ->
    GlobalMax = get_max_buckets_supported(),
    KvNodes = ns_cluster_membership:service_active_nodes(kv),
    AllCores =
        lists:map(
          fun (Node) ->
                  Props = ns_doctor:get_node(Node),
                  proplists:get_value(cpu_count, Props, GlobalMax)
          end, KvNodes),

    case AllCores of
        [] ->
            GlobalMax;
        Cores ->
            MinCores = lists:min(Cores),
            CoresPerBucket = guardrail_monitor:get(cores_per_bucket),
            case CoresPerBucket of
                C when is_number(C) andalso C > 0 andalso MinCores > 0 ->
                    min(floor(MinCores / CoresPerBucket), GlobalMax);
                _ ->
                    GlobalMax
            end
    end.

get_min_replicas() ->
    ns_config:read_key_fast(min_replicas_count, ?MIN_REPLICAS_SUPPORTED).

get_default_num_vbuckets(couchstore) ->
    get_default_num_vbuckets_helper(?DEFAULT_VBUCKETS_COUCHSTORE);
get_default_num_vbuckets(magma) ->
    get_default_num_vbuckets_helper(?DEFAULT_VBUCKETS_MAGMA);
get_default_num_vbuckets(ephemeral) ->
    get_default_num_vbuckets_helper(?DEFAULT_VBUCKETS_EPHEMERAL);
get_default_num_vbuckets(undefined) ->
    %% Occurs when parsing invalid bucket parameters. Doesn't get used
    %% for a resultant bucket.
    -1.

get_default_num_vbuckets_helper(DefaultNumVBs) ->
    case ns_config:search(couchbase_num_vbuckets_default) of
        false ->
            misc:getenv_int("COUCHBASE_NUM_VBUCKETS",
              config_profile:get_value(default_num_vbuckets,
                                       DefaultNumVBs));
        {value, X} ->
            X
    end.

allow_variable_num_vbuckets() ->
    config_profile:get_bool(allow_variable_num_vbuckets).

get_num_vbuckets(BucketConfig) ->
    proplists:get_value(num_vbuckets, BucketConfig).

get_cc_versioning_enabled(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            undefined;
        membase ->
            proplists:get_value(cross_cluster_versioning_enabled, BucketConfig)
    end.

-spec get_access_scanner_enabled(proplists:proplist()) -> boolean() | undefined.
get_access_scanner_enabled(BucketConfig) ->
    case is_persistent(BucketConfig) of
        true ->
            proplists:get_value(access_scanner_enabled, BucketConfig);
        false ->
            undefined
    end.

get_vbuckets_max_cas(BucketConfig) ->
    proplists:get_value(vbuckets_max_cas, BucketConfig).

get_vp_window_hrs(BucketConfig) ->
    proplists:get_value(version_pruning_window_hrs, BucketConfig).

new_bucket_default_params(membase) ->
    [{type, membase},
     %% The default number of vbuckets cannot be determined until the
     %% type of storage backend (magma vs couchstore) is known. This is
     %% done after the bucket creation attributes are all parsed.
     %% {num_vbuckets, ???}
     {num_replicas, ?DEFAULT_MEMBASE_NUM_REPLICAS},
     {ram_quota, 0},
     {replication_topology, star},
     {repl_type, dcp},
     {servers, []}];
new_bucket_default_params(memcached) ->
    Nodes = ns_cluster_membership:service_active_nodes(kv),
    [{type, memcached},
     {num_vbuckets, 0},
     {num_replicas, ?DEFAULT_MEMCACHED_NUM_REPLICAS},
     {servers, Nodes},
     {map, []},
     {ram_quota, 0}].

cleanup_bucket_props(Props) ->
    lists:keydelete(moxi_port, 1, Props).

create_bucket(BucketType, BucketName, NewConfig) ->
    MergedConfig =
        misc:update_proplist(new_bucket_default_params(BucketType),
                             NewConfig),
    BucketUUID = couch_uuids:random(),
    Manifest = collections:default_manifest(MergedConfig),
    case do_create_bucket(BucketName, MergedConfig, BucketUUID, Manifest) of
        ok ->
            %% The janitor will handle creating the map.
            {ok, BucketUUID, MergedConfig};
        {error, _} = Error ->
            Error
    end.

restore_bucket(BucketName, NewConfig, BucketUUID, Manifest) ->
    case is_valid_bucket_name(BucketName) of
        true ->
            do_create_bucket(BucketName, NewConfig, BucketUUID, Manifest);
        {error, _} ->
            {error, {invalid_bucket_name, BucketName}}
    end.

do_create_bucket(BucketName, Config, BucketUUID, Manifest) ->
    Result =
        chronicle_kv:transaction(
          kv, [root(), nodes_wanted, buckets_marked_for_shutdown_key(),
               ?CHRONICLE_SECRETS_KEY],
          fun (Snapshot) ->
                  BucketNames = get_bucket_names(Snapshot),
                  %% We make similar checks via validate_create_bucket/2 in
                  %% ns_orchestrator and since the leader leases guarantees that
                  %% leader wouldn't change between these calls, the below
                  %% checks are redundant.
                  %%
                  %% Despite that, name_conflict/2 check below has existed,
                  %% therefore adding the is_marked_for_shutdown check too in
                  %% similar vein.
                  %%
                  %% More discussion here at:
                  %% https://review.couchbase.org/c/ns_server/+/188906/
                  %% comments/9fdd0336_0ec5a962

                  ShutdownBucketNames =
                      get_bucket_names_marked_for_shutdown(Snapshot),
                  SecretId = proplists:get_value(encryption_secret_id,
                                                 Config, ?SECRET_ID_NOT_SET),
                  EncryptionSecretOk = validate_encryption_secret(SecretId,
                                                                  BucketName,
                                                                  Snapshot),
                  case {name_conflict(BucketName, BucketNames),
                        name_conflict(BucketName, ShutdownBucketNames),
                        EncryptionSecretOk} of
                      {true, _, _} ->
                          {abort, already_exists};
                      {_, true, _} ->
                          {abort, still_exists};
                      {_, _, {error, Reason}} ->
                          {abort, {error, Reason}};
                      {false, false, ok} ->
                          {commit, create_bucket_sets(BucketName, BucketNames,
                                                      BucketUUID, Config) ++
                                   collections_sets(BucketName, Config,
                                                    Snapshot, Manifest)}
                  end
          end),
    case Result of
        {ok, _} -> ok;
        {error, _} = Error -> Error
    end.

create_bucket_sets(Bucket, Buckets, BucketUUID, Config) ->
    [{set, root(), lists:usort([Bucket | Buckets])},
     {set, sub_key(Bucket, props), Config},
     {set, uuid_key(Bucket), BucketUUID}].

collections_sets(Bucket, Config, Snapshot, Manifest) ->
    case collections:enabled(Config) of
        true ->
            Nodes = ns_cluster_membership:nodes_wanted(Snapshot),
            [{set, collections:key(Bucket), Manifest} |
             [collections:last_seen_ids_set(Node, Bucket, Manifest) ||
                 Node <- Nodes]];
        false ->
            []
    end.

buckets_marked_for_shutdown_key() ->
    buckets_marked_for_shutdown.

get_buckets_marked_for_shutdown() ->
    get_buckets_marked_for_shutdown(direct).

get_buckets_marked_for_shutdown(Snapshot) ->
    chronicle_compat:get(Snapshot, buckets_marked_for_shutdown_key(),
                         #{default => []}).

del_marked_for_shutdown(BucketName) ->
    Key = buckets_marked_for_shutdown_key(),
    chronicle_kv:transaction(
      kv, [Key],
      fun (Snapshot) ->
              Buckets = get_buckets_marked_for_shutdown(Snapshot),
              {commit,
               [{set, Key, proplists:delete(BucketName, Buckets)}]}
      end).

add_marked_for_shutdown(Snapshot, {BucketName, BucketConfig}) ->
    {set, buckets_marked_for_shutdown_key(),
     get_buckets_marked_for_shutdown(Snapshot) ++
     [{BucketName, get_servers(BucketConfig),
       get_shutdown_timeout(BucketConfig)}]}.

get_bucket_names_marked_for_shutdown() ->
    get_bucket_names_marked_for_shutdown(direct).

get_bucket_names_marked_for_shutdown(Snapshot) ->
    [BN || {BN, _Nodes, _Timeout} <- get_buckets_marked_for_shutdown(Snapshot)].

-spec delete_bucket(bucket_name()) ->
                           {ok, BucketConfig :: list()} |
                           {exit, {not_found, bucket_name()}, any()}.
delete_bucket(BucketName) ->
    RootKey = root(),
    PropsKey = sub_key(BucketName, props),
    IsCluster76 = cluster_compat_mode:is_cluster_76(),

    RV = chronicle_kv:transaction(
           kv, [RootKey, PropsKey, nodes_wanted, uuid_key(BucketName),
                buckets_marked_for_shutdown_key()],
           fun (Snapshot) ->
                   BucketNames = get_bucket_names(Snapshot),
                   case lists:member(BucketName, BucketNames) of
                       false ->
                           {abort, not_found};
                       true ->
                           {ok, BucketConfig} =
                               get_bucket(BucketName, Snapshot),
                           UUID = uuid(BucketName, Snapshot),
                           NodesWanted =
                               ns_cluster_membership:nodes_wanted(Snapshot),
                           KeysToDelete =
                               [collections:key(BucketName),
                                last_balanced_vbmap_key(BucketName),
                                sub_key(BucketName, encr_at_rest),
                                uuid_key(BucketName), PropsKey |
                                [collections:last_seen_ids_key(N, BucketName) ||
                                    N <- NodesWanted]],
                           {commit,
                            [{set, RootKey, BucketNames -- [BucketName]}] ++
                            %% We need to ensure the cluster is 7.6 to avoid
                            %% running into issues similar to the one described
                            %% here:
                            %%
                            %% https://review.couchbase.org/c/ns_server/+/
                            %% 188906/comments/209b4dbb_78588f3e
                            [add_marked_for_shutdown(
                               Snapshot, {BucketName, BucketConfig}) ||
                             IsCluster76] ++
                            [{delete, K} || K <- KeysToDelete],
                            [{uuid, UUID}] ++ BucketConfig}
                   end
           end),
    case RV of
        {ok, _, BucketConfig} ->
            {ok, BucketConfig};
        not_found ->
            {exit, {not_found, BucketName}, nothing}
    end.

wait_for_nodes_loop([]) ->
    ok;
wait_for_nodes_loop(Nodes) ->
    receive
        {done, Node} ->
            wait_for_nodes_loop(Nodes -- [Node]);
        timeout ->
            {timeout, Nodes}
    end.

wait_for_nodes_check_pred(Status, Pred) ->
    Active = proplists:get_value(active_buckets, Status),
    case Active of
        undefined ->
            false;
        _ ->
            Pred(Active)
    end.

%% Wait till active buckets satisfy certain predicate on all nodes. After
%% `Timeout' milliseconds, we give up and return the list of leftover nodes.
-spec wait_for_nodes([node()],
                     fun(([string()]) -> boolean()),
                     timeout()) -> ok | {timeout, [node()]}.
wait_for_nodes(Nodes, Pred, Timeout) ->
    misc:executing_on_new_process(
      fun () ->
              Self = self(),

              ns_pubsub:subscribe_link(
                buckets_events,
                fun ({significant_buckets_change, Node}) ->
                        Status = ns_doctor:get_node(Node),

                        case wait_for_nodes_check_pred(Status, Pred) of
                            false ->
                                ok;
                            true ->
                                Self ! {done, Node}
                        end;
                    (_) ->
                        ok
                end),

              Statuses = ns_doctor:get_nodes(),
              InitiallyFilteredNodes =
                  lists:filter(
                    fun (N) ->
                            Status = ns_doctor:get_node(N, Statuses),
                            not wait_for_nodes_check_pred(Status, Pred)
                    end, Nodes),

              erlang:send_after(Timeout, Self, timeout),
              wait_for_nodes_loop(InitiallyFilteredNodes)
      end).

get_shutdown_timeout(BucketConfig) ->
    case ns_bucket:node_kv_backend_type(BucketConfig) of
        magma ->
            ?DELETE_MAGMA_BUCKET_TIMEOUT;
        _ ->
            ?DELETE_BUCKET_TIMEOUT
    end.

wait_for_bucket_shutdown(BucketName, Nodes0, Timeout) ->
    %% A bucket deletion can be only prempted by a auto-failover and it can
    %% happen the node on which the bucket was hosted could have been
    %% failed-over before the shutdown was performed via ns_orchestrator.
    %%
    %% Filter out the servers that aren't currently active.

    Nodes = ns_cluster_membership:active_nodes(direct, Nodes0),

    Pred = fun (Active) ->
                   not lists:member(BucketName, Active)
           end,
    LeftoverNodes =
        case wait_for_nodes(Nodes, Pred, Timeout) of
            ok ->
                [];
            {timeout, LeftoverNodes0} ->
                ?log_warning("Nodes ~p failed to delete bucket ~p "
                             "within expected time (~p msecs).",
                             [LeftoverNodes0, BucketName, Timeout]),
                LeftoverNodes0
        end,

    case testconditions:check_test_condition({wait_for_bucket_shutdown,
                                              BucketName}) of
        ok ->
            case LeftoverNodes of
                [] ->
                    ok;
                _ ->
                    {shutdown_failed, LeftoverNodes}
            end;
        Other -> Other
    end.

override_keys() ->
    [storage_mode, autocompaction].

-spec remove_override_props([{_, _}], [node()]) -> [{_, _}].
remove_override_props(Props, Nodes) ->
    lists:filter(fun ({{node, Node, SubKey}, _Value}) ->
                         not lists:member(Node, Nodes)
                           andalso lists:member(SubKey, override_keys());
                     (_) ->
                         true
                 end, Props).

-spec remove_override_props_many([node()], [{bucket_name(), [{_, _}]}]) ->
    [{bucket_name(), [{_, _}]}].
remove_override_props_many(Nodes, BucketConfigs) ->
    lists:map(fun ({BN, BC}) ->
                      {BN, remove_override_props(BC, Nodes)}
              end, BucketConfigs).

get_override_keys(BucketConfig, SubKey) ->
    [K || {{node, _Node, SK} = K, _V} <- BucketConfig, SK =:= SubKey].

do_add_override_props(Props, BucketConfig, Key, FetchFun) ->
    Nodes = get_servers(BucketConfig),

    OldValue = FetchFun(BucketConfig),
    OldOverrideKeys = get_override_keys(BucketConfig, Key),
    OldOverrideKeyNodes = [N || {node, N, _SK} <- OldOverrideKeys],
    OldOverrideValue =
        case OldOverrideKeys of
            [] ->
                undefined;
            _ ->
                proplists:get_value(hd(OldOverrideKeys), BucketConfig)
        end,

    OverrideProps = [{{node, N, Key}, OldValue}
                     || N <- Nodes -- OldOverrideKeyNodes],

    NewProps =
        case OldOverrideValue of
                undefined ->
                    Props;
                _ ->
                    lists:keystore(Key, 1, Props, {Key, OldOverrideValue})
        end,

    {NewProps ++ OverrideProps, OldOverrideKeys}.

add_override_props(Props, BucketConfig) ->
    lists:foldl(
      fun ({Key, FetchFun}, {NewProps, DeleteKeys}) ->
              {P, D} =
                  do_add_override_props(NewProps, BucketConfig, Key, FetchFun),
              {P, DeleteKeys ++ D}

      end, {Props, []},
      [{storage_mode, fun storage_mode/1},
       {autocompaction, fun autocompaction_settings/1}]).

%% Updates properties of bucket of given name and type.  Check of type
%% protects us from type change races in certain cases.
%% If bucket with given name exists, but with different type, we
%% should return {exit, {not_found, _}, _}
update_bucket_props(Type, OldStorageMode, BucketName, Props) ->
    case lists:member(BucketName,
                      get_bucket_names_of_type({Type, OldStorageMode})) of
        true ->
            try
                update_bucket_props_inner(
                  Type, OldStorageMode, BucketName, Props)
            catch
                throw:Error ->
                    Error
            end;
        false ->
            {exit, {not_found, BucketName}, []}
    end.

maybe_delete_cas_props(PrevProps, NewProps) ->
    PrevCcvEn =
        proplists:get_value(cross_cluster_versioning_enabled,
                            PrevProps, false),
    NewCcvEn =
        proplists:get_value(cross_cluster_versioning_enabled,
                            NewProps, false),

    maybe_delete_cas_props_inner(PrevCcvEn, NewCcvEn, NewProps).

maybe_delete_cas_props_inner(_PrevCcvEn, false = _CurrCcvEn, Props) ->
    {Props, [vbuckets_max_cas]};
maybe_delete_cas_props_inner(false = _PrevCcvEn, true = _CurrCcvEn, Props) ->
    {Props, []};
maybe_delete_cas_props_inner(true = _PrevCcvEn, true = _CurrCcvEn, _Props) ->
    throw({error, cc_versioning_already_enabled}).

update_bucket_props_inner(Type, OldStorageMode, BucketName, Props) ->
    {ok, BucketConfig} = get_bucket(BucketName),
    PrevProps = extract_bucket_props(BucketConfig),
    DisplayBucketType = display_type(Type, OldStorageMode),

    case update_bucket_props_allowed(Props, BucketConfig) of
        true ->
            ok;
        {false, Error} ->
            throw({error, Error})
    end,

    {Props1, MaybeDeleteCasKey} =
        maybe_delete_cas_props(PrevProps, Props),

    NewSecretId = proplists:get_value(encryption_secret_id, Props,
                                      ?SECRET_ID_NOT_SET),
    PrevSecretId = proplists:get_value(encryption_secret_id, PrevProps,
                                       ?SECRET_ID_NOT_SET),
    IsSecretIdChanging = (PrevSecretId =/= NewSecretId),

    SecretIdCheckPredicate =
        case IsSecretIdChanging of
            true ->
                validate_encryption_secret(NewSecretId, BucketName, _);
            _ ->
                fun (_) -> ok end
        end,

    NewStorageMode = proplists:get_value(storage_mode, Props),
    IsStorageModeMigration = OldStorageMode =/= NewStorageMode,

    RV =
        case IsStorageModeMigration of
            false ->
                update_bucket_props_with_predicate(
                    BucketName, Props1, MaybeDeleteCasKey,
                    SecretIdCheckPredicate, [], #{});
            true ->
                %% Reject storage migration if servers haven't been
                %% populated yet (This is extremely unlikely to happen,
                %% since we invoke a janitor run right after a bucket
                %% is created in chronicle - but there is still a
                %% non-zero probability that it could happen, therefore
                %% the below check).
                get_servers(BucketConfig) =/= [] orelse
                    throw({error,
                           {storage_mode_migration, janitor_not_run}}),

                {NewProps, DeleteKeys} =
                    add_override_props(Props1, BucketConfig),

                %% Collections can be updated concurrently while a
                %% bucket is being updated - make sure history is not
                %% enabled on any of the bucket collections, before we
                %% update the storage_mode in the transaction.
                %%
                %% A concurrent update could have been set to a majority
                %% nodes and this node might not have yet received that
                %% (or not have been part of the majority nodes). Set
                %% read_consistency to 'quorum' to make sure we pick
                %% such updates too.

                Predicate =
                    fun (Snapshot) ->
                            case collections:history_retention_enabled(
                                   BucketName, Snapshot) of
                                false ->
                                    SecretIdCheckPredicate(Snapshot);
                                true ->
                                    {error,
                                     {storage_mode_migration,
                                      history_retention_enabled_on_collections}}
                            end
                    end,

                update_bucket_props_with_predicate(
                  BucketName, NewProps, DeleteKeys ++ MaybeDeleteCasKey,
                  Predicate, [collections], #{read_consistency => quorum})
        end,

    case RV of
        ok ->
            {ok, NewBucketConfig} = get_bucket(BucketName),
            NewExtractedProps = extract_bucket_props(NewBucketConfig),
            if
                PrevProps =/= NewExtractedProps ->
                    event_log:add_log(
                      bucket_cfg_changed,
                      [{bucket, list_to_binary(BucketName)},
                       {bucket_uuid, uuid(BucketName, direct)},
                       {type, DisplayBucketType},
                       {old_settings,
                        {build_bucket_props_json(PrevProps)}},
                       {new_settings,
                        {build_bucket_props_json(NewExtractedProps)}}]);
                true ->
                    ok
            end,
            ok;
        _ ->
            RV
    end.

-spec update_bucket_props_allowed(proplists:proplist(), proplists:proplist()) ->
          true | {false, Error::term()}.
update_bucket_props_allowed(NewProps, BucketConfig) ->
    Res = functools:sequence_(
            [?cut(is_storage_mode_update_allowed(
                    NewProps, BucketConfig)),
             ?cut(update_bucket_props_allowed_inner(
                    NewProps, BucketConfig))]),
    case Res of
        ok ->
            true;
        Error ->
            {false, Error}
    end.

%% is_storage_mode_update_allowed/2 logic.
%%
%% storage_mode_migration_in_progress - no, magma -> couchstore.
%%  - history_retention_collection_default should not be explicitly set to
%%    true.
%% storage_mode_migration_in_progress - no, couchstore -> magma.
%%  - no check pass.
%% storage_mode_migration_in_progress - yes, couchstore -> magma.
%%  - storage_mode: couchstore, some nodes have magma backend.
%%  - no check pass.
%% storage_mode_migration_in_progress - yes, magma -> couchstore.
%%  - storage_mode: magma, some nodes have couchstore backend.
%%  - no check pass because:
%%      1. This was previously a couchstore bucket and therefore it is not
%%      possible for history_retention_collection_default to have been set to
%%      true.
%%      2. We disallow changing any props other than ram_quota and
%%      storage_mode while a storage mode migration is running, therefore we
%%      can safely assume history_retention_collection_default was never
%%      explicitly toggled to true.

is_storage_mode_update_allowed(NewProps, BucketConfig) ->
    NewStorageMode = proplists:get_value(storage_mode, NewProps),
    OldStorageMode = proplists:get_value(storage_mode, BucketConfig),
    StorageModeMigrationInProgress =
        storage_mode_migration_in_progress(BucketConfig),

    case {StorageModeMigrationInProgress, OldStorageMode, NewStorageMode} of
        {false, magma, couchstore} ->
            %% Intentionally not using
            %% history_retention_collection_default/1 - because it returns
            %% true by default for a magma bucket.
            case proplists:get_value(
                   history_retention_collection_default, BucketConfig) of
                true ->
                    %% Prevents migrating a magma bucket to couchstore if the
                    %% history_retention_collection_default is explicitly set
                    %% to true.
                    {storage_mode_migration,
                     history_retention_enabled_on_bucket};
                _Val ->
                    ok
            end;
        _ ->
            ok
    end.

update_bucket_props_allowed_inner(NewProps, BucketConfig) ->
    case storage_mode_migration_in_progress(BucketConfig) of
        true ->
            %% We allow only ram_quota and storage_mode settings to be changed
            %% during the bucket storage_mode migration - disallow updating any
            %% other keys.
            FilteredProps =
                lists:filter(
                  fun ({K, _V}) ->
                          not lists:member(K, [ram_quota, storage_mode])
                  end, NewProps),
            case FilteredProps of
                [] ->
                    ok;
                _ ->
                    %% Check if any of the other props have changed or a new
                    %% Prop is being added.
                    PropsChanged =
                        lists:any(
                          fun ({K, V}) ->
                                  case proplists:get_value(K, BucketConfig) of
                                      undefined ->
                                          true;
                                      CurrentValue ->
                                          V =/= CurrentValue
                                  end
                          end, FilteredProps),
                    case PropsChanged of
                        false ->
                            ok;
                        true ->
                            {storage_mode_migration, in_progress}
                    end
            end;
        false ->
            ok
    end.

%% If there are per-node storage mode override keys, we are essentially midway
%% between a storage mode migration.
storage_mode_migration_in_progress(BucketConfig) ->
    lists:any(fun ({{node, _N, storage_mode}, _V}) ->
                      true;
                  (_KV) ->
                      false
              end, BucketConfig).

update_bucket_props(BucketName, Props) ->
    update_bucket_props(BucketName, Props, []).

update_bucket_props(BucketName, Props, DeleteKeys) ->
    update_bucket_props_with_predicate(
      BucketName, Props, DeleteKeys, fun (_) -> ok end, [], #{}).

update_bucket_props_with_predicate(
  BucketName, Props, DeleteKeys, Predicate, SubKeys, Opts) ->
    update_bucket_config(
      BucketName,
      fun (OldProps) ->
              NewProps = lists:foldl(
                           fun ({K, _V} = Tuple, Acc) ->
                                   [Tuple | lists:keydelete(K, 1, Acc)]
                           end, OldProps, Props),
              NewProps1 = lists:foldl(
                            fun (K, Acc) ->
                                    lists:keydelete(K, 1, Acc)
                            end, NewProps, DeleteKeys),
              cleanup_bucket_props(NewProps1)
      end, Predicate, SubKeys, Opts).

set_auto_fields(CurBucketConfig, UpdatedBucketConfig) ->
    IsEnabled = fun (Id) -> Id /= ?SECRET_ID_NOT_SET end,
    CurEncr = proplists:get_value(encryption_secret_id, CurBucketConfig,
                                  ?SECRET_ID_NOT_SET),
    NewEncr = proplists:get_value(encryption_secret_id, UpdatedBucketConfig,
                                  ?SECRET_ID_NOT_SET),
    case IsEnabled(CurEncr) /= IsEnabled(NewEncr) of
        true ->
            ToggleKey = encryption_last_toggle_datetime,
            ToggleTime = calendar:universal_time(),
            [{ToggleKey, ToggleTime} |
             proplists:delete(ToggleKey, UpdatedBucketConfig)];
        false ->
            UpdatedBucketConfig
    end.

set_property(Bucket, Key, Value, Default, Fun) ->
    ok = update_bucket_config(
           Bucket,
           fun (OldConfig) ->
                   Fun(proplists:get_value(Key, OldConfig, Default)),
                   lists:keystore(Key, 1, OldConfig, {Key, Value})
           end).

set_property(Bucket, Key, Value) ->
    ok = update_bucket_config(Bucket, lists:keystore(Key, 1, _, {Key, Value})).

set_fast_forward_map(Bucket, Map) ->
    set_property(Bucket, fastForwardMap, Map, [],
                 master_activity_events:note_set_ff_map(Bucket, Map, _)).

validate_map(Map) ->
    case mb_map:is_valid(Map) of
        true ->
            ok;
        different_length_chains ->
            ok
    end.

set_map(Bucket, Map) ->
    validate_map(Map),
    set_property(Bucket, map, Map, [],
                 master_activity_events:note_set_map(Bucket, Map, _)).

validate_map_with_node_names(Snapshot, Servers) ->
    Nodes = chronicle_compat:get(Snapshot, nodes_wanted, #{default => []}),
    ordsets:is_subset(ordsets:from_list(Servers), ordsets:from_list(Nodes)).

validate_init_map_trans(BucketName, Snapshot, Servers) ->
    case get_bucket(BucketName, Snapshot) of
        {ok, Config} ->
            case validate_map_with_node_names(Snapshot, Servers) of
                true ->
                    {ok, Config};
                false ->
                    false
            end;
        not_present ->
            false
    end.

% Update the initial map via a transaction that validates map with the
% nodes_wanted in chronicle. This allows chronicle to reject the initial map set
% transaction if node names have changed since then
update_init_map_config(BucketName, Servers, Fun) ->
    PropsKey = sub_key(BucketName, props),
    RV =
        chronicle_kv:transaction(
          kv, [PropsKey, nodes_wanted],
          fun (Snapshot) ->
                  case validate_init_map_trans(BucketName, Snapshot, Servers) of
                      {ok, Config} ->
                          {commit, [{set, PropsKey, Fun(Config)}]};
                      false ->
                          {abort, mismatch}
                  end
          end),
    case RV of
        {ok, _} ->
            ok;
        Other ->
            Other
    end.

set_initial_map(Bucket, Map, Servers, MapOpts) ->
    validate_map(Map),
    update_init_map_config(
      Bucket, Servers,
      fun (OldConfig) ->
              OldMap = proplists:get_value(map, OldConfig, []),
              master_activity_events:note_set_map(Bucket, Map, OldMap),
              misc:update_proplist(
                OldConfig,
                [{map, Map}, {map_opts_hash, erlang:phash2(MapOpts)}])
      end).

set_restored_attributes_property(Bucket, Map, ServerList, Fun) ->
    update_bucket_config(
        Bucket,
        fun (OldConfig) ->
            OldConfig1 =
                functools:chain(OldConfig,
                                [proplists:delete(hibernation_state, _),
                                 proplists:delete(servers, _)]),
            Fun(proplists:get_value(map, OldConfig1, [])),
            OldConfig1 ++ [{map, Map}, {servers, ServerList}]
        end).

set_restored_attributes(Bucket, Map, ServerList) ->
    validate_map(Map),
    set_restored_attributes_property(Bucket, Map, ServerList,
                                     master_activity_events:note_set_map(Bucket,
                                     Map, _)).

set_map_opts(Bucket, Opts) ->
    set_property(Bucket, map_opts_hash, erlang:phash2(Opts)).

set_servers(Bucket, Servers) ->
    set_property(Bucket, servers, Servers).

update_servers(Servers, BucketConfig) ->
    lists:keystore(servers, 1, BucketConfig, {servers, Servers}).

maybe_update_desired_servers(BucketConfig, ToRemoveServers) ->
    case get_desired_servers(BucketConfig) of
        undefined ->
            BucketConfig;
        DesiredServers ->
            update_desired_servers(DesiredServers -- ToRemoveServers,
                                   BucketConfig)
    end.

remove_servers_from_bucket(BucketConfig, ToRemoveServers) ->
    Servers = get_servers(BucketConfig),
    C1 = update_servers(Servers -- ToRemoveServers, BucketConfig),
    maybe_update_desired_servers(C1, ToRemoveServers).

clear_hibernation_state(Bucket) ->
    ok = update_bucket_config(
           Bucket,
           fun (OldConfig) ->
                   proplists:delete(hibernation_state, OldConfig)
           end).

update_servers_and_map(Bucket, OldConfig, FailedNodes, NewMap) ->
    Servers = ns_bucket:get_servers(OldConfig),
    C1 = misc:update_proplist(OldConfig, [{servers, Servers -- FailedNodes},
                                          {fastForwardMap, undefined},
                                          {map, NewMap}]),
    NewConfig = maybe_update_desired_servers(C1, FailedNodes),
    master_activity_events:note_set_ff_map(
      Bucket, undefined,
      proplists:get_value(fastForwardMap, OldConfig, [])),
    master_activity_events:note_set_map(
      Bucket, NewMap, proplists:get_value(map, OldConfig, [])),
    NewConfig.

get_commits_from_snapshot(BucketsUpdates, Snapshot) ->
    lists:map(
      fun({BucketName, UpdtFun}) ->
              case get_bucket(BucketName, Snapshot) of
                  {ok, CurrentConfig} ->
                      {set, sub_key(BucketName, props),
                       set_auto_fields(CurrentConfig, UpdtFun(CurrentConfig))};
                  not_present ->
                      {abort, not_found}
              end
      end, BucketsUpdates).

% Update the bucket config atomically.
update_bucket_config(BucketName, Fun) ->
    update_bucket_config(BucketName, Fun, fun (_) -> ok end, [], #{}).

update_bucket_config(BucketName, Fun, Predicate, Subkeys, Opts) ->
    update_buckets_config([{BucketName, Fun}], Predicate, Subkeys, Opts).

update_buckets_config(BucketsUpdates) ->
    update_buckets_config(BucketsUpdates, fun (_) -> ok end, [], #{}).

update_buckets_config(BucketsUpdates, Predicate, SubKeys, Opts) ->
    RV =
        chronicle_kv:transaction(
          kv,
          [?CHRONICLE_SECRETS_KEY] ++
          [sub_key(BucketName, SubKey) ||
           {BucketName, _} <- BucketsUpdates, SubKey <- [props | SubKeys]],
          fun (Snapshot) ->
                  case Predicate(Snapshot) of
                      ok ->
                          Commits =
                              get_commits_from_snapshot(BucketsUpdates,
                                                        Snapshot),

                          case lists:keyfind(abort, 1, Commits) of
                              false ->
                                  {commit, Commits};
                              Res ->
                                  Res
                          end;
                      Error ->
                          {abort, Error}
                  end
          end, Opts),
    case RV of
        {ok, _} ->
            ok;
        Other ->
            Other
    end.

update_maps(Buckets, OnMap, ExtraSets) ->
    Updaters = [{B, OnMap} || B <- Buckets],
    multi_prop_update(map, Updaters, ExtraSets).

multi_prop_update(_Key, []) ->
    ok;
multi_prop_update(Key, Values) ->
    Updaters = [{B, fun (_, _) -> V end} || {B, V} <- Values],
    multi_prop_update(Key, Updaters, []).

multi_prop_update(Key, Updaters, ExtraSets) ->
    RV =
        chronicle_kv:transaction(
          kv, [sub_key(N, props) || {N, _} <- Updaters],
          fun (Snapshot) ->
                  Sets =
                      lists:filtermap(
                        fun ({Name, Updater}) ->
                                case get_bucket(Name, Snapshot) of
                                    {ok, BC} ->
                                        {true, {set, sub_key(Name, props),
                                                misc:key_update(
                                                  Key, BC, Updater(Name, _))}};
                                    not_present ->
                                        false
                                end
                        end, Updaters),
                  {commit, Sets ++ [{set, K, V} || {K, V} <- ExtraSets]}
          end),
    case RV of
        {ok, _} ->
            ok;
        Error ->
            Error
    end.

update_buckets_for_delta_recovery(ModifiedBuckets, DeltaNodes) ->
    BucketSets = [{sub_key(N, props), BC} || {N, BC} <- ModifiedBuckets],
    ExtraSets =
        ns_cluster_membership:update_membership_sets(DeltaNodes, active) ++
        failover:clear_failover_vbuckets_sets(DeltaNodes),
    Updates = BucketSets ++ ExtraSets,
    RV =
        chronicle_kv:transaction(
          kv, [nodes_wanted],
          fun (Snapshot) ->
                  NodesWanted = ns_cluster_membership:nodes_wanted(Snapshot),
                  case DeltaNodes -- NodesWanted of
                      [] ->
                          {commit, [{set, K, V} || {K, V} <- Updates]};
                      _Nodes ->
                          {abort, {ejected_delta_nodes}}
                  end
          end, #{}),
    case RV of
        {ok, _} ->
            ok;
        Error ->
            Error
    end.

is_named_bucket_persistent(BucketName) ->
    {ok, BucketConfig} = get_bucket(BucketName),
    is_persistent(BucketConfig).

is_persistent(BucketConfig) ->
    bucket_type(BucketConfig) =:= membase andalso
        (storage_mode(BucketConfig) =:= couchstore orelse
         storage_mode(BucketConfig) =:= magma).

is_auto_compactable(BucketConfig) ->
    is_persistent(BucketConfig) andalso
    node_storage_mode(BucketConfig) =/= magma.

is_ephemeral_bucket(BucketConfig) ->
    case storage_mode(BucketConfig) of
        ephemeral -> true;
        couchstore -> false;
        magma -> false
    end.

%% @doc Check if a bucket name exists in the list. Case insensitive.
name_conflict(BucketName, ListOfNames) ->
    BucketNameLower = string:to_lower(BucketName),
    lists:any(fun (Name) -> BucketNameLower == string:to_lower(Name) end,
              ListOfNames).

%% @doc Check if a bucket exists. Case insensitive.
name_conflict(BucketName) ->
    name_conflict(BucketName, get_bucket_names()).

node_bucket_names(Node, BucketsConfigs) ->
    [B || {B, C} <- BucketsConfigs,
          lists:member(Node, get_servers(C))].

node_bucket_names(Node) ->
    node_bucket_names(Node, get_buckets()).

-spec node_bucket_names_of_type(node(), bucket_type_mode()) -> list().
node_bucket_names_of_type(Node, Type) ->
    node_bucket_names_of_type(Node, Type, get_buckets()).

-spec node_bucket_names_of_type(node(), bucket_type_mode(), list()) -> list().
node_bucket_names_of_type(Node, {Type, Mode}, BucketConfigs) ->
    [B || {B, C} <- BucketConfigs,
          lists:member(Node, get_servers(C)),
          bucket_type(C) =:= Type,
          storage_mode(C) =:= Mode];
node_bucket_names_of_type(Node, persistent, BucketConfigs) ->
    [B || {B, C} <- BucketConfigs,
          lists:member(Node, get_servers(C)),
          is_persistent(C)];
node_bucket_names_of_type(Node, auto_compactable, BucketConfigs) ->
    [B || {B, C} <- BucketConfigs,
          lists:member(Node, get_servers(C)),
          is_auto_compactable(C)];
node_bucket_names_of_type(Node, Type, BucketConfigs) ->
    [B || {B, C} <- BucketConfigs,
          lists:member(Node, get_servers(C)),
          bucket_type(C) =:= Type].

%% All the vbuckets (active or replica) on a node
-spec all_node_vbuckets(term()) -> list(integer()).
all_node_vbuckets(BucketConfig) ->
    VBucketMap = couch_util:get_value(map, BucketConfig, []),
    Node = node(),
    [Ordinal-1 ||
        {Ordinal, VBuckets} <- misc:enumerate(VBucketMap),
        lists:member(Node, VBuckets)].

config_to_map_options(Config) ->
    [{max_slaves, proplists:get_value(max_slaves, Config, 10)},
     {replication_topology, proplists:get_value(replication_topology, Config, star)}].

get_vbmap_history_size() ->
    %% Not set in config through any means, but gives us a tunable parameter.
    ns_config:read_key_fast(vbmap_history_size, get_max_buckets_supported()).

update_vbucket_map_history(Map, SanifiedOptions) ->
    History = get_vbucket_map_history(ns_config:latest()),
    NewEntry = {Map, SanifiedOptions},
    HistorySize = get_vbmap_history_size(),
    History1 = [NewEntry | lists:delete(NewEntry, History)],
    History2 = case length(History1) > HistorySize of
                   true -> lists:sublist(History1, HistorySize);
                   false -> History1
               end,
    ns_config:set(vbucket_map_history, History2).

last_balanced_vbmap_key(BucketName) ->
    sub_key(BucketName, last_balanced_vbmap).

store_last_balanced_vbmap(BucketName, Map, Options) ->
    case cluster_compat_mode:is_cluster_76() of
        true ->
            {ok, _} =
                chronicle_kv:set(
                  kv, last_balanced_vbmap_key(BucketName), {Map, Options});
        false ->
            update_vbucket_map_history(Map, Options)
    end.

%% this can be replaced with deleting vbucket_map_history key on
%% ns_config upgrade after 7.6 becomes min supported version
maybe_remove_vbucket_map_history() ->
    case cluster_compat_mode:is_cluster_76() andalso
        ns_config:search(vbucket_map_history) =/= false andalso
        lists:all(?cut(get_last_balanced_map(_) =/= not_found),
                  get_bucket_names_of_type(membase)) of
        true ->
            ns_config:delete(vbucket_map_history);
        false ->
            ok
    end.

past_vbucket_maps(BucketName) ->
    past_vbucket_maps(BucketName, ns_config:latest()).

past_vbucket_maps(BucketName, Config) ->
    case cluster_compat_mode:is_cluster_76() of
        true ->
            case get_last_balanced_map(BucketName) of
                not_found ->
                    %% can be removed after 7.6 becomes min supported
                    %% version
                    get_vbucket_map_history(Config);
                MapAndOptions ->
                    [MapAndOptions]
            end;
        false ->
            get_vbucket_map_history(Config)
    end.

get_last_balanced_map(BucketName) ->
    case chronicle_kv:get(kv, last_balanced_vbmap_key(BucketName)) of
        {error, not_found} ->
            not_found;
        {ok, {MapAndOptions, _Rev}} ->
            MapAndOptions
    end.

get_vbucket_map_history(Config) ->
    case ns_config:search(Config, vbucket_map_history) of
        {value, V} ->
            lists:filter(
              fun ({_Map, Options}) ->
                      %% A a map with no replication_topology is a map
                      %% generated for chain replication. We stopped using
                      %% them long ago, but theoretically it's possible to
                      %% stumble upon one here through a series of
                      %% upgrades. Don't return it here so the code elsewhere
                      %% need not know how to handle them.
                      proplists:is_defined(replication_topology, Options)
              end, V);
        false -> []
    end.

num_replicas_changed(BucketConfig) ->
    num_replicas_changed(num_replicas(BucketConfig),
                         proplists:get_value(map, BucketConfig)).

num_replicas_changed(_NumReplicas, undefined) ->
    false;
num_replicas_changed(NumReplicas, Map) ->
    ExpectedChainLength = NumReplicas + 1,
    lists:any(?cut(ExpectedChainLength =/= length(_)), Map).

can_have_views(BucketConfig) ->
    ?COUCHDB_ENABLED(storage_mode(BucketConfig) =:= couchstore, false).

is_magma(BucketConfig) ->
    storage_mode(BucketConfig) =:= magma.

get_view_nodes(BucketConfig) ->
    case can_have_views(BucketConfig) of
        true ->
            lists:sort(get_servers(BucketConfig));
        false ->
            []
    end.

uuid_key(Bucket) ->
    sub_key(Bucket, uuid).

uuid(Bucket, Snapshot) ->
    case chronicle_compat:get(Snapshot, uuid_key(Bucket), #{}) of
        {ok, UUID} ->
            UUID;
        {error, not_found} ->
            not_present
    end.

uuids() ->
    uuids(get_snapshot(all, [uuid])).

uuids(Snapshot) ->
    [{Name, uuid(Name, Snapshot)} || Name <- get_bucket_names(Snapshot)].

filter_out_unknown_buckets(BucketsWithUUIDs, Snapshot) ->
    lists:filter(fun ({Name, UUID}) ->
                         uuid(Name, Snapshot) =:= UUID
                 end, BucketsWithUUIDs).

buckets_with_data_key(Node) ->
    {node, Node, buckets_with_data}.

buckets_with_data_on_this_node() ->
    Node = node(),
    Snapshot =
        chronicle_compat:get_snapshot(
          [fetch_snapshot(all, _, [uuid, props]),
           chronicle_compat:txn_get_many([buckets_with_data_key(Node)], _)]),
    BucketConfigs = get_buckets(Snapshot),
    Stored = membase_buckets_with_data_on_node(Snapshot, Node),
    Filtered = filter_out_unknown_buckets(Stored, Snapshot),
    [B || {B, _} <- Filtered] ++
        get_bucket_names_of_type(memcached, BucketConfigs).

membase_buckets_with_data_on_node(Snapshot, Node) ->
    chronicle_compat:get(Snapshot, buckets_with_data_key(Node),
                         #{default => []}).

activate_bucket_data_on_this_node(Name) ->
    NodeKey = buckets_with_data_key(node()),
    RV =
        chronicle_compat:txn(
          fun (Txn) ->
                  Snapshot = fetch_snapshot(all, Txn, [uuid]),
                  BucketsWithData =
                      case chronicle_compat:txn_get(NodeKey, Txn) of
                          {ok, {V, _}} ->
                              V;
                          {error, not_found} ->
                              []
                      end,
                  NewBuckets =
                      lists:keystore(Name, 1, BucketsWithData,
                                     {Name, uuid(Name, Snapshot)}),

                  case filter_out_unknown_buckets(NewBuckets, Snapshot) of
                      BucketsWithData ->
                          {abort, not_changed};
                      Other ->
                          {commit, [{set, NodeKey, Other}]}
                  end
          end),
    case RV of
        not_changed ->
            ok;
        {ok, _} ->
            ok
    end.

deactivate_bucket_data_on_this_node(Name) ->
    case chronicle_kv:update(kv, buckets_with_data_key(node()),
                             lists:keydelete(Name, 1, _)) of
        {error, not_found} ->
            ok;
        {ok, _} ->
            ok
    end.

chronicle_upgrade_bucket(Func, BucketNames, ChronicleTxn) ->
    lists:foldl(
      fun (Name, Acc) ->
              Func(Name, Acc)
      end, ChronicleTxn, BucketNames).

%% These bucket properties were never GA'd and so should be removed from
%% any bucket configs that contain them.
removed_bucket_settings() ->
    [pitr_enabled, pitr_granularity, pitr_max_history_age].

chronicle_upgrade_bucket_to_morpheus(BucketName, ChronicleTxn) ->
    PropsKey = sub_key(BucketName, props),
    {ok, BucketConfig0} = chronicle_upgrade:get_key(PropsKey, ChronicleTxn),
    BucketConfig =
        lists:filter(
          fun ({Key, _Value}) ->
                  not lists:member(Key, removed_bucket_settings())
          end, BucketConfig0),
    AddProps =
        case bucket_type(BucketConfig) of
            memcached ->
                [];
            membase ->
                [{expiry_pager_sleep_time,
                  attribute_default(expiry_pager_sleep_time)},
                 {memory_low_watermark,
                  attribute_default(memory_low_watermark)},
                 {memory_high_watermark,
                  attribute_default(memory_high_watermark)},
                 %% The default value isn't used for existing buckets as it
                 %% may lead to XDCR setups stopping.
                 {invalid_hlc_strategy, ignore},
                 {dcp_connections_between_nodes,
                  attribute_default(dcp_connections_between_nodes)}] ++
                    case is_persistent(BucketConfig) of
                        true ->
                            [{access_scanner_enabled, true}];
                        false ->
                            []
                    end ++
                    case ns_bucket:is_magma(BucketConfig) of
                        true ->
                            [{continuous_backup_enabled,
                              attribute_default(continuous_backup_enabled)},
                             {continuous_backup_interval,
                              attribute_default(continuous_backup_interval)},
                             {continuous_backup_location,
                              attribute_default(continuous_backup_location)}];
                        false ->
                            []
                    end
        end,
    case AddProps of
        [] ->
            ChronicleTxn;
        _ ->
            NewBucketConfig = misc:merge_proplists(fun(_, L, _) -> L end,
                                                   AddProps, BucketConfig),
            chronicle_upgrade:set_key(PropsKey, NewBucketConfig,
                                      ChronicleTxn)
    end.

chronicle_upgrade_to_morpheus(ChronicleTxn) ->
    {ok, BucketNames} = chronicle_upgrade:get_key(root(), ChronicleTxn),
    chronicle_upgrade_bucket(chronicle_upgrade_bucket_to_morpheus(_, _),
                             BucketNames, ChronicleTxn).

default_76_enterprise_props(true = _IsEnterprise) ->
    [{cross_cluster_versioning_enabled, false},
     {version_pruning_window_hrs,
      attribute_default(version_pruning_window_hrs)}];
default_76_enterprise_props(false = _IsEnterprise) ->
    [].

chronicle_upgrade_bucket_to_76(BucketName, ChronicleTxn) ->
    PropsKey = sub_key(BucketName, props),
    AddProps =
        [{rank, ?DEFAULT_BUCKET_RANK}] ++
        default_76_enterprise_props(cluster_compat_mode:is_enterprise()),
    {ok, BucketConfig} = chronicle_upgrade:get_key(PropsKey, ChronicleTxn),
    NewBucketConfig = misc:merge_proplists(fun (_, L, _) -> L end, AddProps,
                                           BucketConfig),
    ChronicleTxn2 = chronicle_upgrade:set_key(PropsKey, NewBucketConfig,
                                              ChronicleTxn),
    CollectionsKey = sub_key(BucketName, collections),
    case chronicle_upgrade:get_key(CollectionsKey, ChronicleTxn2) of
        {error, not_found} ->
            ChronicleTxn2;
        {ok, Manifest} ->
            NewManifest = collections:upgrade_to_76(Manifest,
                                                         BucketConfig),
            chronicle_upgrade:set_key(CollectionsKey, NewManifest,
                                      ChronicleTxn2)
    end.

chronicle_upgrade_to_76(ChronicleTxn) ->
    {ok, BucketNames} = chronicle_upgrade:get_key(root(), ChronicleTxn),
    chronicle_upgrade_bucket(chronicle_upgrade_bucket_to_76(_, _),
                             BucketNames, ChronicleTxn).

upgrade_bucket_config_to_72(Bucket, ChronicleTxn) ->
    PropsKey = sub_key(Bucket, props),
    {ok, BCfg} = chronicle_upgrade:get_key(PropsKey, ChronicleTxn),
    case is_magma(BCfg) of
        true ->
            %% Only add the keys if this is a magma Bucket as they are
            %% not relevant to couchstore buckets.
            BCfg1 = lists:keystore(history_retention_seconds, 1, BCfg,
                                   {history_retention_seconds, 0}),
            BCfg2 = lists:keystore(history_retention_bytes, 1, BCfg1,
                                   {history_retention_bytes, 0}),
            BCfg3 =
                lists:keystore(history_retention_collection_default,
                               1, BCfg2,
                               {history_retention_collection_default,
                                true}),
            BCfg4 =
                lists:keystore(magma_key_tree_data_blocksize,
                               1, BCfg3,
                               {magma_key_tree_data_blocksize,
                                ?MAGMA_KEY_TREE_DATA_BLOCKSIZE}),
            BCfg5 =
                lists:keystore(magma_seq_tree_data_blocksize,
                               1, BCfg4,
                               {magma_seq_tree_data_blocksize,
                                ?MAGMA_SEQ_TREE_DATA_BLOCKSIZE}),

            chronicle_upgrade:set_key(PropsKey, BCfg5, ChronicleTxn);
        _ ->
            ChronicleTxn
    end.

chronicle_upgrade_to_72(ChronicleTxn) ->
    {ok, BucketNames} = chronicle_upgrade:get_key(root(), ChronicleTxn),
    lists:foldl(
      fun (Name, Txn) ->
              Txn1 = upgrade_bucket_config_to_72(Name, Txn),
              collections:chronicle_upgrade_to_72(Name, Txn1)
      end, ChronicleTxn, BucketNames).

%% returns proplist with only props useful for ns_bucket
extract_bucket_props(Props) ->
    [X || X <- [lists:keyfind(Y, 1, Props) ||
                   Y <- [num_replicas, replica_index, ram_quota,
                         durability_min_level, durability_impossible_fallback,
                         frag_percent, warmup_behavior,
                         storage_quota_percentage, num_vbuckets,
                         cross_cluster_versioning_enabled, vbuckets_max_cas,
                         version_pruning_window_hrs,
                         access_scanner_enabled, expiry_pager_sleep_time,
                         memory_low_watermark, memory_high_watermark,
                         autocompaction, purge_interval, flush_enabled,
                         num_threads, eviction_policy, conflict_resolution_type,
                         drift_ahead_threshold_ms, drift_behind_threshold_ms,
                         storage_mode, max_ttl, compression_mode,
                         magma_max_shards, weight, width, desired_servers,
                         {serverless, storage_limit, kv},
                         {serverless, storage_limit, index},
                         {serverless, storage_limit, fts},
                         {serverless, throttle_limit, kv},
                         {serverless, throttle_limit, index},
                         {serverless, throttle_limit, fts},
                         {serverless, throttle_limit, n1ql},
                         history_retention_seconds, history_retention_bytes,
                         magma_key_tree_data_blocksize,
                         magma_seq_tree_data_blocksize,
                         history_retention_collection_default, rank,
                         invalid_hlc_strategy,
                         encryption_secret_id,
                         encryption_dek_rotation_interval,
                         encryption_dek_lifetime,
                         continuous_backup_enabled,
                         continuous_backup_interval,
                         continuous_backup_location,
                         dcp_connections_between_nodes,
                         magma_fusion_logstore_uri]],
          X =/= false].

build_threshold({Percentage, Size}) ->
    {prepare_list([{percentage, Percentage}, {size, Size}])}.

build_bucket_props_json(Props) ->
    lists:foldl(
      fun ({autocompaction, false}, Acc) ->
              Acc;
          ({autocompaction, CProps}, Acc) ->
              [{autocompaction,
                {build_compaction_settings_json(CProps)}} | Acc];
          ({desired_servers, V}, Acc) ->
              [{desired_servers, [to_binary(El) || El <- V]} | Acc];
          ({K, V}, Acc) ->
              [{K, to_binary(V)} | Acc]
      end, [], Props).

build_compaction_settings_json(Settings) ->
    lists:foldl(
      fun ({allowed_time_period, V}, Acc) ->
              [{allowed_time_period, {prepare_list(V)}} | Acc];
          ({database_fragmentation_threshold, V}, Acc) ->
              [{database_fragmentation_threshold, build_threshold(V)} | Acc];
          ({view_fragmentation_threshold, V}, Acc) ->
              [{view_fragmentation_threshold, build_threshold(V)} | Acc];
          ({purge_interval, _} = T, Acc) ->
              [T | Acc];
          ({parallel_db_and_view_compaction, _} = T, Acc) ->
              [T | Acc];
          ({index_fragmentation_percentage, _} = T, Acc) ->
              [T | Acc];
          ({index_compaction_mode, _} = T, Acc) ->
              [T | Acc];
          ({index_circular_compaction_days, _} = T, Acc) ->
              [T | Acc];
          ({index_circular_compaction_abort, _} = T, Acc) ->
              [T | Acc];
          ({index_circular_compaction_interval, V}, Acc) ->
              [{index_circular_compaction_interval, {prepare_list(V)}} | Acc];
          ({magma_fragmentation_percentage, _} = T, Acc) ->
              [T | Acc];
          (_, Acc) ->
              Acc
      end, [], Settings).

get_hibernation_state(Props) ->
    proplists:get_value(hibernation_state, Props).

get_width(Props) ->
    proplists:get_value(width, Props).

get_weight(Props) ->
    proplists:get_value(weight, Props).

get_desired_servers(Props) ->
    proplists:get_value(desired_servers, Props).

update_desired_servers(DesiredServers, BucketConfig) ->
    lists:keystore(desired_servers, 1, BucketConfig,
                   {desired_servers, DesiredServers}).

-spec get_expected_servers(proplists:proplist()) -> [node()].
%% Use this to get the list of servers that the bucket will be on after creation
get_expected_servers(BucketConfig) ->
    case get_servers(BucketConfig) of
        [] ->
            case get_desired_servers(BucketConfig) of
                %% If desired servers is undefined then this is not a serverless
                %% cluster.
                %% When the servers list has not yet been populated we assume
                %% that the bucket will be placed on all nodes.
                undefined -> ns_cluster_membership:service_active_nodes(kv);
                Nodes -> Nodes
            end;
        Nodes -> Nodes
    end.

remove_bucket(BucketName) ->
    menelaus_users:cleanup_bucket_roles(BucketName),
    case delete_bucket(BucketName) of
        {ok, BucketConfig} ->
            ns_janitor_server:delete_bucket_request(BucketName),
            ns_server_stats:delete_bucket_stats(BucketName),
            {ok, BucketConfig};
        Other ->
            Other
    end.

validate_encryption_secret(?SECRET_ID_NOT_SET, _Bucket, _Snapshot) ->
    ok;
validate_encryption_secret(SecretId, Bucket, Snapshot) ->
    case cb_cluster_secrets:ensure_can_encrypt_dek_kind(SecretId,
                                                        {bucketDek, Bucket},
                                                        Snapshot) of
        ok -> ok;
        {error, not_found} -> {error, secret_not_found};
        {error, not_allowed} -> {error, secret_not_allowed}
    end.

get_encryption(BucketName, Snapshot) ->
    case get_bucket(BucketName, Snapshot) of
        {ok, BucketConfig} ->
            IsNodeInServers = lists:member(node(), get_servers(BucketConfig)),
            {ok, Dir} = ns_storage_conf:this_node_bucket_dbdir(BucketName),
            ExistsOnDisk = filelib:is_dir(Dir),
            Services = ns_cluster_membership:node_services(Snapshot, node()),
            IsKVNode = lists:member(kv, Services),
            case IsNodeInServers orelse (IsKVNode andalso ExistsOnDisk) of
                true ->
                    case proplists:get_value(encryption_secret_id, BucketConfig,
                                             ?SECRET_ID_NOT_SET) of
                        ?SECRET_ID_NOT_SET -> {ok, disabled};
                        Id -> {ok, {secret, Id}}
                    end;
                false ->
                    {error, not_found}
            end;
        not_present ->
            {error, not_found}
    end.

get_dek_lifetime(BucketName, Snapshot) ->
    case get_bucket(BucketName, Snapshot) of
        {ok, BucketConfig} ->
            Val = proplists:get_value(encryption_dek_lifetime, BucketConfig,
                                      ?DEFAULT_DEK_LIFETIME_S),
            case Val of
                0 -> {ok, undefined};
                _ -> {ok, Val}
            end;
        not_present ->
            {error, not_found}
    end.

get_dek_rotation_interval(BucketName, Snapshot) ->
    case get_bucket(BucketName, Snapshot) of
        {ok, BucketConfig} ->
            Val = proplists:get_value(encryption_dek_rotation_interval,
                                      BucketConfig,
                                      ?DEFAULT_DEK_ROTATION_INTERVAL_S),
            case Val of
                0 -> {ok, undefined};
                _ -> {ok, Val}
            end;
        not_present ->
            {error, not_found}
    end.

get_drop_keys_timestamp(Bucket, Snapshot) ->
    maybe
        {ok, Config} ?= get_bucket(Bucket, Snapshot),
        {ok, #{dek_drop_datetime := DT}} ?=
            chronicle_compat:get(Snapshot, sub_key(Bucket, encr_at_rest), #{}),
        ToggleDate = proplists:get_value(encryption_last_toggle_datetime,
                                         Config),
        case ToggleDate of
            undefined -> {ok, DT};
            {_, _} when ToggleDate =< DT -> {ok, DT};
            {_, _} -> {ok, undefined}
        end
    else
        not_present -> {error, not_found};
        {ok, #{}} -> {ok, undefined};
        {error, not_found} -> {ok, undefined}
    end.

-ifdef(TEST).
min_live_copies_test() ->
    ?assertEqual(min_live_copies([node1], []), undefined),
    ?assertEqual(min_live_copies([node1], [{map, undefined}]), undefined),
    Map1 = [[node1, node2], [node2, node1]],
    ?assertEqual(2, min_live_copies([node1, node2], [{map, Map1}])),
    ?assertEqual(1, min_live_copies([node1], [{map, Map1}])),
    ?assertEqual(0, min_live_copies([node3], [{map, Map1}])),
    Map2 = [[undefined, node2], [node2, node1]],
    ?assertEqual(1, min_live_copies([node1, node2], [{map, Map2}])),
    ?assertEqual(0, min_live_copies([node1, node3], [{map, Map2}])).

get_expected_servers_test() ->
    meck:new(ns_cluster_membership, [passthrough]),
    meck:expect(ns_cluster_membership, service_active_nodes,
                fun (_) -> [node1, node2] end),
    %% By default get the servers list
    ?assertEqual([node1], get_expected_servers([{servers, [node1]}])),
    %% When servers is not yet populated, check desired servers
    ?assertEqual([node1], get_expected_servers([{servers, []},
                                                {desired_servers, [node1]}])),
    %% Default to all kv nodes, when desired_servers is undefined
    ?assertEqual([node1, node2], get_expected_servers([{servers, []}])),
    %% Current server's list takes precedent over desired_servers when populated
    ?assertEqual([node1], get_expected_servers([{servers, [node1]},
                                                {desired_servers, [node2]}])),
    meck:unload(ns_cluster_membership).

drift_thresholds_test() ->
    %% When conflict_resolution_type != lww and history_retention_seconds == 0,
    %% there should be no drift thresholds
    BucketConfig1 = [{conflict_resolution_type, seqno},
                     {history_retention_seconds, 0},
                     {drift_ahead_threshold_ms, 1},
                     {drift_behind_threshold_ms, 2}],
    ?assertEqual(undefined, drift_thresholds(BucketConfig1)),

    %% When conflict_resolution_type != lww and history_retention_seconds is
    %% undefined, there should be no drift thresholds
    BucketConfig2 = [{conflict_resolution_type, custom},
                     {drift_ahead_threshold_ms, 1},
                     {drift_behind_threshold_ms, 2}],
    ?assertEqual(undefined, drift_thresholds(BucketConfig2)),

    %% When conflict_resolution_type == lww, there should be drift thresholds
    BucketConfig3 = [{conflict_resolution_type, lww},
                     {history_retention_seconds, 0},
                     {drift_ahead_threshold_ms, 1},
                     {drift_behind_threshold_ms, 2}],
    ?assertEqual({1, 2}, drift_thresholds(BucketConfig3)),

    %% When history_retention_seconds > 0, there should be drift thresholds
    BucketConfig4 = [{conflict_resolution_type, seqno},
                     {history_retention_seconds, 1},
                     {drift_ahead_threshold_ms, 1},
                     {drift_behind_threshold_ms, 2}],
    ?assertEqual({1, 2}, drift_thresholds(BucketConfig4)).

update_bucket_props_allowed_test() ->
    %% No per-node override keys set in the BucketConfig.
    %% Expectation: Bucket updates allowed.
    NewProps = [{storage_mode, magma},
                {foo, blah}],
    BucketConfig = [{storage_mode, couchstore},
                    {type, membase},
                    {ram_quota, 1024},
                    {foo, blah}],
    ?assert(update_bucket_props_allowed(NewProps, BucketConfig)),

    %% per-node override keys set in the BucketConfig.
    %% Expectation: storage_mode update allowed.
    BucketConfig1 = BucketConfig ++ [{{node, n1, storage_mode}, magma}],
    ?assert(update_bucket_props_allowed(NewProps, BucketConfig1)),

    %% per-node override keys set in the BucketConfig.
    %% Expectation: ram_quota update allowed.
    NewProps1 = [{ram_quota, 2048}],
    ?assert(update_bucket_props_allowed(NewProps1, BucketConfig1)),

    NewProps2 = [{foo, not_blah}],

    %% per-node override keys set in the BucketConfig.
    %% Expectation: can not change any bucket props.
    ?assertEqual({false, {storage_mode_migration, in_progress}},
                 update_bucket_props_allowed(NewProps2, BucketConfig1)),

    %% per-node override keys set in the BucketConfig.
    %% Expectation: can not add any new bucket props.
    NewProps3 = [{bar, blah}],
    ?assertEqual({false, {storage_mode_migration, in_progress}},
                 update_bucket_props_allowed(NewProps3, BucketConfig1)).

add_override_props_test() ->
    meck:new(cluster_compat_mode, [passthrough]),
    meck:expect(cluster_compat_mode, is_cluster_morpheus,
                fun () -> true end),
    meck:expect(cluster_compat_mode, is_enterprise,
                fun () -> true end),

    Servers = [n0, n1],

    MagmaACSettings = [{magma_fragement_percentage, 60}],
    CouchstoreACSettings =
        [{parallel_db_and_view_compaction,false},
                          {database_fragmentation_threshold,{30,undefined}},
                          {view_fragmentation_threshold,{30,undefined}}],
    BucketConfig = [{type, membase},
                    {storage_mode, couchstore},
                    {servers, Servers},
                    {autocompaction, CouchstoreACSettings}],

    Props = [{storage_mode, magma},
             {autocompaction, false}],
    ExpectedProps =
        Props ++
        lists:foldl(
          fun (N, Acc) ->
                  [{{node, N, storage_mode}, couchstore},
                   {{node, N, autocompaction}, CouchstoreACSettings} | Acc]
          end, [], Servers),

    {NewProps, DK} = add_override_props(Props, BucketConfig),

    ?assertEqual(lists:sort(ExpectedProps), lists:sort(NewProps)),
    ?assertEqual(DK, []),

    %% node n1 has been migrated to magma, now revert the storage_mode back to
    %% couchstore.
    BucketConfig1 = [{type, membase},
                     {storage_mode, magma},
                     {autocompaction, MagmaACSettings},
                     {servers, Servers},
                     {{node, n0, storage_mode}, couchstore},
                     {{node, n0, autocompaction}, CouchstoreACSettings}],

    Props1 = [{storage_mode, couchstore}],
    ExpectedProps1 = [{storage_mode, couchstore},
                      {autocompaction, CouchstoreACSettings},
                      {{node, n1, storage_mode}, magma},
                      {{node, n1, autocompaction}, MagmaACSettings}],
    DeleteKeys = [{node, n0, storage_mode},
                  {node, n0, autocompaction}],
    {NewProps1, DK1} =
        add_override_props(Props1, BucketConfig1),

    ?assertListsEqual(NewProps1, ExpectedProps1),
    ?assertListsEqual(DK1, DeleteKeys),

    meck:unload(cluster_compat_mode).

remove_override_props_test() ->
    Props = [{type, membase},
             {storage_mode, magma},
             {autocompaction, magma_compaction_settings},
             {servers, [n0, n1, n2]},
             {{node, n1, storage_mode}, couchstore},
             {{node, n2, storage_mode}, couchstore},
             {{node, n1, autocompaction}, couchstore_compaction_settings},
             {{node, n2, autocompaction}, couchstore_compaction_settings}],
    RemoveNodes = [n1],
    ExpectedProps =
        Props -- [{{node, n1, storage_mode}, couchstore},
                  {{node, n1, autocompaction}, couchstore_compaction_settings}],
    ?assertEqual(ExpectedProps,
                 remove_override_props(Props, RemoveNodes)).

node_autocompaction_settings_test() ->
    ?assertEqual([],
                 node_autocompaction_settings(
                   [{autocompaction, false}])),
    ?assertEqual(per_node_setting,
                 node_autocompaction_settings(
                   [{autocompaction, false},
                    {{node, node(), autocompaction}, per_node_setting}])),
    ?assertEqual(per_node_setting,
                 node_autocompaction_settings(
                   [{autocompaction, bucket_setting},
                    {{node, node(), autocompaction}, per_node_setting}])),
    ?assertEqual(bucket_setting,
                 node_autocompaction_settings(
                   [{autocompaction, bucket_setting}])),
    ?assertEqual([],
                 node_autocompaction_settings(
                   [{autocompaction, bucket_setting},
                    {{node, node(), autocompaction}, false}])).

assert_sorted(Expected, Given) ->
    ?assertEqual(Expected, lists:map(fun ({K, _V}) -> K end,
                                     lists:sort(rank_sorting_fn(), Given))).

%% Asserts that the sorting function sorts by the 'rank' key from high-low,
%% while sorting based on name, if the ranks are equal. The secondary
%% sorting is done in alphabetical order from A-Z..
sorting_fn_test_() ->
    LL = [{["B", "C", "D", "A"],
           [{"A", [{rank, 0}, {name, "A"}]},
            {"B", [{rank, 11}, {name, "B"}]},
            {"C", [{rank, 10}, {name, "C"}]},
            {"D", [{rank, 9}, {name, "D"}]}]},
          {["X", "Y", "A", "Z"],
           [{"X", [{rank, 100}, {name, "X"}]},
            {"Y", [{rank, 12}, {name, "Y"}]},
            {"Z", [{rank, 0}, {name, "Z"}]},
            {"A", [{rank, 0}, {name, "A"}]}]},
          {["4", "2", "1", "3", "5"],
           [{"5", [{rank, 0}, {name, "5"}]},
            {"4", [{rank, 66}, {name, "4"}]},
            {"3", [{rank, 0}, {name, "3"}]},
            {"2", [{rank, 5}, {name, "2"}]},
            {"1", [{rank, 0}, {name, "1"}]}]},
          {["A", "AA", "AAA", "B", "Z"],
           [{"B", [{rank, 2}, {name, "B"}]},
            {"Z", [{rank, 1}, {name, "Z"}]},
            {"A", [{rank, 100}, {name, "A"}]},
            {"AAA", [{rank, 87}, {name, "AAA"}]},
            {"AA", [{rank, 88}, {name, "AA"}]}]}],

    {setup, fun () -> ok end, fun (_) -> ok end,
     [{lists:flatten(io_lib:format("Sorting function test for: ~p",
                                   [Expected])),
       fun () ->
               assert_sorted(Expected, Given)
       end} || {Expected, Given} <- LL]}.

get_max_buckets_test_() ->
    MeckModules = [ns_config, ns_cluster_membership, ns_doctor],
    Nodes = [node1, node2],

    Tests =
        [{30, 30, #{}, false, 1},
         {10, 10, #{}, false, 1},
         {30, 30, #{node1 => 5}, false, 1},
         {5, 30, #{node1 => 5}, true, 1},
         {3, 30, #{node1 => 3}, true, 1},
         {3, 30, #{node1 => 12, node2 => 6}, true, 2},
         {12, 30, #{node1 => 12, node2 => 6}, true, 0.5},
         {30, 30, #{}, true, 0.5}],

    {setup, fun() ->
                    meck:new(MeckModules, [passthrough]),
                    meck:expect(ns_cluster_membership, service_active_nodes,
                                fun (kv) -> Nodes end)
            end,
     fun (_) -> meck:unload(MeckModules) end,
     [{lists:flatten(io_lib:format("get_max_buckets test for: ~p",
                                   [T])),
       fun () ->
               meck:expect(ns_config, read_key_fast,
                           fun (max_bucket_count, _) ->
                                   MaxSupported;
                               (resource_management, _) ->
                                   [{cores_per_bucket,
                                     [{enabled, CoresEnabled},
                                      {minimum, CoresPerBucket}]}]
                           end),
               meck:expect(ns_doctor, get_node,
                           fun (Node) ->
                                   case maps:get(Node, NodeCores, undefined) of
                                       undefined -> [];
                                       Cores -> [{cpu_count, Cores}]
                                   end
                           end),
               ?assertEqual(Expected, get_max_buckets())
       end}
      || {Expected, MaxSupported, NodeCores, CoresEnabled, CoresPerBucket} = T
             <- Tests]}.

-endif.
