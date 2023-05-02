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
-include("cut.hrl").

-ifdef(TEST).
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
         kv_backend_type/1,
         num_replicas_changed/1,
         create_bucket/3,
         restore_bucket/4,
         delete_bucket/1,
         display_type/1,
         display_type/2,
         external_bucket_type/1,
         durability_min_level/1,
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
         is_named_bucket_persistent/1,
         is_persistent/1,
         is_ephemeral_bucket/1,
         is_valid_bucket_name/1,
         live_bucket_nodes/1,
         live_bucket_nodes_from_config/1,
         map_to_replicas/1,
         replicated_vbuckets/3,
         name_conflict/1,
         name_conflict/2,
         node_locator/1,
         num_replicas/1,
         pitr_enabled/1,
         pitr_granularity/1,
         pitr_max_history_age/1,
         attribute_default/1,
         attribute_min/1,
         attribute_max/1,
         ram_quota/1,
         conflict_resolution_type/1,
         drift_thresholds/1,
         history_retention_seconds/1,
         history_retention_bytes/1,
         history_retention_collection_default/1,
         eviction_policy/1,
         storage_mode/1,
         storage_backend/1,
         raw_ram_quota/1,
         magma_fragmentation_percentage/1,
         magma_max_shards/2,
         magma_key_tree_data_blocksize/1,
         magma_seq_tree_data_blocksize/1,
         update_maps/3,
         update_buckets/3,
         multi_prop_update/2,
         set_bucket_config/2,
         set_bucket_config_failover/3,
         set_fast_forward_map/2,
         set_map/2,
         set_initial_map/4,
         set_map_opts/2,
         set_servers/2,
         set_restored_attributes/3,
         remove_servers/2,
         clear_hibernation_state/1,
         update_bucket_props/2,
         update_bucket_props/4,
         node_bucket_names/1,
         node_bucket_names/2,
         node_bucket_names_of_type/2,
         node_bucket_names_of_type/3,
         all_node_vbuckets/1,
         store_last_balanced_vbmap/3,
         past_vbucket_maps/1,
         past_vbucket_maps/2,
         config_to_map_options/1,
         can_have_views/1,
         is_magma/1,
         get_view_nodes/1,
         get_default_num_vbuckets/0,
         allow_variable_num_vbuckets/0,
         get_num_vbuckets/1,
         get_max_buckets/0,
         uuid_key/1,
         uuid/2,
         uuids/0,
         uuids/1,
         buckets_with_data_on_this_node/0,
         activate_bucket_data_on_this_node/1,
         deactivate_bucket_data_on_this_node/1,
         config_upgrade_to_66/1,
         upgrade_to_chronicle/2,
         chronicle_upgrade_to_71/1,
         chronicle_upgrade_to_72/1,
         chronicle_upgrade_to_elixir/1,
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
         remove_bucket/1]).

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

all_keys(Names, SubKeys) ->
    [sub_key(B, SubKey) || B <- Names, SubKey <- SubKeys].

fetch_snapshot(Bucket, Txn) ->
    fetch_snapshot(Bucket, Txn, all_sub_keys()).

fetch_snapshot(_Bucket, {ns_config, Config}, _SubKeys) ->
    Converted = bucket_configs_to_chronicle(get_buckets(Config), false),
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

upgrade_to_chronicle(Buckets, NodesWanted) ->
    BucketConfigs = proplists:get_value(configs, Buckets, []),
    bucket_configs_to_chronicle(BucketConfigs, true) ++
        collections:default_kvs(BucketConfigs, NodesWanted).

bucket_configs_to_chronicle(BucketConfigs, ToChronicle) ->
    [{root(), [N || {N, _} <- BucketConfigs]} |
     lists:flatmap(
       fun ({B, BC}) ->
               {value, {uuid, UUID}, BC1} = lists:keytake(uuid, 1, BC),
               BC2 = case ToChronicle of
                         true ->
                             lists:keydelete(sasl_password, 1, BC1);
                         false ->
                             BC1
                     end,
               [{sub_key(B, props), BC2},
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

get_bucket(Bucket, direct) ->
    case chronicle_compat:backend() of
        chronicle ->
            case chronicle_compat:get(sub_key(Bucket, props), #{}) of
                {ok, Props} ->
                    {ok, Props};
                {error, not_found} ->
                    not_present
            end;
        ns_config ->
            get_bucket(Bucket, ns_config:latest())
    end;
get_bucket(Bucket, Snapshot) when is_map(Snapshot) ->
    case maps:find(sub_key(Bucket, props), Snapshot) of
        {ok, {Props, _}} ->
            {ok, Props};
        error ->
            not_present
    end;
get_bucket(Bucket, Config) ->
    BucketConfigs = get_buckets(Config),
    get_bucket_from_configs(Bucket, BucketConfigs).

ensure_bucket(Bucket) ->
    case get_bucket(Bucket) of
        not_present ->
            exit({bucket_not_present, Bucket});
        {ok, BucketConfig} ->
            BucketConfig
    end.

get_bucket_from_configs(Bucket, Configs) ->
    case lists:keysearch(Bucket, 1, Configs) of
        {value, {_, BucketConfig}} ->
            {ok, BucketConfig};
        false -> not_present
    end.

get_bucket_names() ->
    get_bucket_names(direct).

get_bucket_names(direct) ->
    case chronicle_compat:backend() of
        chronicle ->
            chronicle_compat:get(root(), #{required => true});
        ns_config ->
            get_bucket_names(get_buckets())
    end;
get_bucket_names(Snapshot) when is_map(Snapshot) ->
    {ok, {Names, _}} = maps:find(root(), Snapshot),
    Names;
get_bucket_names(BucketConfigs) ->
    proplists:get_keys(BucketConfigs).

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

get_buckets() ->
    get_buckets(direct).

get_buckets(direct) ->
    case chronicle_compat:backend() of
        chronicle ->
            get_buckets(get_snapshot(all, [props]));
        ns_config ->
            get_buckets(ns_config:latest())
    end;
get_buckets(Snapshot) when is_map(Snapshot) ->
    lists:map(fun (N) ->
                      {ok, {Props, _}} = maps:find(sub_key(N, props), Snapshot),
                      {N, Props}
              end, get_bucket_names(Snapshot));
get_buckets(Config) ->
    ns_config:search_prop(Config, buckets, configs, []).

live_bucket_nodes(Bucket) ->
    {ok, BucketConfig} = get_bucket(Bucket),
    live_bucket_nodes_from_config(BucketConfig).

live_bucket_nodes_from_config(BucketConfig) ->
    Servers = get_servers(BucketConfig),
    LiveNodes = [node()|nodes()],
    [Node || Node <- Servers, lists:member(Node, LiveNodes) ].

-spec conflict_resolution_type([{_,_}]) -> atom().
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

-spec history_retention_seconds([{_,_}]) -> integer().
history_retention_seconds(BucketConfig) ->
    proplists:get_value(history_retention_seconds, BucketConfig,
                        ?HISTORY_RETENTION_SECONDS_DEFAULT).

-spec history_retention_bytes([{_,_}]) -> integer().
history_retention_bytes(BucketConfig) ->
    proplists:get_value(history_retention_bytes, BucketConfig,
                        ?HISTORY_RETENTION_BYTES_DEFAULT).

-spec history_retention_collection_default([{_,_}]) -> boolean().
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

-spec storage_mode([{_,_}]) -> atom().
storage_mode(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            undefined;
        membase ->
            proplists:get_value(storage_mode, BucketConfig, couchstore)
    end.

-spec storage_backend([{_,_}]) -> atom().
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

%% Point-in-time Recovery numerical parameter ranges and default values.

%% The default value of the attribute. Currently PITR-only.
attribute_default(Name) ->
    case Name of
        pitr_granularity -> 600;        % 10 minutes
        pitr_max_history_age -> 86400   % 24 hours
    end.

%% The minimum value of the attribute. Currently PITR-only.
attribute_min(Name) ->
    case Name of
        pitr_granularity -> 1;          % 1 second
        pitr_max_history_age -> 1       % 1 second
    end.

%% The maximum value of the attribute. Currently PITR-only.
attribute_max(Name) ->
    case Name of
        pitr_granularity -> 18000;      % 5 hours
        pitr_max_history_age -> 172800  % 48 hours
    end.

%% Per-bucket-type point-in-time recovery attributes.  Point-in-time
%% recovery is not supported on memcached buckets.
pitr_enabled(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            false;
        membase ->
            proplists:get_bool(pitr_enabled, BucketConfig)
    end.

pitr_granularity(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            undefined;
        membase ->
            proplists:get_value(pitr_granularity, BucketConfig,
                                attribute_default(pitr_granularity))
    end.

pitr_max_history_age(BucketConfig) ->
    case bucket_type(BucketConfig) of
        memcached ->
            undefined;
        membase ->
            proplists:get_value(pitr_max_history_age, BucketConfig,
                                attribute_default(pitr_max_history_age))
    end.

%% returns bucket ram quota multiplied by number of nodes this bucket
%% will reside after initial cleanup. I.e. gives amount of ram quota that will
%% be used by across the cluster for this bucket.
-spec ram_quota([{_,_}]) -> integer().
ram_quota(Bucket) ->
    case proplists:get_value(ram_quota, Bucket) of
        X when is_integer(X) ->
            X * length(get_expected_servers(Bucket))
    end.

%% returns bucket ram quota for _single_ node. Each node will subtract
%% this much from it's node quota.
-spec raw_ram_quota([{_,_}]) -> integer().
raw_ram_quota(Bucket) ->
    case proplists:get_value(ram_quota, Bucket) of
        X when is_integer(X) ->
            X
    end.

magma_fragmentation_percentage(BucketConfig) ->
    BucketSetting =
        case proplists:get_value(autocompaction, BucketConfig, false) of
            false ->
                false;
            Settings ->
                proplists:get_value(magma_fragmentation_percentage, Settings,
                                    false)
        end,

    case BucketSetting of
        false ->
            compaction_daemon:global_magma_frag_percent();
        Pct ->
            Pct
    end.

magma_max_shards(BucketConfig, Default) ->
    proplists:get_value(magma_max_shards, BucketConfig, Default).

-spec magma_key_tree_data_blocksize([{_,_}]) -> integer().
magma_key_tree_data_blocksize(BucketConfig) ->
    proplists:get_value(magma_key_tree_data_blocksize, BucketConfig,
                        ?MAGMA_KEY_TREE_DATA_BLOCKSIZE).

-spec magma_seq_tree_data_blocksize([{_,_}]) -> integer().
magma_seq_tree_data_blocksize(BucketConfig) ->
    proplists:get_value(magma_seq_tree_data_blocksize, BucketConfig,
                        ?MAGMA_SEQ_TREE_DATA_BLOCKSIZE).

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
    case cluster_compat_mode:is_cluster_71() andalso
        not racks_balanced(KvGroups) of
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

-spec num_replicas([{_,_}]) -> integer().
num_replicas(Bucket) ->
    case proplists:get_value(num_replicas, Bucket) of
        X when is_integer(X) ->
            X
    end.

%% ns_server type (membase vs memcached)
bucket_type(Bucket) ->
    proplists:get_value(type, Bucket).

%% KV type (persistent vs ephemeral)
kv_bucket_type(BucketConfig) ->
    case is_persistent(BucketConfig) of
        true -> persistent;
        false -> ephemeral
    end.

kv_backend_type(BucketConfig) ->
    StorageMode = storage_mode(BucketConfig),
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

get_max_buckets() ->
    Default = config_profile:get_value(max_buckets_supported,
                                       ?MAX_BUCKETS_SUPPORTED),
    ns_config:read_key_fast(max_bucket_count, Default).

get_default_num_vbuckets() ->
    case ns_config:search(couchbase_num_vbuckets_default) of
        false ->
            misc:getenv_int("COUCHBASE_NUM_VBUCKETS",
              config_profile:get_value(default_num_vbuckets, 1024));
        {value, X} ->
            X
    end.

allow_variable_num_vbuckets() ->
    config_profile:get_bool(allow_variable_num_vbuckets).

get_num_vbuckets(BucketConfig) ->
    proplists:get_value(num_vbuckets, BucketConfig).

new_bucket_default_params(membase) ->
    [{type, membase},
     {num_vbuckets, get_default_num_vbuckets()},
     {num_replicas, 1},
     {ram_quota, 0},
     {replication_topology, star},
     {repl_type, dcp},
     {servers, []}];
new_bucket_default_params(memcached) ->
    Nodes = ns_cluster_membership:service_active_nodes(kv),
    [{type, memcached},
     {num_vbuckets, 0},
     {num_replicas, 0},
     {servers, Nodes},
     {map, []},
     {ram_quota, 0}].

cleanup_bucket_props(Props) ->
    lists:keydelete(moxi_port, 1, Props).

generate_sasl_password() ->
    binary_to_list(couch_uuids:random()).

generate_sasl_password(Props) ->
    case cluster_compat_mode:is_cluster_70() of
        false ->
            %% Backwards compatility with older releases that require
            %% this property
            lists:keystore(sasl_password, 1, Props,
                           {sasl_password, generate_sasl_password()});
        true ->
            Props
    end.

add_auth_type(Props) ->
    case cluster_compat_mode:is_cluster_71() of
        true ->
            Props;
        false ->
            %% Required property of older versions
            [{auth_type, sasl} | Props]
    end.

create_bucket(BucketType, BucketName, NewConfig) ->
    MergedConfig0 =
        misc:update_proplist(new_bucket_default_params(BucketType),
                             NewConfig),
    MergedConfig1 = generate_sasl_password(MergedConfig0),
    MergedConfig = add_auth_type(MergedConfig1),
    BucketUUID = couch_uuids:random(),
    Manifest = collections:default_manifest(MergedConfig),
    do_create_bucket(chronicle_compat:backend(), BucketName,
                     MergedConfig, BucketUUID, Manifest),
    %% The janitor will handle creating the map.
    {ok, BucketUUID, MergedConfig}.

restore_bucket(BucketName, NewConfig, BucketUUID, Manifest) ->
    case is_valid_bucket_name(BucketName) of
        true ->
            do_create_bucket(chronicle, BucketName, NewConfig, BucketUUID,
                             Manifest),
            ok;
        {error, _} ->
            {error, {invalid_bucket_name, BucketName}}
    end.

do_create_bucket(ns_config, BucketName, Config, BucketUUID, _Manifest) ->
    ns_config:update_sub_key(
      buckets, configs,
      fun (List) ->
              case lists:keyfind(BucketName, 1, List) of
                  false -> ok;
                  Tuple ->
                      exit({already_exists, Tuple})
              end,
              [{BucketName, [{uuid, BucketUUID} | Config]} | List]
      end);
do_create_bucket(chronicle, BucketName, Config, BucketUUID, Manifest) ->
    {ok, _} =
        chronicle_kv:transaction(
          kv, [root(), nodes_wanted, buckets_marked_for_shutdown_key()],
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

                  case {name_conflict(BucketName, BucketNames),
                        name_conflict(BucketName, ShutdownBucketNames)} of
                      {true, _} ->
                          {abort, already_exists};
                      {_, true} ->
                          {abort, still_exists};
                      {false, false} ->
                          {commit, create_bucket_sets(BucketName, BucketNames,
                                                      BucketUUID, Config) ++
                                   collections_sets(BucketName, Config,
                                                    Snapshot, Manifest)}
                  end
          end).

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
    do_delete_bucket(chronicle_compat:backend(), BucketName).

do_delete_bucket(ns_config, BucketName) ->
    Ref = make_ref(),
    Process = self(),
    RV = ns_config:update_sub_key(
           buckets, configs,
           fun (List) ->
                   case lists:keyfind(BucketName, 1, List) of
                       false -> exit({not_found, BucketName});
                       {_, BucketConfig} = Tuple ->
                           Process ! {Ref, BucketConfig},
                           lists:delete(Tuple, List)
                   end
           end),
    case RV of
        ok ->
            receive
                {Ref, BucketConfig} ->
                    {ok, BucketConfig}
            after 0 ->
                    exit(this_cannot_happen)
            end;
        {exit, {not_found, _}, _} ->
            RV
    end;
do_delete_bucket(chronicle, BucketName) ->
    RootKey = root(),
    PropsKey = sub_key(BucketName, props),
    IsClusterElixir = cluster_compat_mode:is_cluster_elixir(),

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
                                uuid_key(BucketName), PropsKey |
                                [collections:last_seen_ids_key(N, BucketName) ||
                                    N <- NodesWanted]],
                           {commit,
                            [{set, RootKey, BucketNames -- [BucketName]}] ++
                            %% We need to ensure the cluster is elixir to avoid
                            %% running into issues similar to the one described
                            %% here:
                            %%
                            %% https://review.couchbase.org/c/ns_server/+/
                            %% 188906/comments/209b4dbb_78588f3e
                            [add_marked_for_shutdown(
                               Snapshot, {BucketName, BucketConfig}) ||
                             IsClusterElixir] ++
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
    case ns_bucket:kv_backend_type(BucketConfig) of
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

    check_test_condition({wait_for_bucket_shutdown, BucketName}),

    case LeftoverNodes of
        [] ->
            ok;
        _ ->
            {shutdown_failed, LeftoverNodes}
    end.

%% Updates properties of bucket of given name and type.  Check of type
%% protects us from type change races in certain cases.
%%
%% If bucket with given name exists, but with different type, we
%% should return {exit, {not_found, _}, _}
update_bucket_props(Type, StorageMode, BucketName, Props) ->
    case lists:member(BucketName,
                      get_bucket_names_of_type({Type, StorageMode})) of
        true ->
            {ok, BucketConfig} = get_bucket(BucketName),
            PrevProps = extract_bucket_props(BucketConfig),
            DisplayBucketType = display_type(Type, StorageMode),

            %% Update the bucket properties.
            RV = update_bucket_props(BucketName, Props),

            case RV of
                ok ->
                    {ok, NewBucketConfig} = get_bucket(BucketName),
                    NewProps = extract_bucket_props(NewBucketConfig),
                    if
                        PrevProps =/= NewProps ->
                            event_log:add_log(
                              bucket_cfg_changed,
                              [{bucket, list_to_binary(BucketName)},
                               {bucket_uuid, uuid(BucketName, direct)},
                               {type, DisplayBucketType},
                               {old_settings,
                                {build_bucket_props_json(PrevProps)}},
                               {new_settings,
                                {build_bucket_props_json(NewProps)}}]);
                        true ->
                            ok
                    end,
                    ok;
                _ ->
                    RV
            end;
        false ->
            {exit, {not_found, BucketName}, []}
    end.

update_bucket_props(BucketName, Props) ->
    update_bucket_config(
      BucketName,
      fun (OldProps) ->
              NewProps = lists:foldl(
                           fun ({K, _V} = Tuple, Acc) ->
                                   [Tuple | lists:keydelete(K, 1, Acc)]
                           end, OldProps, Props),
              cleanup_bucket_props(NewProps)
      end).

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
    case chronicle_compat:backend() of
        ns_config ->
            set_map_opts(Bucket, MapOpts),
            set_map(Bucket, Map);
        chronicle ->
            validate_map(Map),
            update_init_map_config(
              Bucket, Servers,
              fun (OldConfig) ->
                      OldMap = proplists:get_value(map, OldConfig, []),
                      master_activity_events:note_set_map(Bucket, Map, OldMap),
                      misc:update_proplist(
                        OldConfig,
                        [{map, Map}, {map_opts_hash, erlang:phash2(MapOpts)}])
              end)
    end.

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

remove_servers(Bucket, Nodes) ->
    ok = update_bucket_config(
           Bucket,
           fun (OldConfig) ->
                   Servers = get_servers(OldConfig),
                   C1 = update_servers(Servers -- Nodes, OldConfig),
                   case get_desired_servers(OldConfig) of
                       undefined ->
                           C1;
                       DesiredServers ->
                           update_desired_servers(DesiredServers -- Nodes, C1)
                   end
           end).

clear_hibernation_state(Bucket) ->
    ok = update_bucket_config(
           Bucket,
           fun (OldConfig) ->
                   proplists:delete(hibernation_state, OldConfig)
           end).

set_bucket_config_failover(Bucket, NewMap, FailedNodes) ->
    validate_map(NewMap),
    ok = update_bucket_config(
           Bucket,
           fun (OldConfig) ->
                   Servers = ns_bucket:get_servers(OldConfig),
                   C1 = lists:foldl(
                          fun({Key, Value}, Cfg) ->
                                  lists:keystore(Key, 1, Cfg, {Key, Value})
                          end, OldConfig, [{servers, Servers -- FailedNodes},
                                           {fastForwardMap, undefined},
                                           {map, NewMap}]),
                   NewConfig = case ns_bucket:get_desired_servers(C1) of
                                   undefined ->
                                       C1;
                                   DesiredServers ->
                                       ns_bucket:update_desired_servers(
                                         DesiredServers -- FailedNodes, C1)
                               end,
                   master_activity_events:note_set_ff_map(
                     Bucket, undefined,
                     proplists:get_value(fastForwardMap, OldConfig, [])),
                   master_activity_events:note_set_map(
                     Bucket, NewMap, proplists:get_value(map, OldConfig, [])),
                   NewConfig
           end).

% Update the bucket config atomically.
update_bucket_config(BucketName, Fun) ->
    update_bucket_config(chronicle_compat:backend(), BucketName, Fun).

update_bucket_config(ns_config, BucketName, Fun) ->
    ns_config:update_sub_key(
      buckets, configs,
      fun (Buckets) ->
              RV = misc:key_update(BucketName, Buckets, Fun),
              RV =/= false orelse exit({not_found, BucketName}),
              RV
      end);
update_bucket_config(chronicle, BucketName, Fun) ->
    PropsKey = sub_key(BucketName, props),
    RV =
        chronicle_kv:transaction(
          kv, [PropsKey],
          fun (Snapshot) ->
                  case get_bucket(BucketName, Snapshot) of
                      {ok, Config} ->
                          {commit, [{set, PropsKey, Fun(Config)}]};
                      not_present ->
                          {abort, not_found}
                  end
          end),
    case RV of
        {ok, _} ->
            ok;
        Other ->
            Other
    end.

update_maps(Buckets, OnMap, ExtraSets) ->
    update_maps(chronicle_compat:backend(), Buckets, OnMap, ExtraSets).

update_maps(ns_config, Buckets, OnMap, ExtraSets) ->
    update_many(
      fun (AllBuckets) ->
              {lists:filtermap(
                 fun ({Name, BC}) ->
                         case lists:member(Name, Buckets) of
                             true ->
                                 {true, {Name, misc:key_update(
                                                 map, BC, OnMap(Name, _))}};
                             false ->
                                 false
                         end
                 end, AllBuckets), ExtraSets}
      end);
update_maps(chronicle, Buckets, OnMap, ExtraSets) ->
    Updaters = [{B, OnMap} || B <- Buckets],
    multi_prop_update(map, Updaters, ExtraSets).

multi_prop_update(_Key, []) ->
    ok;
multi_prop_update(Key, Values) ->
    Updaters = [{B, fun (_, _) -> V end} || {B, V} <- Values],
    multi_prop_update(Key, Updaters, []).

multi_prop_update(Key, Updaters, ExtraSets) ->
    {ok, _} =
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
    ok.

update_many(Fun) ->
    RV =
        ns_config:run_txn(
          fun(Config, SetFn) ->
                  Buckets = get_buckets(Config),
                  {ModifiedBuckets, ExtraSets} = Fun(Buckets),
                  NewBuckets = misc:update_proplist(Buckets, ModifiedBuckets),

                  BucketSet = {buckets, [{configs, NewBuckets}]},
                  {commit,
                   functools:chain(
                     Config,
                     [SetFn(K, V, _) || {K, V} <- [BucketSet | ExtraSets]])}
          end),
    case RV of
        {commit, _} ->
            ok;
        Error ->
            Error
    end.

update_buckets(ModifiedBuckets, CurrentBuckets, ExtraSets) ->
    BucketSets =
        case chronicle_compat:backend() of
            ns_config ->
                NewBuckets = misc:update_proplist(CurrentBuckets,
                                                  ModifiedBuckets),
                [{buckets, [{configs, NewBuckets}]}];
            chronicle ->
                [{sub_key(N, props), BC} || {N, BC} <- ModifiedBuckets]
        end,
    chronicle_compat:set_multiple(BucketSets ++ ExtraSets).

is_named_bucket_persistent(BucketName) ->
    {ok, BucketConfig} = get_bucket(BucketName),
    is_persistent(BucketConfig).

is_persistent(BucketConfig) ->
    bucket_type(BucketConfig) =:= membase andalso
        (storage_mode(BucketConfig) =:= couchstore orelse
         storage_mode(BucketConfig) =:= magma).

is_auto_compactable(BucketConfig) ->
    is_persistent(BucketConfig) andalso
    storage_mode(BucketConfig) =/= magma.

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
    ns_config:read_key_fast(vbmap_history_size, get_max_buckets()).

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
    case cluster_compat_mode:is_cluster_elixir() of
        true ->
            {ok, _} =
                chronicle_kv:set(
                  kv, last_balanced_vbmap_key(BucketName), {Map, Options});
        false ->
            update_vbucket_map_history(Map, Options)
    end.

past_vbucket_maps(BucketName) ->
    past_vbucket_maps(BucketName, ns_config:latest()).

past_vbucket_maps(BucketName, Config) ->
    case cluster_compat_mode:is_cluster_elixir() of
        true ->
            case chronicle_kv:get(kv, last_balanced_vbmap_key(BucketName)) of
                {error, not_found} ->
                    get_vbucket_map_history(Config);
                {ok, {MapAndOptions, _Rev}} ->
                    [MapAndOptions]
            end;
        false ->
            get_vbucket_map_history(Config)
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

uuid(BucketConfig) ->
    UUID = proplists:get_value(uuid, BucketConfig),
    true = is_binary(UUID),
    UUID.

uuid_key(Bucket) ->
    sub_key(Bucket, uuid).

uuid(Bucket, direct) ->
    case chronicle_compat:backend() of
        chronicle ->
            case chronicle_compat:get(uuid_key(Bucket), #{}) of
                {ok, UUID} ->
                    UUID;
                {error, not_found} ->
                    not_present
            end;
        ns_config ->
            case get_bucket(Bucket, ns_config:latest()) of
                {ok, Props} ->
                    uuid(Props);
                not_present ->
                    not_present
            end
    end;
uuid(Bucket, Snapshot) when is_map(Snapshot) ->
    case maps:find(uuid_key(Bucket), Snapshot) of
        {ok, {UUID, _}} ->
            UUID;
        error ->
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
    deactivate_bucket_data_on_this_node(chronicle_compat:backend(), Name).

deactivate_bucket_data_on_this_node(chronicle, Name) ->
    case chronicle_kv:update(kv, buckets_with_data_key(node()),
                             lists:keydelete(Name, 1, _)) of
        {error, not_found} ->
            ok;
        {ok, _} ->
            ok
    end;
deactivate_bucket_data_on_this_node(ns_config, Name) ->
    ns_config:update_key(buckets_with_data_key(node()),
                         lists:keydelete(Name, 1, _), []).

upgrade_buckets(Config, Fun) ->
    Buckets = get_buckets(Config),
    NewBuckets = [{Name, Fun(Name, BucketConfig)} ||
                  {Name, BucketConfig} <-Buckets],
    [{set, buckets, [{configs, NewBuckets}]}].

config_upgrade_to_66(Config) ->
    upgrade_buckets(Config,
          fun (_Name, BCfg) ->
                  case bucket_type(BCfg) of
                      membase ->
                          lists:keystore(durability_min_level, 1, BCfg,
                                         {durability_min_level, none});
                      memcached ->
                          BCfg
                  end
          end).

chronicle_upgrade_bucket(Func, BucketNames, ChronicleTxn) ->
    lists:foldl(
      fun (Name, Acc) ->
              Func(Name, Acc)
      end, ChronicleTxn, BucketNames).

chronicle_upgrade_bucket_to_71(BucketName, ChronicleTxn) ->
    PropsKey = sub_key(BucketName, props),
    {ok, BucketConfig} = chronicle_upgrade:get_key(PropsKey, ChronicleTxn),
    NewBucketConfig = lists:keydelete(auth_type, 1, BucketConfig),
    chronicle_upgrade:set_key(PropsKey, NewBucketConfig, ChronicleTxn).

chronicle_upgrade_to_71(ChronicleTxn) ->
    {ok, BucketNames} = chronicle_upgrade:get_key(root(), ChronicleTxn),
    chronicle_upgrade_bucket(chronicle_upgrade_bucket_to_71(_, _),
                             BucketNames, ChronicleTxn).

chronicle_upgrade_bucket_to_elixir(BucketName, ChronicleTxn) ->
    PropsKey = sub_key(BucketName, props),
    AddProps = [{pitr_enabled, false},
                {pitr_granularity, attribute_default(pitr_granularity)},
                {pitr_max_history_age,
                 attribute_default(pitr_max_history_age)}],
    {ok, BucketConfig} = chronicle_upgrade:get_key(PropsKey, ChronicleTxn),
    NewBucketConfig = misc:merge_proplists(fun (_, L, _) -> L end, AddProps,
                                           BucketConfig),
    chronicle_upgrade:set_key(PropsKey, NewBucketConfig, ChronicleTxn).

chronicle_upgrade_to_elixir(ChronicleTxn) ->
    {ok, BucketNames} = chronicle_upgrade:get_key(root(), ChronicleTxn),
    chronicle_upgrade_bucket(chronicle_upgrade_bucket_to_elixir(_, _),
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
    [X || X <-
              [lists:keyfind(Y, 1, Props) ||
                  Y <- [num_replicas, replica_index, ram_quota,
                        durability_min_level, frag_percent,
                        storage_quota_percentage, num_vbuckets,
                        pitr_enabled, pitr_granularity, pitr_max_history_age,
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
                        history_retention_collection_default]],
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

check_test_condition(Step) ->
    case testconditions:get(Step) of
        {delay, MSecs} = Val ->
            ?log_debug("Executing testcondition - ~p", [{Step, Val}]),
            testconditions:delete(Step),
            timer:sleep(MSecs);
        _ ->
            ok
    end.

-spec get_expected_servers([{_,_}]) -> [node()].
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
            {ok, BucketConfig};
        Other ->
            Other
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
-endif.
