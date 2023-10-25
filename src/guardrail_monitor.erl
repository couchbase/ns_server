%% @author Couchbase <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(guardrail_monitor).

-include("ns_common.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("ns_test.hrl").
-endif.

-behaviour(gen_server).

-export([is_enabled/0, get_config/0, get/1, get/2, start_link/0,
         validate_topology_change/2, validate_storage_migration/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).


%% Amount of time to wait between state checks (ms)
-define(CHECK_INTERVAL, ?get_param(check_interval, 20000)).

-define(SERVER, ?MODULE).

-record(state, {
                statuses = [] :: [{resource(), status()}],
                timer_ref = undefined :: undefined | reference()
               }).

-type resource() :: {bucket, bucket_name()}.
-export_type([resource/0]).
-type status() :: ok | data_ingress_status().
-export_type([status/0]).

-spec is_enabled() -> boolean().
is_enabled() ->
    cluster_compat_mode:is_cluster_trinity() andalso
        config_profile:get_bool({resource_management, enabled}).


-spec get_config() -> proplists:proplist().
get_config() ->
    ns_config:read_key_fast(resource_management, []).

-spec get(cores_per_bucket | collections_per_quota) -> undefined | number().
get(cores_per_bucket) ->
    case proplists:get_value(cores_per_bucket, get_config()) of
        undefined -> undefined;
        Config ->
            case proplists:get_value(enabled, Config) of
                true -> proplists:get_value(minimum, Config);
                false -> undefined
            end
    end;
get(collections_per_quota) ->
    case proplists:get_value(collections_per_quota, get_config()) of
        undefined -> undefined;
        Config ->
            case proplists:get_value(enabled, Config) of
                true -> proplists:get_value(maximum, Config);
                false -> undefined
            end
    end.

get(bucket, Key) ->
    case proplists:get_value(bucket, get_config()) of
        undefined ->
            undefined;
        BucketConfig ->
            case proplists:get_value(Key, BucketConfig) of
                undefined ->
                    undefined;
                ResourceConfig ->
                    case proplists:get_value(enabled, ResourceConfig) of
                        false ->
                            undefined;
                        true ->
                            ResourceConfig
                    end
            end
    end.

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).


validate_topology_change(EjectedLiveNodes, KeepNodes) ->
    case is_enabled() of
        true ->
            KeepKVNodes = ns_cluster_membership:service_nodes(KeepNodes, kv),
            case validate_topology_change_data_grs(EjectedLiveNodes,
                                                   KeepKVNodes) of
                ok ->
                    ActiveKVNodes =
                        ns_cluster_membership:service_active_nodes(kv),
                    NewKVNodes = KeepKVNodes -- ActiveKVNodes,
                    validate_topology_change_cores_per_bucket(NewKVNodes);
                Err ->
                    Err
            end;
        false ->
            ok
    end.

validate_topology_change_data_grs(EjectedNodes, KeepKVNodes) ->
    case EjectedNodes of
        [] -> ok;
        _ ->
            lists:foldl(
                fun (Resource, ok) ->
                    validate_topology_change_data_gr(Resource, EjectedNodes,
                                                     KeepKVNodes);
                    (_, Err) ->
                        Err
                end, ok, [data_size, resident_ratio])
    end.

topology_change_error({data_size, Buckets}) ->
    {data_size_will_be_too_high,
     iolist_to_binary(
       io_lib:format(
         "The following buckets are expected to "
         "breach the maximum data size per node: ~s",
         [lists:join(", ", Buckets)]))};
topology_change_error({resident_ratio, Buckets}) ->
    {rr_will_be_too_low,
     iolist_to_binary(
       io_lib:format(
         "The following buckets are expected to "
         "breach the resident ratio minimum: ~s",
         [lists:join(", ", Buckets)]))};
topology_change_error({cores_per_bucket, Nodes}) ->
    {not_enough_cores_for_num_buckets,
     iolist_to_binary(
       io_lib:format(
         "The following node(s) being added have insufficient cpu cores for "
         "the number of buckets already in the cluster: ~s",
         [lists:join(", ", lists:map(atom_to_list(_), Nodes))]))}.

validate_topology_change_data_gr(Resource, EjectedNodes, KeepKVNodes) ->
    case get(bucket, Resource) of
        undefined ->
            ok;
        ResourceConfig ->
            BucketDataSizes =
                stats_interface:total_active_logical_data_size(
                  EjectedNodes ++ KeepKVNodes),
            BadBuckets =
                maps:keys(
                  maps:filter(
                    fun (_Name, 0) ->
                            false;
                        (Name, TotalDataSize) ->
                            validate_bucket_topology_change(
                              Resource, Name, KeepKVNodes, TotalDataSize,
                              ResourceConfig)
                    end, BucketDataSizes)),
            case BadBuckets of
                [] ->
                    %% No bucket is anticipated to violate this guardrail
                    ok;
                _ ->
                    %% Guardrail violation expected for each of BadBuckets
                    {error, topology_change_error({Resource, BadBuckets})}

            end
    end.

validate_bucket_topology_change(Resource, Name, KeepKVNodes, TotalDataSize,
                                ResourceConfig) ->
    case ns_bucket:get_bucket(Name) of
        not_present ->
            false;
        {ok, BCfg} ->
            NumNodes = case ns_bucket:get_width(BCfg) of
                           undefined -> length(KeepKVNodes);
                           W -> W * ns_cluster_membership:server_groups()
                       end,
            validate_bucket_topology_change(
                Resource, KeepKVNodes, TotalDataSize, ResourceConfig, BCfg,
                NumNodes)
    end.

validate_bucket_topology_change(data_size, KeepKVNodes, TotalDataSize,
                                          ResourceConfig, BCfg, NumNodes) ->
    ExpDataSizePerNode = TotalDataSize / (NumNodes * math:pow(10, 12)),
    DataSizeLimit = get_data_size_maximum_on_nodes(
                      ResourceConfig, BCfg, KeepKVNodes),
    validate_bucket_resource_max(ExpDataSizePerNode, DataSizeLimit);
validate_bucket_topology_change(resident_ratio, KeepKVNodes, TotalDataSize,
                                               ResourceConfig, BCfg,
                                               NumNodes) ->
    Quota = ns_bucket:raw_ram_quota(BCfg),
    ExpResidentRatio = 100 * NumNodes * Quota / TotalDataSize,
    ResidentRatioLimit = get_resident_ratio_minimum_on_nodes(
                           ResourceConfig, BCfg, KeepKVNodes),
    validate_bucket_resource_min(ExpResidentRatio, ResidentRatioLimit).

validate_topology_change_cores_per_bucket(NewKVNodes) ->
    case guardrail_monitor:get(cores_per_bucket) of
        undefined ->
            ok;
        MinCoresPerBucket ->
            NumBuckets = length(ns_bucket:get_bucket_names()),
            MinCores = MinCoresPerBucket * NumBuckets,
            BadNodes =
                lists:filter(
                  fun (Node) ->
                          Props = ns_doctor:get_node(Node),
                          case proplists:get_value(cpu_count, Props) of
                              undefined ->
                                  false;
                              Cores when is_number(Cores) ->
                                  Cores < MinCores;
                              Other ->
                                  ?log_error(
                                     "Unable to check if node ~p has "
                                     "sufficient cores, as its cpu_count is "
                                     "not a number (~p). Will reject the "
                                     "rebalance just in case", [Node, Other]),
                                  true
                          end
                  end, NewKVNodes),
            case BadNodes of
                [] ->
                    ok;
                _ ->
                    {error, topology_change_error({cores_per_bucket, BadNodes})}
            end
    end.

-spec validate_storage_migration(bucket_name(), proplists:proplist(), atom()) ->
          ok | {error, data_size | resident_ratio, number()}.
validate_storage_migration(BucketName, BucketConfig, NewStorageMode) ->
    KvNodes = ns_bucket:get_servers(BucketConfig),
    Stats = stats_interface:for_storage_mode_migration(BucketName, KvNodes),
    case validate_storage_migration_data_size(Stats, NewStorageMode) of
        ok ->
            case validate_storage_migration_resident_ratio(Stats,
                                                           NewStorageMode) of
                ok ->
                    ok;
                {error, Limit} ->
                    {error, resident_ratio, Limit}
            end;
        {error, Limit} ->
            {error, data_size, Limit}
    end.

validate_storage_migration_data_size(Stats, StorageMode) ->
    case get(bucket, data_size) of
        undefined ->
            ok;
        ResourceConfig ->
            case maps:get(data_size, Stats, undefined) of
                undefined ->
                    ok;
                DataSize ->
                    Limit = get_data_size_maximum(ResourceConfig, StorageMode,
                                                  true),
                    case validate_bucket_resource_max(DataSize, Limit) of
                        false ->
                            ok;
                        true ->
                            {error, Limit}
                    end
            end
    end.

validate_storage_migration_resident_ratio(Stats, StorageMode) ->
    case get(bucket, resident_ratio) of
        undefined ->
            ok;
        ResourceConfig ->
            case maps:get(resident_ratio, Stats, undefined) of
                undefined ->
                    ok;
                ResidentRatio ->
                    Minimum = get_resident_ratio_minimum(ResourceConfig,
                                                         StorageMode, true),
                    case validate_bucket_resource_min(ResidentRatio, Minimum) of
                        false ->
                            ok;
                        true ->
                            {error, Minimum}
                    end
            end
    end.

%%%===================================================================
%%% Spawning and gen_server implementation
%%%===================================================================


init([]) ->
    self() ! check,
    {ok, #state{}}.

handle_call(_, _From, #state{} = State) ->
    {reply, ok, State}.

handle_cast(_, State) ->
    {noreply, State}.

handle_info(check, #state{statuses = OldStatuses} = State) ->
    %% Remind myself to check resource statuses again, after the check interval
    State1 = restart_timer(State),
    State2 =
        case is_enabled() of
            true ->
                NewStatuses = check_resources(),
                case OldStatuses == NewStatuses of
                    true ->
                        State1;
                    false ->
                        ?log_info("Resource statuses changed from ~p to ~p",
                                  [OldStatuses, NewStatuses]),
                        ns_config:set({node, node(), resource_statuses},
                                      NewStatuses),
                        State1#state{statuses = NewStatuses}
                end;
            false ->
                State1
        end,
    {noreply, State2};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% We need to make sure there is only one timer at any given moment, otherwise
%% the system would be fragile to future changes or diag/evals
restart_timer(#state{timer_ref = Ref} = State) when is_reference(Ref) ->
    erlang:cancel_timer(Ref),
    restart_timer(State#state{timer_ref = undefined});
restart_timer(#state{timer_ref = undefined} = State) ->
    State#state{timer_ref = erlang:send_after(?CHECK_INTERVAL, self(), check)}.


%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Checks all enabled resources and returns the status map
-spec check_resources() -> [{resource(), status()}].
check_resources() ->
    Config = get_config(),
    Stats = stats_interface:for_resource_management(),
    lists:flatmap(check(_, Stats), Config).

%% Checks if a resource threshold has been met, returning all the statuses for
%% that resource (for instance the status for each bucket)
check({bucket, Config}, Stats) ->
    lists:flatten(
      lists:map(
        fun ({BucketName, BucketConfig}) ->
                case proplists:get_value({bucket, BucketName}, Stats) of
                    undefined ->
                        [];
                    BucketStats ->
                        check_bucket(Config, BucketName, BucketConfig,
                                     BucketStats)
                end
        end, ns_bucket:get_buckets()));
check({disk_usage = Resource, Config}, Stats) ->
    case proplists:get_value(enabled, Config) of
        false ->
            [];
        true ->
            Metric = get_disk_usage(proplists:get_value(disk_usage, Stats, [])),
            Maximum = proplists:get_value(maximum, Config),
            {Gauge, Statuses} =
                case Metric > Maximum of
                    true ->
                        %% For now if we see disk usage reach the limit we apply
                        %% the guard for all buckets. In future we should allow
                        %% this to apply on a per-service and per-bucket level,
                        %% when these are mapped to different disk partitions
                        {1, [{{bucket, BucketName}, disk_usage}
                             || BucketName <- ns_bucket:get_bucket_names()]};
                    false ->
                        {0, []}
                end,
            ns_server_stats:notify_gauge(
              {<<"resource_limit_reached">>,
               [{resource, Resource}]},
              Gauge),
            Statuses
    end;
check({_Resource, _Config}, _Stats) ->
    %% Other resources do not need regular checks
    [].

check_bucket(Config, BucketName, BucketConfig, BucketStats) ->
    Results =
        lists:filtermap(
          fun (Resource) ->
                  ResourceConfig = proplists:get_value(Resource, Config),
                  Result =
                      case proplists:get_value(enabled, ResourceConfig) of
                          true ->
                              check_bucket_guard_rail(Resource, ResourceConfig,
                                                      BucketConfig,
                                                      BucketStats);
                          false ->
                              false
                      end,
                  NotifyStat = ns_server_stats:notify_gauge(
                                 {<<"resource_limit_reached">>,
                                  [{resource, Resource},
                                   {bucket, BucketName}]}, _),
                  case Result of
                      true ->
                          NotifyStat(1),
                          {true, Resource};
                      false ->
                          NotifyStat(0),
                          false
                  end
          end, proplists:get_keys(Config)),
    [{{bucket, BucketName}, Result} || Result <- Results].

check_bucket_guard_rail(Resource, ResourceConfig, BucketConfig, BucketStats) ->
    case proplists:get_value(Resource, BucketStats) of
        undefined ->
            false;
        Metric ->
            case Resource of
                resident_ratio ->
                    Limit = get_resident_ratio_minimum(ResourceConfig,
                                                       BucketConfig),
                    validate_bucket_resource_min(Metric, Limit);
                data_size ->
                    Limit = get_data_size_maximum(ResourceConfig, BucketConfig),
                    validate_bucket_resource_max(Metric, Limit)
            end
    end.

validate_bucket_resource_min(Metric, Limit) ->
    case Metric of
        %% Ignore infinity/neg_infinity as these are not meaningful here
        infinity ->
            false;
        neg_infinity ->
            false;
        Value ->
            Value < Limit
    end.

validate_bucket_resource_max(Metric, Limit) ->
    case Metric of
        %% Ignore infinity/neg_infinity as these are not meaningful here
        infinity ->
            false;
        neg_infinity ->
            false;
        Value ->
            %% Inclusive inequality so that when limit is 0 and value is 0, the
            %% guard rail still fires, which is useful for testing, and doesn't
            %% impact real world behaviour in a noticeable manner
            Value >= Limit
    end.

get_resident_ratio_minimum(ResourceConfig, BucketConfig) ->
    get_resident_ratio_minimum(
        ResourceConfig, ns_bucket:storage_mode(BucketConfig),
        ns_bucket:storage_mode_migration_in_progress(BucketConfig)).

get_resident_ratio_minimum(ResourceConfig, StorageMode, Migration) ->
    CouchstoreLimit = proplists:get_value(couchstore_minimum, ResourceConfig),
    MagmaLimit = proplists:get_value(magma_minimum, ResourceConfig),
    case {StorageMode, Migration} of
        {couchstore, false} ->
            CouchstoreLimit;
        {magma, false} ->
            MagmaLimit;
        {_, false} ->
            %% For memcached and ephemeral buckets, there is no limit
            -1;
        _ ->
            %% Always use the most restrictive storage mode if storage mode
            %% migration is in progress
            max(CouchstoreLimit, MagmaLimit)
    end.

get_resident_ratio_minimum_on_nodes(ResourceConfig, BucketConfig, Nodes) ->
    CouchstoreLimit = proplists:get_value(couchstore_minimum, ResourceConfig),
    MagmaLimit = proplists:get_value(magma_minimum, ResourceConfig),
    %% Use the most restrictive limit, only considering specific nodes
    case get_limits_from_node_storage_modes(BucketConfig, CouchstoreLimit,
                                            MagmaLimit, Nodes) of
        [] -> -1;
        Limits -> lists:max(Limits)
    end.

get_limits_from_node_storage_modes(BucketConfig, CouchstoreLimit, MagmaLimit,
                                   Nodes) ->
    lists:filtermap(
      fun (Node) ->
              case ns_bucket:node_storage_mode(Node, BucketConfig) of
                  couchstore -> {true, CouchstoreLimit};
                  magma -> {true, MagmaLimit};
                  %% memcached and ephemeral buckets are not considered
                  _ -> false
              end
      end, Nodes).

get_data_size_maximum(ResourceConfig, BucketConfig) ->
    get_data_size_maximum(
        ResourceConfig, ns_bucket:storage_mode(BucketConfig),
        ns_bucket:storage_mode_migration_in_progress(BucketConfig)).

get_data_size_maximum(ResourceConfig, StorageMode, Migration) ->
    CouchstoreLimit = proplists:get_value(couchstore_maximum, ResourceConfig),
    MagmaLimit = proplists:get_value(magma_maximum, ResourceConfig),
    case {StorageMode, Migration} of
        {couchstore, false} ->
            CouchstoreLimit;
        {magma, false} ->
            MagmaLimit;
        {_, false} ->
            %% For memcached and ephemeral buckets, there is no limit
            infinity;
        _ ->
            %% Always use the most restrictive storage mode if storage mode
            %% migration is in progress
            min(CouchstoreLimit, MagmaLimit)
    end.

get_data_size_maximum_on_nodes(ResourceConfig, BucketConfig, Nodes) ->
    CouchstoreLimit = proplists:get_value(couchstore_maximum, ResourceConfig),
    MagmaLimit = proplists:get_value(magma_maximum, ResourceConfig),
    %% Use the most restrictive limit, only considering specific nodes
    case get_limits_from_node_storage_modes(BucketConfig, CouchstoreLimit,
                                            MagmaLimit, Nodes) of
        [] -> infinity;
        Limits -> lists:min(Limits)
    end.

get_disk_usage(DiskStats) ->
    Mounts = lists:filtermap(
               fun({Disk, Value}) ->
                       {true, {Disk, ignore, Value}};
                  (_) ->
                       false
               end, DiskStats),
    case ns_storage_conf:this_node_dbdir() of
        {ok, DbDir} ->
            case misc:realpath(DbDir, "/") of
                {ok, RealFile} ->
                    case ns_storage_conf:extract_disk_stats_for_path(
                           Mounts, RealFile) of
                        {ok, {_Disk, _Cap, Used}} -> Used;
                        none -> 0
                    end;
                _ ->
                    0
            end;
        {error, not_found} ->
            ?log_warning("Couldn't check disk usage as node db dir is missing"),
            0
    end.

-ifdef(TEST).
modules() ->
    [ns_config, leader_registry, chronicle_compat, stats_interface,
     janitor_agent, ns_bucket, cluster_compat_mode, config_profile,
     ns_cluster_membership, ns_storage_conf, ns_doctor].

basic_test_setup() ->
    meck:new(modules(), [passthrough]).

basic_test_teardown() ->
    meck:unload(modules()).

check_bucket_t() ->
    %% Resource level check
    RRConfig = [{enabled, true},
                {couchstore_minimum, 10},
                {magma_minimum, 1}],
    CouchstoreBucket = [{type, membase},
                        {storage_mode, couchstore}],

    %% RR% above minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreBucket,
                   [{resident_ratio, 15}])),

    %% RR% at minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreBucket,
                   [{resident_ratio, 10}])),

    %% RR% below minimum
    ?assertEqual(true,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreBucket,
                   [{resident_ratio, 5}])),

    DataSizeConfig = [{enabled, true},
                      {couchstore_maximum, 1.6},
                      {magma_maximum, 16}],

    %% Data size below maximum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   data_size, DataSizeConfig, CouchstoreBucket,
                   [{data_size, 1}])),

    %% Data size above maximum
    ?assertEqual(true,
                 check_bucket_guard_rail(
                   data_size, DataSizeConfig, CouchstoreBucket,
                   [{data_size, 2}])),

    MagmaBucket = [{type, membase},
                   {storage_mode, magma}],

    %% Bucket level check

    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"couchstore", CouchstoreBucket},
                         {"magma", MagmaBucket}]
                end),
    Config = [{resident_ratio, RRConfig},
              {data_size, DataSizeConfig}],


    %% RR% above couchstore minimum
    ?assertEqual(
       [],
       check_bucket(Config, "couchstore", CouchstoreBucket,
                    [{resident_ratio, 15}])),
    %% RR% below couchstore minimum
    ?assertEqual(
       [{{bucket, "couchstore"}, resident_ratio}],
       check_bucket(Config, "couchstore", CouchstoreBucket,
                    [{resident_ratio, 5}])),

    %% RR% above magma minimum
    ?assertEqual(
       [],
       check_bucket(Config, "magma", MagmaBucket,
                    [{resident_ratio, 2}])),
    %% RR% below magma minimum
    ?assertEqual(
       [{{bucket, "magma"}, resident_ratio}],
       check_bucket(Config, "magma", MagmaBucket,
                    [{resident_ratio, 0.5}])),

    %% Data size below couchstore maximum
    ?assertEqual(
       [],
       check_bucket(Config, "couchstore", CouchstoreBucket,
                    [{data_size, 1}])),
    %% Data size above couchstore maximum
    ?assertEqual(
       [{{bucket, "couchstore"}, data_size}],
       check_bucket(Config, "couchstore", CouchstoreBucket,
                    [{data_size, 5}])),

    %% Data size below magma maximum
    ?assertEqual(
       [],
       check_bucket(Config, "magma", MagmaBucket,
                    [{data_size, 5}])),
    %% Data size above magma maximum
    ?assertEqual(
       [{{bucket, "magma"}, data_size}],
       check_bucket(Config, "magma", MagmaBucket,
                    [{data_size, 20}])),

    %% Service level check

    %% RR% above couchstore minimum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{{bucket, "couchstore"}, [{resident_ratio, 15}]}])),
    %% RR% below couchstore minimum
    ?assertListsEqual(
       [{{bucket, "couchstore"}, resident_ratio}],
       check({bucket, Config}, [{{bucket, "couchstore"}, [{resident_ratio, 5}]}])),

    %% RR% above magma minimum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{{bucket, "magma"}, [{resident_ratio, 2}]}])),
    %% RR% below magma minimum
    ?assertListsEqual(
       [{{bucket, "magma"}, resident_ratio}],
       check({bucket, Config}, [{{bucket, "magma"}, [{resident_ratio, 0.5}]}])),

    %% Data size below couchstore maximum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{{bucket, "couchstore"}, [{data_size, 1}]}])),
    %% Data size above couchstore maximum
    ?assertListsEqual(
       [{{bucket, "couchstore"}, data_size}],
       check({bucket, Config}, [{{bucket, "couchstore"}, [{data_size, 5}]}])),

    %% Data size below magma maximum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{{bucket, "magma"}, [{data_size, 5}]}])),
    %% Data size above magma maximum
    ?assertListsEqual(
       [{{bucket, "magma"}, data_size}],
       check({bucket, Config}, [{{bucket, "magma"}, [{data_size, 20}]}])),
    ok.

check_bucket_during_storage_migration_t() ->
    RRConfig = [{enabled, true},
                {couchstore_minimum, 10},
                {magma_minimum, 1}],
    CouchstoreToMagmaBucket = [{type, membase},
                               {storage_mode, magma},
                               %% Migration from couchstore in progress
                               {{node, node1, storage_mode}, couchstore}],

    %% Bucket being migrated from couchstore to magma should continue to be
    %% treated as a couchstore bucket during migration

    %% RR% above minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreToMagmaBucket,
                   [{resident_ratio, 15}])),

    %% RR% at minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreToMagmaBucket,
                   [{resident_ratio, 10}])),

    %% RR% below minimum
    ?assertEqual(true,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, CouchstoreToMagmaBucket,
                   [{resident_ratio, 5}])),

    DataSizeConfig = [{enabled, true},
                      {couchstore_maximum, 1.6},
                      {magma_maximum, 16}],

    %% Data size below maximum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   data_size, DataSizeConfig, CouchstoreToMagmaBucket,
                   [{data_size, 1}])),

    %% Data size above maximum
    ?assertEqual(true,
                 check_bucket_guard_rail(
                   data_size, DataSizeConfig, CouchstoreToMagmaBucket,
                   [{data_size, 2}])),

    MagmaToCouchstoreBucket = [{type, membase},
                               {storage_mode, couchstore},
                               %% Migration from magma in progress
                               {{node, node1, storage_mode}, magma}],

    %% Bucket being migrated from magma to couchstore should immediately be
    %% treated the same as a couchstore bucket

    %% RR% above minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, MagmaToCouchstoreBucket,
                   [{resident_ratio, 15}])),

    %% RR% at minimum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, MagmaToCouchstoreBucket,
                   [{resident_ratio, 10}])),

    %% RR% below minimum
    ?assertEqual(true,
                 check_bucket_guard_rail(
                   resident_ratio, RRConfig, MagmaToCouchstoreBucket,
                   [{resident_ratio, 5}])),

    %% Data size below maximum
    ?assertEqual(false,
                 check_bucket_guard_rail(
                   data_size, DataSizeConfig, MagmaToCouchstoreBucket,
                   [{data_size, 1}])),

    %% Data size above maximum
    ?assertEqual(true,
                 check_bucket_guard_rail(
                   data_size, DataSizeConfig, MagmaToCouchstoreBucket,
                   [{data_size, 2}])),
                   ok.

dont_check_memcached_or_ephemeral_t() ->
    MemcachedBucket = [{type, memcached},
                       {storage_mode, undefined}],

    EphemeralBucket = [{type, membase},
                       {storage_mode, ephemeral}],

    %% Bucket level check

    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"memcached", MemcachedBucket},
                         {"ephemeral", EphemeralBucket}]
                end),
    RRConfig = [{enabled, true},
                {couchstore_minimum, 10},
                {magma_minimum, 1}],
    DataSizeConfig = [{enabled, true},
                      {couchstore_maximum, 1.6},
                      {magma_maximum, 16}],
    Config = [{resident_ratio, RRConfig},
              {data_size, DataSizeConfig}],


    %% Low memcached RR% (should be impossible, but make sure this isn't checked
    %% anyway
    ?assertEqual(
       [],
       check_bucket(Config, "memcached", MemcachedBucket,
                    [{resident_ratio, 0}])),

    %% Low ephemeral RR% (should be impossible, but make sure this isn't checked
    %% anyway
    ?assertEqual(
       [],
       check_bucket(Config, "ephemeral", MemcachedBucket,
                    [{resident_ratio, 0}])),

    %% High memcached data size
    ?assertEqual(
       [],
       check_bucket(Config, "memcached", MemcachedBucket,
                    [{data_size, 100}])),

    %% High ephemeral data size
    ?assertEqual(
       [],
       check_bucket(Config, "ephemeral", MemcachedBucket,
                    [{data_size, 100}])),

    %% Topology check setup

    Servers = [node1, node2],
    DesiredServers = [{"memcached", Servers},
                      {"ephemeral", Servers}],
    meck:expect(ns_bucket, get_bucket,
                fun ("memcached") ->
                        {ok, [{ram_quota, 10} | MemcachedBucket]};
                    ("ephemeral") ->
                        {ok, [{ram_quota, 10} | EphemeralBucket]};
                    (_) ->
                        not_present
                end),

    %% Check topology change doesn't care about memcached
    ?assertEqual(false,
                 validate_bucket_topology_change(
                     resident_ratio, "memcached", DesiredServers, 1000,
                     RRConfig)),

    %% Check topology change doesn't care about ephemeral
    ?assertEqual(false,
                 validate_bucket_topology_change(
                     resident_ratio, "ephemeral", DesiredServers, 1000,
                     RRConfig)),
    ok.

check_resources_t() ->
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio,
                            [{enabled, false},
                             {couchstore_minimum, 10},
                             {magma_minimum, 1}]}]}]
                end),
    CouchstoreBucket = [{type, membase},
                        {storage_mode, couchstore}],
    MagmaBucket = [{type, membase},
                   {storage_mode, magma}],
    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"couchstore_bucket", CouchstoreBucket},
                         {"magma_bucket", MagmaBucket}]
                end),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        []
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"}, []}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 11}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 2}]}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 9},
                           {data_size, 2}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 0.5},
                           {data_size, 20}]}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio,
                            [{enabled, true},
                             {couchstore_minimum, 10},
                             {magma_minimum, 1}]},
                           {data_size,
                            [{enabled, true},
                             {couchstore_maximum, 1.6},
                             {magma_maximum, 16}]}]}]
                end),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 9}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 2}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 11}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 0.5}]}]
                end),
    ?assertEqual([{{bucket, "magma_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 9}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 0.5}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, resident_ratio},
                  {{bucket, "magma_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{data_size, 2}]},
                         {{bucket, "magma_bucket"},
                          [{data_size, 20}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, data_size},
                  {{bucket, "magma_bucket"}, data_size}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 11},
                           {data_size, 2}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 2},
                           {data_size, 20}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, data_size},
                  {{bucket, "magma_bucket"}, data_size}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 9},
                           {data_size, 2}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 0.5},
                           {data_size, 20}]}]
                end),
    ?assertListsEqual([{{bucket, "couchstore_bucket"}, resident_ratio},
                       {{bucket, "couchstore_bucket"}, data_size},
                       {{bucket, "magma_bucket"}, resident_ratio},
                       {{bucket, "magma_bucket"}, data_size}],
                      check_resources()),

    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{disk_usage,
                          [{enabled, true},
                           {maximum, 85}]}]
                end),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{disk_usage, [{"/", 50}]}]
                end),

    meck:expect(ns_storage_conf, this_node_dbdir,
                fun () -> {ok, "invalid_file"} end),

    meck:expect(ns_storage_conf, extract_disk_stats_for_path,
                fun (_, _) -> none end),

    meck:expect(ns_bucket, get_bucket_names,
                fun () -> ["couchstore_bucket", "magma_bucket"] end),

    ?assertEqual([], check_resources()),

    meck:expect(ns_storage_conf, this_node_dbdir,
                fun () -> {ok, ""} end),

    ?assertEqual([], check_resources()),

    meck:expect(ns_storage_conf, extract_disk_stats_for_path,
                fun ([{"/", ignore, Value}], _) -> {ok, {0, 0, Value}} end),

    ?assertEqual([], check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{disk_usage, [{"/", 90}]}]
                end),

    ?assertEqual([{{bucket, "couchstore_bucket"}, disk_usage},
                  {{bucket, "magma_bucket"}, disk_usage}],
                 check_resources()).

validate_bucket_topology_change_t() ->
    meck:expect(cluster_compat_mode, is_cluster_trinity, ?cut(true)),
    meck:expect(config_profile, get_bool,
                fun ({resource_management, enabled}) -> true end),

    Servers = [node1, node2],
    RRConfig = [{couchstore_minimum, 10},
                {magma_minimum, 1}],
    meck:expect(ns_bucket, get_bucket,
                fun ("couchstore_bucket") ->
                        {ok, [{ram_quota, 10},
                              {type, membase},
                              {storage_mode, couchstore}]};
                    ("magma_bucket") ->
                        {ok, [{ram_quota, 10},
                              {type, membase},
                              {storage_mode, magma}]};
                    (_) ->
                        not_present
                end),

    meck:expect(ns_cluster_membership, service_active_nodes,
                fun (kv) -> Servers end),

    %% Resident ratio will end up just below the couchstore minimum
    ?assertEqual(true,
                 validate_bucket_topology_change(
                   resident_ratio,
                   "couchstore_bucket",
                   Servers,
                   201,  %% Bytes
                   RRConfig)),

    %% Resident ratio will end up just below the magma minimum
    ?assertEqual(true,
                 validate_bucket_topology_change(
                   resident_ratio,
                   "magma_bucket",
                   Servers,
                   2001,  %% Bytes
                   RRConfig)),

    %% Resident ratio will end up exactly at the couchstore minimum
    ?assertEqual(false,
                 validate_bucket_topology_change(
                   resident_ratio,
                   "couchstore_bucket",
                   Servers,
                   200,  %% Bytes
                   RRConfig)),

    %% Resident ratio will end up exactly at the magma minimum
    ?assertEqual(false,
                 validate_bucket_topology_change(
                   resident_ratio,
                   "magma_bucket",
                   Servers,
                   2000,  %% Bytes
                   RRConfig)),

    DataSizeConfig = [{couchstore_maximum, 0.000000001},  %% 1,000 Bytes
                      {magma_maximum,      0.00000001}],  %% 10,000 Bytes
    ?assertEqual(true,
                 validate_bucket_topology_change(
                   data_size,
                   "couchstore_bucket",
                   Servers,
                   2000,  %% Bytes
                   DataSizeConfig)),

    ?assertEqual(true,
                 validate_bucket_topology_change(
                   data_size,
                   "magma_bucket",
                   Servers,
                   20000,  %% Bytes
                   DataSizeConfig)),

    ?assertEqual(true,
                 validate_bucket_topology_change(
                   data_size,
                   "couchstore_bucket", [node3 | Servers],
                   3000,  %% Bytes
                   DataSizeConfig)),

    ?assertEqual(false,
                 validate_bucket_topology_change(
                   data_size,
                   "couchstore_bucket", Servers,
                   1999,  %% Bytes
                   DataSizeConfig)),

    ?assertEqual(false,
                 validate_bucket_topology_change(
                   data_size,
                   "magma_bucket", Servers,
                   19999,  %% Bytes
                   DataSizeConfig)),

    ?assertEqual(false,
                 validate_bucket_topology_change(
                   data_size,
                   "couchstore_bucket", [node3 | Servers],
                   2999,  %% Bytes
                   DataSizeConfig)).

test_validate_topology_change(ActiveKVNodes, KeepKVNodes) ->
    meck:expect(ns_cluster_membership, service_nodes,
                fun (_Servers, kv) -> KeepKVNodes end),
    meck:expect(ns_cluster_membership, service_active_nodes,
                fun (kv) -> ActiveKVNodes end),
    validate_topology_change(ActiveKVNodes -- KeepKVNodes, KeepKVNodes).

validate_topology_change_data_grs_t() ->
    ResourceConfig0 = [{couchstore_minimum, 10},
                       {magma_minimum, 1}],

    ResourceConfig1 = [{enabled, false} | ResourceConfig0],
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio, ResourceConfig1}]}]
                end),
    %% 3 buckets, each with a quota of 10 bytes
    meck:expect(ns_bucket, get_bucket,
                fun ("couchstore_bucket") ->
                        {ok, [{ram_quota, 10},
                              {type, membase},
                              {storage_mode, couchstore}]};
                    ("magma_bucket") ->
                        {ok, [{ram_quota, 10},
                              {type, membase},
                              {storage_mode, magma}]};
                    ("new") ->
                        {ok, [{ram_quota, 10},
                              {type, membase},
                              {storage_mode, couchstore}]};
                    (_) ->
                        not_present
                end),
    %% For 3 nodes, with a total of 200/2000 bytes of data for couchstore and
    %% magma respectively, giving a RR% of 15/1.5% respectively, then to remove
    %% a node would give a RR% of 10/1%. Taking data size slightly larger than
    %% that, 201/2001, ensures that a rebalance from 3 to 2 nodes should only
    %% just violate the guardrail
    meck:expect(stats_interface, total_active_logical_data_size,
                fun (_) -> #{"couchstore_bucket" => 201,
                             "magma_bucket" => 2001} end),

    %% Don't give an error ejecting a node when the guard rail is disabled
    ?assertEqual(ok, test_validate_topology_change([node1, node2, node3],
                                                   [node1, node2])),

    ResourceConfig2 = [{enabled, true} | ResourceConfig0],
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio, ResourceConfig2}]}]
                end),

    %% Error when just ejecting a live node
    ?assertMatch({error,
                  {rr_will_be_too_low,
                   <<"The following buckets are expected to breach the "
                     "resident ratio minimum: couchstore_bucket, "
                     "magma_bucket">>}},
                 test_validate_topology_change([node1, node2, node3],
                                               [node1, node2])),

    %% Don't give an error when no nodes are being ejected
    ?assertEqual(ok, test_validate_topology_change([node1, node2],
                                                   [node1, node2])),

    %% Don't give an error when a node is being added
    ?assertEqual(ok, test_validate_topology_change([node1],
                                                   [node1, node2])),

    %% Error for ejecting a node while adding another

    ?assertMatch({error,
                  {rr_will_be_too_low,
                   <<"The following buckets are expected to breach the "
                     "resident ratio minimum: couchstore_bucket, "
                     "magma_bucket">>}},
                 test_validate_topology_change([node1, node2],
                                               [node1, node3])),

    %% For 3 nodes, with a total of 200/2000 bytes of data for couchstore and
    %% magma respectively, giving a RR% of 15/1.5% respectively, so to remove a
    %% node would just remain within the limits (10/1%)
    meck:expect(stats_interface, total_active_logical_data_size,
                fun (_) -> #{"couchstore_bucket" => 200,
                             "magma_bucket" => 2000,
                             %% Ignored as size is 0
                             "new" => 0,
                             %% Ignored as the bucket name is not found with
                             %% ns_bucket:get_bucket/1
                             "deleted2" => 4000} end),

    %% Don't give an error when ejecting a node if the resident ratio is not too
    %% low
    ?assertMatch(ok,
                 test_validate_topology_change([node1, node2, node3],
                                               [node1, node2])),
    ok.

pretend_cpu_count(Node, Count) ->
    meck:expect(ns_doctor, get_node,
        fun(N) when N =:= Node -> [{cpu_count, Count}] end).

validate_topology_change_cores_per_bucket_t() ->
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{cores_per_bucket,
                          [{enabled, true},
                           {minimum, 0.5}]}]
                end),
    meck:expect(ns_bucket, get_bucket_names,
                fun () -> ["bucket1", "bucket2"] end),
    %% For 2 buckets and 0.5 cores per bucket, the minimum will be 1

    %% Core count at minimum
    pretend_cpu_count(node1, 1),
    ?assertEqual(ok,
                 test_validate_topology_change([node1], [node1])),
    ?assertEqual(ok,
                 test_validate_topology_change([], [node1])),
    ?assertEqual(ok,
                 test_validate_topology_change([node1], [])),

    %% Core count below minimum
    pretend_cpu_count(node2, 0.9),
    ?assertEqual(ok,
                 test_validate_topology_change([node2], [])),
    ?assertMatch({error,
                  {not_enough_cores_for_num_buckets, _}},
                 test_validate_topology_change([], [node2])),
    ?assertMatch({error,
                  {not_enough_cores_for_num_buckets, _}},
                 test_validate_topology_change([node1], [node1, node2])),
    ?assertEqual(ok,
                 test_validate_topology_change([node1, node2], [node1])).

validate_storage_migration_t() ->
    DataSizeConfig0 = [{enabled, true},
                       {couchstore_maximum, 1.6},
                       {magma_maximum, 16}],
    RRConfig0 = [{enabled, true},
                 {couchstore_minimum, 10},
                 {magma_minimum, 1}],
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{data_size, DataSizeConfig0},
                           {resident_ratio, RRConfig0}]}]
                end),
    meck:expect(ns_cluster_membership, service_active_nodes,
                fun (kv) -> [] end),

    %% Test couchstore -> magma
    CouchstoreConfig = [{storage_mode, couchstore}],

    %% Data size and RR% below/above couchstore limit respectively
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{data_size => 1,
                          resident_ratio => 20} end),
    ?assertEqual(ok,
                 validate_storage_migration("", CouchstoreConfig, magma)),

    %% Data size above couchstore limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{data_size => 10} end),
    ?assertEqual({error, data_size, 1.6},
                 validate_storage_migration("", CouchstoreConfig, magma)),

    %% RR% below couchstore limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{resident_ratio => 5} end),
    ?assertEqual({error, resident_ratio, 10},
                 validate_storage_migration("", CouchstoreConfig, magma)),

    %% Data size above magma limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{data_size => 20} end),
    ?assertEqual({error, data_size, 1.6},
                 validate_storage_migration("", CouchstoreConfig, magma)),

    %% RR% below magma limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{resident_ratio => 0.5} end),
    ?assertEqual({error, resident_ratio, 10},
                 validate_storage_migration("", CouchstoreConfig, magma)),

    %% Data size and RR% above/below magma limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{data_size => 20,
                          resident_ratio => 0.5} end),
    ?assertEqual({error, data_size, 1.6},
                 validate_storage_migration("", CouchstoreConfig, magma)),

    %% Test magma -> couchstore
    MagmaConfig = [{storage_mode, magma}],

    %% Data size and RR% below/above couchstore limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{data_size => 1,
                          resident_ratio => 20} end),
    ?assertEqual(ok,
                 validate_storage_migration("", MagmaConfig, couchstore)),

    %% Data size above couchstore limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{data_size => 2} end),
    ?assertEqual({error, data_size, 1.6},
                 validate_storage_migration("", MagmaConfig, couchstore)),

    %% RR% below couchstore limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{resident_ratio => 5} end),
    ?assertEqual({error, resident_ratio, 10},
                 validate_storage_migration("", MagmaConfig, couchstore)),

    %% Data size and RR% above/below couchstore limit
    meck:expect(stats_interface, for_storage_mode_migration,
                fun ("", _Nodes) ->
                        #{data_size => 2,
                          resident_ratio => 5} end),
    ?assertEqual({error, data_size, 1.6},
                 validate_storage_migration("", MagmaConfig, couchstore)),

    ok.

basic_test_() ->
    %% We can re-use (setup) the test environment that we setup/teardown here
    %% for each test rather than create a new one (foreach) to save time.
    {setup,
     fun() ->
             basic_test_setup()
     end,
     fun(_) ->
             basic_test_teardown()
     end,
     [{"check bucket test", fun () -> check_bucket_t() end},
      {"check bucket during storage migration test",
       fun () -> check_bucket_during_storage_migration_t() end},
      {"dont check memcached or ephemeral test",
       fun () -> dont_check_memcached_or_ephemeral_t() end},
      {"check all resources test", fun () -> check_resources_t() end},
      {"validate bucket topology change test",
       fun validate_bucket_topology_change_t/0},
      {"validate topology change data guard rails test",
       fun () -> validate_topology_change_data_grs_t() end},
      {"validate topology change cores_per_bucket test",
       fun () -> validate_topology_change_cores_per_bucket_t() end},
      {"validate storage migration test",
       fun () -> validate_storage_migration_t() end}]}.

check_test_modules() ->
    [ns_config, cluster_compat_mode, menelaus_web_guardrails,stats_interface,
     config_profile, ns_bucket].

check_test_setup() ->
    meck:new(check_test_modules(), [passthrough]).

regular_checks_t() ->
    meck:expect(ns_config, search_node_with_default,
                fun ({?MODULE, check_interval}, _Default) ->
                        %% Use tiny timeout to force a second check immediately
                        1
                end),
    meck:expect(ns_config, set,
                fun ({node, _, resource_statuses}, _) -> ok end),

    meck:expect(cluster_compat_mode, is_cluster_trinity, ?cut(true)),
    meck:expect(config_profile, get_bool,
                fun ({resource_management, enabled}) -> false end),

    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio,
                            [{enabled, true},
                             {couchstore_minimum, 10},
                             {magma_minimum, 1}]}]}]
                end),
    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 10}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 1}]}]
                end),

    CouchstoreBucket = [{type, membase},
                        {storage_mode, couchstore}],
    MagmaBucket = [{type, membase},
                   {storage_mode, magma}],
    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"couchstore_bucket", CouchstoreBucket},
                         {"magma_bucket", MagmaBucket}]
                end),

    {ok, _Pid} = start_link(),

    meck:expect(config_profile, get_bool,
                fun ({resource_management, enabled}) -> true end),

    %% Wait to see second check after enable (implying the first one completed)
    meck:wait(2, ns_config, read_key_fast, [resource_management, '_'],
              ?MECK_WAIT_TIMEOUT),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 9}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 1}]}]
                end),
    meck:wait(1, ns_config, set,
              [{node, node(), resource_statuses},
               [{{bucket, "couchstore_bucket"}, resident_ratio}]],
              ?MECK_WAIT_TIMEOUT),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"},
                          [{resident_ratio, 10}]},
                         {{bucket, "magma_bucket"},
                          [{resident_ratio, 0.5}]}]
                end),
    meck:wait(1, ns_config, set,
              [{node, node(), resource_statuses},
               [{{bucket, "magma_bucket"}, resident_ratio}]],
              ?MECK_WAIT_TIMEOUT),

    %% Test bucket missing and stat missing
    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{{bucket, "couchstore_bucket"}, []}]
                end),
    meck:wait(1, ns_config, set, [{node, node(), resource_statuses}, []],
              ?MECK_WAIT_TIMEOUT),

    %% Confirm that expected functions were called in the first check
    meck:validate(ns_config),
    meck:validate(cluster_compat_mode),
    meck:validate(stats_interface).

check_test_teardown() ->
    gen_server:stop(?SERVER),
    meck:unload(check_test_modules()).

check_test_() ->
    {setup,
     fun () ->
             check_test_setup()
     end,
     fun(_) ->
             check_test_teardown()
     end,
     [{"regular checks test", fun () -> regular_checks_t() end}]}.

-endif.
