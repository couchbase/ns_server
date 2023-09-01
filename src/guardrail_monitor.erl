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
         validate_topology_change/2]).
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

get(bucket, resident_ratio) ->
    case proplists:get_value(bucket, get_config()) of
        undefined ->
            undefined;
        BucketConfig ->
            case proplists:get_value(resident_ratio, BucketConfig) of
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

validate_topology_change(EjectedLiveNodes, KeepKVNodes) ->
    case get(bucket, resident_ratio) of
        undefined ->
            ok;
        ResourceConfig ->
            BucketDataSizes =
                stats_interface:total_active_logical_data_size(
                  EjectedLiveNodes ++ KeepKVNodes),
            BadBuckets =
                maps:keys(
                  maps:filter(
                    fun (_Name, 0) ->
                            false;
                        (Name, TotalDataSize) ->
                            validate_bucket_topology_change(
                              Name, KeepKVNodes, TotalDataSize, ResourceConfig)
                    end, BucketDataSizes)),
            case BadBuckets of
                [] ->
                    %% No bucket is anticipated to breach it's RR% minimum
                    ok;
                _ ->
                    %% RR% violation expected for each of BadBuckets
                    {error,
                     {rr_will_be_too_low,
                      iolist_to_binary(
                        io_lib:format("The following buckets are expected to "
                                      "breach the RR% limit: ~p",
                                      [BadBuckets]))}}
            end
    end.

validate_bucket_topology_change(Name, KeepKVNodes, TotalDataSize,
                                ResourceConfig) ->
    case ns_bucket:get_bucket(Name) of
        not_present ->
            false;
        {ok, BCfg} ->
            NumNodes = case ns_bucket:get_width(BCfg) of
                           undefined -> length(KeepKVNodes);
                           W -> W * ns_cluster_membership:server_groups()
                       end,
            Quota = ns_bucket:raw_ram_quota(BCfg),
            ExpResidentRatio = 100 * NumNodes * Quota / TotalDataSize,
            validate_bucket_resource_min(BCfg, ResourceConfig, ExpResidentRatio)
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
                case proplists:get_value(BucketName, Stats) of
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
                    validate_bucket_resource_min(BucketConfig,
                                                 ResourceConfig, Metric);
                data_size ->
                    validate_bucket_resource_max(BucketConfig,
                                                 ResourceConfig, Metric)
            end
    end.

validate_bucket_resource_min(BucketConfig, ResourceConfig, Metric) ->
    CouchstoreLimit = proplists:get_value(couchstore_minimum, ResourceConfig),
    MagmaLimit = proplists:get_value(magma_minimum, ResourceConfig),
    case Metric of
        %% Ignore infinity/neg_infinity as these are not meaningful here
        infinity ->
            false;
        neg_infinity ->
            false;
        Value ->
            Limit =
                case ns_bucket:storage_mode(BucketConfig) of
                    magma -> MagmaLimit;
                    _ -> CouchstoreLimit
                end,
            Value < Limit
    end.

validate_bucket_resource_max(BucketConfig, ResourceConfig, Metric) ->
    CouchstoreLimit = proplists:get_value(couchstore_maximum, ResourceConfig),
    MagmaLimit = proplists:get_value(magma_maximum, ResourceConfig),
    case Metric of
        %% Ignore infinity/neg_infinity as these are not meaningful here
        infinity ->
            false;
        neg_infinity ->
            false;
        Value ->
            Limit =
                case ns_bucket:storage_mode(BucketConfig) of
                    magma -> MagmaLimit;
                    _ -> CouchstoreLimit
                end,
            %% Inclusive inequality so that when limit is 0 and value is 0, the
            %% guard rail still fires, which is useful for testing, and doesn't
            %% impact real world behaviour in a noticeable manner
            Value >= Limit
    end.

get_disk_usage(DiskStats) ->
    Mounts = lists:filtermap(
               fun({Disk, Value}) ->
                       {true, {Disk, ignore, Value}};
                  (_) ->
                       false
               end, DiskStats),
    {ok, DbDir} = ns_storage_conf:this_node_dbdir(),
    case misc:realpath(DbDir, "/") of
        {ok, RealFile} ->
            case ns_storage_conf:extract_disk_stats_for_path(
                   Mounts, RealFile) of
                {ok, {_Disk, _Cap, Used}} -> Used;
                none -> 0
            end;
        _ ->
            0
    end.

-ifdef(TEST).
modules() ->
    [ns_config, leader_registry, chronicle_compat, stats_interface,
     janitor_agent, ns_bucket, cluster_compat_mode, config_profile,
     ns_cluster_membership, ns_storage_conf].

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
       check({bucket, Config}, [{"couchstore", [{resident_ratio, 15}]}])),
    %% RR% below couchstore minimum
    ?assertListsEqual(
       [{{bucket, "couchstore"}, resident_ratio}],
       check({bucket, Config}, [{"couchstore", [{resident_ratio, 5}]}])),

    %% RR% above magma minimum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{"magma", [{resident_ratio, 2}]}])),
    %% RR% below magma minimum
    ?assertListsEqual(
       [{{bucket, "magma"}, resident_ratio}],
       check({bucket, Config}, [{"magma", [{resident_ratio, 0.5}]}])),

    %% Data size below couchstore maximum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{"couchstore", [{data_size, 1}]}])),
    %% Data size above couchstore maximum
    ?assertListsEqual(
       [{{bucket, "couchstore"}, data_size}],
       check({bucket, Config}, [{"couchstore", [{data_size, 5}]}])),

    %% Data size below magma maximum
    ?assertListsEqual(
       [],
       check({bucket, Config}, [{"magma", [{data_size, 5}]}])),
    %% Data size above magma maximum
    ?assertListsEqual(
       [{{bucket, "magma"}, data_size}],
       check({bucket, Config}, [{"magma", [{data_size, 20}]}])),
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
                        [{"couchstore_bucket", []}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 11}]},
                         {"magma_bucket",
                          [{resident_ratio, 2}]}]
                end),
    ?assertEqual([],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 9},
                           {data_size, 2}]},
                         {"magma_bucket",
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
                        [{"couchstore_bucket",
                          [{resident_ratio, 9}]},
                         {"magma_bucket",
                          [{resident_ratio, 2}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 11}]},
                         {"magma_bucket",
                          [{resident_ratio, 0.5}]}]
                end),
    ?assertEqual([{{bucket, "magma_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 9}]},
                         {"magma_bucket",
                          [{resident_ratio, 0.5}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, resident_ratio},
                  {{bucket, "magma_bucket"}, resident_ratio}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{data_size, 2}]},
                         {"magma_bucket",
                          [{data_size, 20}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, data_size},
                  {{bucket, "magma_bucket"}, data_size}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 11},
                           {data_size, 2}]},
                         {"magma_bucket",
                          [{resident_ratio, 2},
                           {data_size, 20}]}]
                end),
    ?assertEqual([{{bucket, "couchstore_bucket"}, data_size},
                  {{bucket, "magma_bucket"}, data_size}],
                 check_resources()),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 9},
                           {data_size, 2}]},
                         {"magma_bucket",
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

validate_topology_change_t() ->
    Servers = [node1, node2],
    DesiredServers = [{"couchstore_bucket", Servers},
                      {"magma_bucket", Servers},
                      {"deleted2", Servers}],
    ResourceConfig0 = [{couchstore_minimum, 10},
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

    ?assertEqual(true,
                 validate_bucket_topology_change("couchstore_bucket",
                                                 DesiredServers, 400,
                                                 ResourceConfig0)),

    ?assertEqual(true,
                 validate_bucket_topology_change("magma_bucket",
                                                 DesiredServers, 4000,
                                                 ResourceConfig0)),

    ?assertEqual(false,
                 validate_bucket_topology_change("couchstore_bucket",
                                                 DesiredServers, 200,
                                                 ResourceConfig0)),

    ?assertEqual(false,
                 validate_bucket_topology_change("magma_bucket",
                                                 DesiredServers, 2000,
                                                 ResourceConfig0)),

    meck:expect(ns_cluster_membership, service_active_nodes,
                fun (kv) -> Servers end),
    ResourceConfig1 = [{enabled, false} | ResourceConfig0],
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio, ResourceConfig1}]}]
                end),
    meck:expect(stats_interface, total_active_logical_data_size,
                fun (_) -> #{"couchstore_bucket" => 400,
                             "magma_bucket" => 4000} end),

    ?assertEqual(ok, validate_topology_change([node3], Servers)),

    ResourceConfig2 = [{enabled, true} | ResourceConfig0],
    meck:expect(ns_config, read_key_fast,
                fun (resource_management, _) ->
                        [{bucket,
                          [{resident_ratio, ResourceConfig2}]}]
                end),

    ?assertMatch({error, _},
                 validate_topology_change([node3], Servers)),

    meck:expect(stats_interface, total_active_logical_data_size,
                fun (_) -> #{"couchstore_bucket" => 200,
                             "magma_bucket" => 2000,
                             %% Ignored as size is 0
                             "new" => 0,
                             %% Ignored as the bucket name is not found in
                             %% DesiredServers
                             "deleted1" => 4000,
                             %% Ignored as the bucket name is not found with
                             %% ns_bucket:get_bucket/1
                             "deleted2" => 4000} end),

    ?assertMatch(ok,
                 validate_topology_change([node3], Servers)),
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
      {"check all resources test", fun () -> check_resources_t() end},
      {"validate topology change test",
       fun () -> validate_topology_change_t() end}]}.

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
                        [{"couchstore_bucket",
                          [{resident_ratio, 10}]},
                         {"magma_bucket",
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
                        [{"couchstore_bucket",
                          [{resident_ratio, 9}]},
                         {"magma_bucket",
                          [{resident_ratio, 1}]}]
                end),
    meck:wait(1, ns_config, set,
              [{node, node(), resource_statuses},
               [{{bucket, "couchstore_bucket"}, resident_ratio}]],
              ?MECK_WAIT_TIMEOUT),

    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket",
                          [{resident_ratio, 10}]},
                         {"magma_bucket",
                          [{resident_ratio, 0.5}]}]
                end),
    meck:wait(1, ns_config, set,
              [{node, node(), resource_statuses},
               [{{bucket, "magma_bucket"}, resident_ratio}]],
              ?MECK_WAIT_TIMEOUT),

    %% Test bucket missing and stat missing
    meck:expect(stats_interface, for_resource_management,
                fun () ->
                        [{"couchstore_bucket", []}]
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
