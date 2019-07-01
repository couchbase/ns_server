%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-2019 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% Monitor and maintain the vbucket layout of each bucket.
%% There is one of these per bucket.
%%
%% @doc Rebalancing functions.
%%

-module(ns_rebalancer).

-include("cut.hrl").
-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([check_graceful_failover_possible/2,
         validate_autofailover/1,
         generate_initial_map/1,
         start_link_rebalance/5,
         move_vbuckets/2,
         unbalanced/2,
         map_options_changed/1,
         eject_nodes/1,
         maybe_cleanup_old_buckets/1,
         get_delta_recovery_nodes/2,
         start_link_graceful_failover/1,
         generate_vbucket_map_options/2,
         run_failover/2,
         check_test_condition/2,
         rebalance_topology_aware_services/4]).

-export([wait_local_buckets_shutdown_complete/0]). % used via rpc:multicall


-define(DATA_LOST, 1).
-define(BAD_REPLICATORS, 2).

-define(BUCKETS_SHUTDOWN_WAIT_TIMEOUT, ?get_timeout(buckets_shutdown, 20000)).

-define(REBALANCER_READINESS_WAIT_TIMEOUT, ?get_timeout(readiness, 60000)).
-define(REBALANCER_QUERY_STATES_TIMEOUT,   ?get_timeout(query_states, 10000)).
-define(REBALANCER_APPLY_CONFIG_TIMEOUT,   ?get_timeout(apply_config, 300000)).
-define(FAILOVER_OPS_TIMEOUT, ?get_timeout(failover_ops_timeout, 10000)).
%%
%% API
%%

run_failover(Nodes, AllowUnsafe) ->
    case check_failover_possible(Nodes) of
        ok ->
            Result = leader_activities:run_activity(
                       failover, majority,
                       ?cut(orchestrate_failover(Nodes, [durability_aware])),
                       [{unsafe, AllowUnsafe}]),

            case Result of
                {leader_activities_error, _, {quorum_lost, _}} ->
                    orchestration_unsafe;
                {leader_activities_error, _, {no_quorum, _}} ->
                    orchestration_unsafe;
                _ ->
                    Result
            end;
        Error ->
            Error
    end.

orchestrate_failover(Nodes, Options) ->
    case pre_failover_config_sync(Nodes, Options) of
        ok ->
            do_orchestrate_failover(Nodes, Options);
        Error ->
            Error
    end.

do_orchestrate_failover(Nodes, Options) ->
    ale:info(?USER_LOGGER, "Starting failing over ~p", [Nodes]),
    master_activity_events:note_failover(Nodes),

    ErrorNodes = failover(Nodes, Options),

    case ErrorNodes of
        [] ->
            ns_cluster:counter_inc(failover_complete),
            ale:info(?USER_LOGGER, "Failed over ~p: ok", [Nodes]);
        _ ->
            ns_cluster:counter_inc(failover_incomplete),
            ale:error(?USER_LOGGER,
                      "Failover couldn't "
                      "complete on some nodes:~n~p", [ErrorNodes])
    end,

    ok = leader_activities:deactivate_quorum_nodes(Nodes),

    ns_cluster:counter_inc(failover),
    deactivate_nodes(Nodes),

    ok.

pre_failover_config_sync(FailedNodes, Options) ->
    case durability_aware(Options) of
        true ->
            Timeout = ?get_timeout(failover_config_pull, 10000),
            SyncNodes = failover_config_sync_nodes(FailedNodes),

            ?log_info("Going to pull config "
                      "from ~p before failover", [SyncNodes]),

            case ns_config_rep:pull_remotes(SyncNodes, Timeout) of
                ok ->
                    ok;
                Error ->
                    ?log_error("Config pull from ~p failed: ~p",
                               [SyncNodes, Error]),
                    config_sync_failed
            end;
        false ->
            ok
    end.

failover_config_sync_nodes(FailedNodes) ->
    Nodes = ns_cluster_membership:get_nodes_with_status(_ =/= inactiveFailed),
    Nodes -- FailedNodes.

deactivate_nodes([]) ->
    ok;
deactivate_nodes(Nodes) ->
    ale:info(?USER_LOGGER, "Deactivating failed over nodes ~p", [Nodes]),
    ns_cluster_membership:deactivate(Nodes).

%% @doc Fail one or more nodes. Doesn't eject the node from the cluster. Takes
%% effect immediately.
failover(Nodes, Options) ->
    lists:umerge([failover_buckets(Nodes, Options),
                  failover_services(Nodes)]).

failover_buckets(Nodes, Options) ->
    Results =
        lists:foldl(
          fun ({Bucket, BucketConfig}, Acc) ->
                  %% Verify that the server list is consistent with cluster
                  %% membership states.
                  ok = ns_janitor:check_server_list(Bucket, BucketConfig),

                  try failover_bucket(Bucket, BucketConfig, Nodes, Options) of
                      Res ->
                          Res ++ Acc
                  catch throw:{failed, Msg} ->
                          ?log_error("Caught failover exception: ~p", [Msg]),
                          update_failover_vbuckets(Acc),
                          ns_orchestrator:request_janitor_run({bucket, Bucket}),
                          throw({failover_failed, Msg})
                  end
          end, [], ns_bucket:get_buckets()),
    update_failover_vbuckets(Results),
    failover_handle_results(Results).

update_failover_vbuckets(Results) ->
    GroupedByNode =
        misc:groupby_map(fun (L) ->
                                 Node   = proplists:get_value(node, L),
                                 Bucket = proplists:get_value(bucket, L),
                                 VBs    = proplists:get_value(vbuckets, L),

                                 {Node, {Bucket, VBs}}
                         end, Results),
    {commit, _} =
        ns_config:run_txn(
          fun (Config, Set) ->
                  {commit,
                   lists:foldl(?cut(update_failover_vbuckets(Set, _, _)),
                               Config, GroupedByNode)}
          end).

update_failover_vbuckets(Set, {Node, BucketResults}, Config) ->
    ExistingBucketResults = node_failover_vbuckets(Config, Node),
    Merged = merge_failover_vbuckets(ExistingBucketResults, BucketResults),

    ?log_debug("Updating failover_vbuckets for ~p with ~p~n"
               "Existing vbuckets: ~p~nNew vbuckets: ~p",
               [Node, Merged, ExistingBucketResults, BucketResults]),

    case Merged of
        ExistingBucketResults ->
            Config;
        _ ->
            Set({node, Node, failover_vbuckets}, Merged, Config)
    end.

merge_failover_vbuckets(ExistingBucketResults, BucketResults) ->
    Grouped =
        misc:groupby_map(fun functools:id/1,
                         ExistingBucketResults ++ BucketResults),
    lists:map(fun ({B, [VBs1, VBs2]}) when is_list(VBs1), is_list(VBs2) ->
                      {B, lists:usort(VBs1 ++ VBs2)};
                  ({B, [VBs]}) when is_list(VBs) ->
                      {B, lists:sort(VBs)}
              end, Grouped).

-ifdef(TEST).
merge_failover_vbuckets_test() ->
    ?assertEqual(
       [{"test", [0, 1, 2, 3]}, {"test1", [0, 1, 2, 3]}],
       merge_failover_vbuckets(
         [], [{"test", [0, 1, 2, 3]}, {"test1", [0, 1, 2, 3]}])),
    ?assertEqual(
       [{"test", [0, 1, 2, 3]}, {"test1", [0, 1, 2, 3]}],
       merge_failover_vbuckets(
         [{"test", [0, 1, 2, 3]}], [{"test1", [0, 1, 2, 3]}])),
    ?assertEqual(
       [{"test", [0, 1, 2, 3]}],
       merge_failover_vbuckets([{"test", [0, 3]}], [{"test", [1, 2]}])),
    ?assertEqual(
       [{"test", [0, 1, 2, 3]}],
       merge_failover_vbuckets([{"test", [0, 2, 3]}], [{"test", [1, 2]}])).
-endif.

failover_handle_results(Results) ->
    NodeStatuses =
        misc:groupby_map(fun (Result) ->
                                 Node   = proplists:get_value(node, Result),
                                 Status = proplists:get_value(status, Result),

                                 {Node, Status}
                         end, Results),

    lists:filtermap(fun ({Node, Statuses}) ->
                            NonOKs = [S || S <- Statuses, S =/= ok],

                            case NonOKs of
                                [] ->
                                    false;
                                _ ->
                                    {true, Node}
                            end
                    end, NodeStatuses).

failover_bucket(Bucket, BucketConfig, Nodes, Options) ->
    master_activity_events:note_bucket_failover_started(Bucket, Nodes),

    Type   = ns_bucket:bucket_type(BucketConfig),
    Result = do_failover_bucket(Type, Bucket, BucketConfig, Nodes, Options),

    master_activity_events:note_bucket_failover_ended(Bucket, Nodes),

    Result.

do_failover_bucket(memcached, Bucket, BucketConfig, Nodes, _Options) ->
    failover_memcached_bucket(Nodes, Bucket, BucketConfig),
    [];
do_failover_bucket(membase, Bucket, BucketConfig, Nodes, Options) ->
    Map = proplists:get_value(map, BucketConfig, []),
    R = failover_membase_bucket(Nodes, Bucket, BucketConfig, Map, Options),

    [[{bucket, Bucket},
      {node, N},
      {status, R},
      {vbuckets, node_vbuckets(Map, N)}] || N <- Nodes].

failover_services(Nodes) ->
    Config    = ns_config:get(),
    Services0 = lists:flatmap(
                  ns_cluster_membership:node_services(Config, _), Nodes),
    Services  = lists:usort(Services0) -- [kv],

    Results = lists:flatmap(failover_service(Config, _, Nodes), Services),
    failover_handle_results(Results).

failover_service(Config, Service, Nodes) ->
    ns_cluster_membership:failover_service_nodes(Config, Service, Nodes),

    %% We're refetching the config since failover_service_nodes updated the
    %% one that we had.
    Result = service_janitor:complete_service_failover(ns_config:get(),
                                                       Service,
                                                       Nodes),
    case Result of
        ok ->
            ?log_debug("Failed over service ~p on nodes ~p successfully",
                       [Service, Nodes]);
        _ ->
            ?log_error("Failed to failover service ~p on nodes ~p: ~p",
                       [Service, Nodes, Result])
    end,

    [[{node, Node},
      {status, Result},
      {service, Service}] || Node <- Nodes].

validate_autofailover(Nodes) ->
    BucketPairs = ns_bucket:get_buckets(),
    UnsafeBuckets =
        [BucketName
         || {BucketName, BucketConfig} <- BucketPairs,
            validate_autofailover_bucket(BucketConfig, Nodes) =:= false],
    case UnsafeBuckets of
        [] -> ok;
        _ -> {error, UnsafeBuckets}
    end.

validate_autofailover_bucket(BucketConfig, Nodes) ->
    case proplists:get_value(type, BucketConfig) of
        membase ->
            Map = proplists:get_value(map, BucketConfig),
            Map1 = mb_map:promote_replicas(Map, Nodes),
            case Map1 of
                undefined ->
                    true;
                _ ->
                    case [I || {I, [undefined|_]} <- misc:enumerate(Map1, 0)] of
                        [] -> true;
                        _MissingVBuckets ->
                            false
                    end
            end;
        _ ->
            true
    end.

failover_memcached_bucket(Nodes, Bucket, BucketConfig) ->
    remove_nodes_from_server_list(Nodes, Bucket, BucketConfig).

failover_membase_bucket(Nodes, Bucket, BucketConfig, [], _Options) ->
    %% this is possible if bucket just got created and ns_janitor didn't get a
    %% chance to create a map yet; or alternatively, if it failed to do so
    %% because, for example, one of the nodes was down
    failover_membase_bucket_with_no_map(Nodes, Bucket, BucketConfig);
failover_membase_bucket(Nodes, Bucket, BucketConfig, Map, Options) ->
    failover_membase_bucket_with_map(Nodes, Bucket, BucketConfig, Map, Options).

failover_membase_bucket_with_no_map(Nodes, Bucket, BucketConfig) ->
    ?log_debug("Skipping failover of bucket ~p because it has no vbuckets. "
               "Config:~n~p", [Bucket, BucketConfig]),

    %% we still need to make sure to remove ourselves from the bucket server
    %% list
    remove_nodes_from_server_list(Nodes, Bucket, BucketConfig),
    ok.

failover_membase_bucket_with_map(Nodes, Bucket, BucketConfig, Map, Options) ->
    NewMap = fix_vbucket_map(Nodes, Bucket, Map, Options),
    true = (NewMap =/= undefined),

    ?log_debug("Original vbucket map: ~p~n"
               "VBucket map with failover applied: ~p", [Map, NewMap]),

    case [I || {I, [undefined|_]} <- misc:enumerate(NewMap, 0)] of
        [] -> ok; % Phew!
        MissingVBuckets ->
            ?rebalance_error("Lost data in ~p for ~w", [Bucket, MissingVBuckets]),
            ?user_log(?DATA_LOST,
                      "Data has been lost for ~B% of vbuckets in bucket ~p.",
                      [length(MissingVBuckets) * 100 div length(Map), Bucket])
    end,

    ns_bucket:set_fast_forward_map(Bucket, undefined),
    ns_bucket:set_map(Bucket, NewMap),
    remove_nodes_from_server_list(Nodes, Bucket, BucketConfig),

    CleanupOptions = failover_janitor_cleanup_options(Nodes, Options),
    case (catch ns_janitor:cleanup(Bucket, CleanupOptions)) of
        ok ->
            ok;
        {error, _, BadNodes} ->
            ?rebalance_error("Skipped vbucket activations and "
                             "replication topology changes because not "
                             "all remaining nodes were found to have "
                             "healthy bucket ~p: ~p", [Bucket, BadNodes]),
            janitor_failed;
        Error ->
            ?rebalance_error("Janitor cleanup of ~p "
                             "failed after failover of ~p: ~p",
                             [Bucket, Nodes, Error]),
            janitor_failed
    end.

failover_janitor_cleanup_options(FailedNodes, FailoverOptions) ->
    [{sync_nodes, failover_config_sync_nodes(FailedNodes)},
     {pull_config, false},
     {push_config, durability_aware(FailoverOptions)}].

durability_aware(Options) ->
    cluster_compat_mode:preserve_durable_mutations() andalso
        proplists:get_bool(durability_aware, Options).

fix_vbucket_map(FailoverNodes, Bucket, Map, Options) ->
    case durability_aware(Options) of
        true ->
            fix_vbucket_map_durability_aware(FailoverNodes, Bucket, Map);
        false ->
            mb_map:promote_replicas(Map, FailoverNodes)
    end.

fix_vbucket_map_durability_aware(FailoverNodes, Bucket, Map) ->
    EnumeratedMap = misc:enumerate(Map, 0),

    FixedChains =
        dict:from_list(
          case [C || C = {_, [Master | _]} <- EnumeratedMap,
                     lists:member(Master, FailoverNodes)] of
              [] ->
                  [];
              ChainsNeedFixing ->
                  fix_chains(Bucket, FailoverNodes, ChainsNeedFixing)
          end),
    lists:map(
      fun ({VB, Chain}) ->
              case dict:find(VB, FixedChains) of
                  {ok, NewChain} ->
                      NewChain;
                  error ->
                      mb_map:promote_replica(Chain, FailoverNodes)
              end
      end, EnumeratedMap).

fix_chains(Bucket, FailoverNodes, Chains) ->
    NodesToQuery = nodes_to_query(Chains, FailoverNodes),

    {Info, BadNodes} =
        janitor_agent:query_vbuckets(
          Bucket, NodesToQuery,
          [high_seqno, high_prepared_seqno],
          [stop_replications, {timeout, ?FAILOVER_OPS_TIMEOUT}]),

    BadNodes =:= [] orelse
        throw_failover_error("Failed to get failover info for bucket ~p: ~p",
                             [Bucket, BadNodes]),

    ?log_debug("Retrieved the following vbuckets information: ~p",
               [dict:to_list(Info)]),

    [{VB, fix_chain(VB, Chain, Info, FailoverNodes)}
     || {VB, Chain} <- Chains].

fix_chain(VBucket, Chain, Info, FailoverNodes) ->
    NodeStates = janitor_agent:fetch_vbucket_states(VBucket, Info),
    WithFNodesRemoved = mb_map:promote_replica(Chain, FailoverNodes),

    case find_max_replica(WithFNodesRemoved, NodeStates) of
        not_found ->
            WithFNodesRemoved;
        MaxReplica ->
            [MaxReplica | lists:delete(MaxReplica, WithFNodesRemoved)]
    end.

nodes_to_query(Chains, FailoverNodes) ->
    NodeVBs =
        lists:flatmap(
          fun ({VB, Chain}) ->
                  [{Node, VB} || Node <- tl(Chain),
                                 Node =/= undefined,
                                 not lists:member(Node, FailoverNodes)]
          end, Chains),
    [{N, lists:usort(VBs)} ||
        {N, VBs} <- misc:groupby_map(fun functools:id/1, NodeVBs)].

throw_failover_error(Msg, Params) ->
    throw({failed, lists:flatten(io_lib:format(Msg, Params))}).

%% A replica is considered ahead of another replica if its last snapshot seqno
%% is greater, if they are the same, the replica with greater high_seqno is then
%% considered ahead.
find_max_replica(Chain, NodeStates) ->
    Get = fun (K, P) ->
                  V = proplists:get_value(K, P), true = V =/= undefined, V
          end,
    ChainStates =
        lists:filtermap(
          fun (undefined) ->
                  false;
              (Node) ->
                  case lists:keyfind(Node, 1, NodeStates) of
                      {Node, _, Props} ->
                          {true,
                           {Node,
                            {Get(high_prepared_seqno, Props),
                             Get(high_seqno, Props)}}};
                      false ->
                          false
                  end
          end, Chain),
    case ChainStates of
        [] ->
            not_found;
        _ ->
            {MaxReplica, _} = misc:min_by(fun ({_, SeqNos}, {_, MaxSeqNos}) ->
                                                  SeqNos > MaxSeqNos
                                          end, ChainStates),
            MaxReplica
    end.

remove_nodes_from_server_list(Nodes, Bucket, BucketConfig) ->
    Servers = proplists:get_value(servers, BucketConfig),
    ns_bucket:set_servers(Bucket, Servers -- Nodes).

generate_vbucket_map_options(KeepNodes, BucketConfig) ->
    Config = ns_config:get(),
    generate_vbucket_map_options(KeepNodes, BucketConfig, Config).

generate_vbucket_map_options(KeepNodes, BucketConfig, Config) ->
    Tags = case ns_config:search(Config, server_groups) of
               false ->
                   undefined;
               {value, ServerGroups} ->
                   case [G || G <- ServerGroups,
                              proplists:get_value(nodes, G) =/= []] of
                       [_] ->
                           %% note that we don't need to handle this case
                           %% specially; but unfortunately removing it would
                           %% make 2.5 nodes always believe that rebalance is
                           %% required in case there's only one server group
                           undefined;
                       _ ->
                           Tags0 = [case proplists:get_value(uuid, G) of
                                        T ->
                                            [{N, T} || N <- proplists:get_value(nodes, G),
                                                       lists:member(N, KeepNodes)]
                                    end || G <- ServerGroups],

                           TagsRV = lists:append(Tags0),

                           case KeepNodes -- [N || {N, _T} <- TagsRV] of
                               [] -> ok;
                               _ ->
                                   %% there's tiny race between start of rebalance and
                                   %% somebody changing server_groups. We largely ignore it,
                                   %% but in case where it can clearly cause problem we raise
                                   %% exception
                                   erlang:error(server_groups_race_detected)
                           end,

                           TagsRV
                   end
           end,

    Opts0 = ns_bucket:config_to_map_options(BucketConfig),

    %% Note that we don't need to have replication_topology here (in fact as
    %% of today it's still returned by ns_bucket:config_to_map_options/1), but
    %% these options are used to compute map_opts_hash which in turn is used
    %% to decide if rebalance is needed. So if we remove this, old nodes will
    %% wrongly believe that rebalance is needed even when the cluster is
    %% balanced. See MB-15543 for details.
    misc:update_proplist(Opts0, [{replication_topology, star},
                                 {tags, Tags}]).

generate_vbucket_map(CurrentMap, KeepNodes, BucketConfig) ->
    Opts = generate_vbucket_map_options(KeepNodes, BucketConfig),

    Map0 =
        case lists:keyfind(deltaRecoveryMap, 1, BucketConfig) of
            {deltaRecoveryMap, DRMapAndOpts} when DRMapAndOpts =/= undefined ->
                {DRMap, DROpts} = DRMapAndOpts,

                case mb_map:is_trivially_compatible_past_map(KeepNodes, CurrentMap,
                                                             Opts, DRMap, DROpts) of
                    true ->
                        DRMap;
                    false ->
                        undefined
                end;
            _ ->
                undefined
        end,

    Map = case Map0 of
              undefined ->
                  EffectiveOpts = [{maps_history, ns_bucket:past_vbucket_maps()} | Opts],
                  NumReplicas = ns_bucket:num_replicas(BucketConfig),
                  mb_map:generate_map(CurrentMap, NumReplicas, KeepNodes, EffectiveOpts);
              _ ->
                  Map0
          end,

    {Map, Opts}.

generate_initial_map(BucketConfig) ->
    Chain = lists:duplicate(proplists:get_value(num_replicas, BucketConfig) + 1,
                            undefined),
    Map1 = lists:duplicate(proplists:get_value(num_vbuckets, BucketConfig),
                           Chain),
    Servers = proplists:get_value(servers, BucketConfig),
    generate_vbucket_map(Map1, Servers, BucketConfig).

local_buckets_shutdown_loop(Ref, CanWait) ->
    ExcessiveBuckets = ns_memcached:active_buckets() -- ns_bucket:node_bucket_names(node()),
    case ExcessiveBuckets of
        [] ->
            ok;
        _ ->
            case CanWait of
                false ->
                    exit({old_buckets_shutdown_wait_failed, ExcessiveBuckets});
                true ->
                    ?log_debug("Waiting until the following old bucket instances are gone: ~p", [ExcessiveBuckets]),
                    receive
                        {Ref, timeout} ->
                            local_buckets_shutdown_loop(Ref, false);
                        {Ref, _Msg} ->
                            local_buckets_shutdown_loop(Ref, true)
                    end
            end
    end.

%% note: this is rpc:multicall-ed
wait_local_buckets_shutdown_complete() ->
    ExcessiveBuckets =
        ns_memcached:active_buckets() -- ns_bucket:node_bucket_names(node()),
    do_wait_local_buckets_shutdown_complete(ExcessiveBuckets).

do_wait_local_buckets_shutdown_complete([]) ->
    ok;
do_wait_local_buckets_shutdown_complete(ExcessiveBuckets) ->
    Timeout = ?BUCKETS_SHUTDOWN_WAIT_TIMEOUT * length(ExcessiveBuckets),
    misc:executing_on_new_process(
      fun () ->
              Ref = erlang:make_ref(),
              Parent = self(),
              Subscription = ns_pubsub:subscribe_link(buckets_events,
                                                      fun ({stopped, _} = StoppedMsg) ->
                                                              Parent ! {Ref, StoppedMsg};
                                                          (_) ->
                                                              ok
                                                      end),
              erlang:send_after(Timeout, Parent, {Ref, timeout}),
              try
                  local_buckets_shutdown_loop(Ref, true)
              after
                  (catch ns_pubsub:unsubscribe(Subscription))
              end
      end).

do_wait_buckets_shutdown(KeepNodes) ->
    {Good, ReallyBad, FailedNodes} =
        misc:rpc_multicall_with_plist_result(
          KeepNodes, ns_rebalancer, wait_local_buckets_shutdown_complete, []),
    NonOk = [Pair || {_Node, Result} = Pair <- Good,
                     Result =/= ok],
    Failures = ReallyBad ++ NonOk ++ [{N, node_was_down} || N <- FailedNodes],
    case Failures of
        [] ->
            ok;
        _ ->
            ?rebalance_error("Failed to wait deletion of some buckets on some nodes: ~p~n", [Failures]),
            exit({buckets_shutdown_wait_failed, Failures})
    end.

sanitize(Config) ->
    misc:rewrite_key_value_tuple(sasl_password, "*****", Config).

pull_and_push_config(Nodes) ->
    case ns_config_rep:pull_remotes(Nodes) of
        ok ->
            ok;
        Error ->
            exit({config_sync_failed, Error})
    end,

    %% And after we have that, make sure recovery, rebalance and
    %% graceful failover, all start with latest config reliably
    case ns_config_rep:ensure_config_seen_by_nodes(Nodes) of
        ok ->
            cool;
        {error, SyncFailedNodes} ->
            exit({config_sync_failed, SyncFailedNodes})
    end.

start_link_rebalance(KeepNodes, EjectNodes,
                     FailedNodes, DeltaNodes, DeltaRecoveryBucketNames) ->
    proc_lib:start_link(
      erlang, apply,
      [fun () ->
               FailKvChk = check_test_condition(no_kv_nodes_left) =/= ok,

               KVKeep = ns_cluster_membership:service_nodes(KeepNodes, kv),
               case KVKeep =:= [] orelse FailKvChk of
                   true ->
                       proc_lib:init_ack({error, no_kv_nodes_left}),
                       exit(normal);
                   false ->
                       ok
               end,

               KVDeltaNodes = ns_cluster_membership:service_nodes(DeltaNodes,
                                                                  kv),
               BucketConfigs = ns_bucket:get_buckets(),
               %% Pre-emptive check to see if delta recovery is possible.
               case build_delta_recovery_buckets(KVKeep, KVDeltaNodes,
                                                 BucketConfigs, DeltaRecoveryBucketNames) of
                   {ok, _DeltaRecoveryBucketTuples} ->
                       proc_lib:init_ack({ok, self()}),

                       master_activity_events:note_rebalance_start(
                         self(), KeepNodes, EjectNodes, FailedNodes, DeltaNodes),

                       rebalance(KeepNodes, EjectNodes, FailedNodes,
                                 DeltaNodes, DeltaRecoveryBucketNames);
                   {error, not_possible} ->
                       proc_lib:init_ack({error, delta_recovery_not_possible})
               end
       end, []]).

move_vbuckets(Bucket, Moves) ->
    {ok, Config} = ns_bucket:get_bucket(Bucket),
    Map = proplists:get_value(map, Config),
    TMap = lists:foldl(fun ({VBucket, TargetChain}, Map0) ->
                               setelement(VBucket+1, Map0, TargetChain)
                       end, list_to_tuple(Map), Moves),
    NewMap = tuple_to_list(TMap),
    ProgressFun = make_progress_fun(0, 1),
    run_mover(Bucket, Config,
              proplists:get_value(servers, Config),
              ProgressFun, Map, NewMap).

rebalance_services(KeepNodes, EjectNodes) ->
    Config = ns_config:get(),

    AllServices = ns_cluster_membership:cluster_supported_services() -- [kv],
    TopologyAwareServices = ns_cluster_membership:topology_aware_services(),
    SimpleServices = AllServices -- TopologyAwareServices,

    SimpleTSs = rebalance_simple_services(Config, SimpleServices, KeepNodes),
    TopologyAwareTSs = rebalance_topology_aware_services(Config, TopologyAwareServices,
                                                         KeepNodes, EjectNodes),

    maybe_delay_eject_nodes(SimpleTSs ++ TopologyAwareTSs, EjectNodes).

rebalance_simple_services(Config, Services, KeepNodes) ->
    lists:filtermap(
      fun (Service) ->
              ServiceNodes = ns_cluster_membership:service_nodes(KeepNodes, Service),
              master_activity_events:note_rebalance_stage_started(
                Service, ServiceNodes),
              Updated = update_service_map_with_config(Config, Service, ServiceNodes),

              master_activity_events:note_rebalance_stage_completed(
                Service),
              case Updated of
                  false ->
                      false;
                  true ->
                      {true, {Service, os:timestamp()}}
              end
      end, Services).

update_service_map_with_config(Config, Service, ServiceNodes0) ->
    CurrentNodes0 = ns_cluster_membership:get_service_map(Config, Service),
    update_service_map(Service, CurrentNodes0, ServiceNodes0).

update_service_map(Service, CurrentNodes0, ServiceNodes0) ->
    CurrentNodes = lists:sort(CurrentNodes0),
    ServiceNodes = lists:sort(ServiceNodes0),

    case CurrentNodes =:= ServiceNodes of
        true ->
            false;
        false ->
            ?rebalance_info("Updating service map for ~p:~n~p",
                            [Service, ServiceNodes]),
            ok = ns_cluster_membership:set_service_map(Service, ServiceNodes),
            true
    end.

rebalance_topology_aware_services(Config, Services, KeepNodesAll, EjectNodesAll) ->
    %% TODO: support this one day
    DeltaNodesAll = [],

    lists:filtermap(
      fun (Service) ->
              ok = check_test_condition(service_rebalance_start, Service),
              KeepNodes = ns_cluster_membership:service_nodes(Config, KeepNodesAll, Service),
              DeltaNodes = ns_cluster_membership:service_nodes(Config, DeltaNodesAll, Service),

              %% if a node being ejected is not active, then it means that it
              %% was never rebalanced in in the first place; so we can
              %% postpone the heat death of the universe a little bit by
              %% ignoring such nodes
              ActiveNodes = ns_cluster_membership:get_service_map(Config, Service),
              EjectNodes = [N || N <- EjectNodesAll,
                                 lists:member(N, ActiveNodes)],

              AllNodes = EjectNodes ++ KeepNodes,

              case AllNodes of
                  [] ->
                      false;
                  _ ->
                      master_activity_events:note_rebalance_stage_started(
                        Service, AllNodes),
                      update_service_map_with_config(Config, Service, AllNodes),
                      ok = rebalance_topology_aware_service(Service, KeepNodes,
                                                            EjectNodes, DeltaNodes),
                      update_service_map(Service, AllNodes, KeepNodes),
                      master_activity_events:note_rebalance_stage_completed(
                        Service),
                      {true, {Service, os:timestamp()}}
              end
      end, Services).

rebalance_topology_aware_service(Service, KeepNodes, EjectNodes, DeltaNodes) ->
    ProgressCallback =
        fun (Progress) ->
                ns_rebalance_observer:update_progress(Service, Progress)
        end,

    misc:with_trap_exit(
      fun () ->
              {Pid, MRef} = service_rebalancer:spawn_monitor_rebalance(
                              Service, KeepNodes,
                              EjectNodes, DeltaNodes, ProgressCallback),

              receive
                  {'EXIT', _Pid, Reason} = Exit ->
                      ?log_debug("Got an exit signal while waiting "
                                 "for the service rebalance to complete. "
                                 "Service: ~p. Exit message: ~p",
                                 [Service, Exit]),

                      misc:terminate_and_wait(Pid, Reason),
                      exit(Reason);
                  {'DOWN', MRef, _, _, Reason} ->
                      case Reason of
                          normal ->
                              ok;
                          _ ->
                              exit({service_rebalance_failed, Service, Reason})
                      end
              end
      end).

get_service_eject_delay(Service) ->
    Default =
        case Service of
            n1ql ->
                20000;
            fts ->
                10000;
            _ ->
                0
        end,

    ?get_param({eject_delay, Service}, Default).

maybe_delay_eject_nodes(Timestamps, EjectNodes) ->
    do_maybe_delay_eject_nodes(Timestamps, EjectNodes).

do_maybe_delay_eject_nodes(_Timestamps, []) ->
    ok;
do_maybe_delay_eject_nodes(Timestamps, EjectNodes) ->
    EjectedServices =
        ordsets:union([ordsets:from_list(ns_cluster_membership:node_services(N))
                       || N <- EjectNodes]),
    Now = os:timestamp(),

    Delays = [begin
                  ServiceDelay = get_service_eject_delay(Service),

                  case proplists:get_value(Service, Timestamps) of
                      undefined ->
                          %% it's possible that a node is ejected without ever
                          %% getting rebalanced in; there's no point in
                          %% delaying anything in such case
                          0;
                      RebalanceTS ->
                          SinceRebalance = max(0, timer:now_diff(Now, RebalanceTS) div 1000),
                          ServiceDelay - SinceRebalance
                  end
              end || Service <- EjectedServices],

    Delay = lists:max(Delays),

    case Delay > 0 of
        true ->
            ?log_info("Waiting ~pms before ejecting nodes:~n~p",
                      [Delay, EjectNodes]),
            timer:sleep(Delay);
        false ->
            ok
    end.

rebalance(KeepNodes, EjectNodesAll, FailedNodesAll,
          DeltaNodes, DeltaRecoveryBucketNames) ->
    ok = check_test_condition(rebalance_start),
    ok = leader_activities:run_activity(
           rebalance, majority,
           ?cut(rebalance_body(KeepNodes, EjectNodesAll,
                               FailedNodesAll,
                               DeltaNodes, DeltaRecoveryBucketNames))).

rebalance_body(KeepNodes,
               EjectNodesAll,
               FailedNodesAll,
               DeltaNodes, DeltaRecoveryBucketNames) ->
    LiveNodes = KeepNodes ++ EjectNodesAll,
    LiveKVNodes = ns_cluster_membership:service_nodes(LiveNodes, kv),
    KVDeltaNodes = ns_cluster_membership:service_nodes(DeltaNodes, kv),

    prepare_rebalance(LiveNodes),

    ok = drop_old_2i_indexes(KeepNodes),

    master_activity_events:note_rebalance_stage_started(kv, LiveKVNodes),
    %% wait till all bucket shutdowns are done on nodes we're
    %% adding (or maybe adding).
    do_wait_buckets_shutdown(KeepNodes),

    %% We run the janitor here to make sure that the vbucket map is in sync
    %% with the vbucket states.
    %% Unfortunately, we need to run it once more in rebalance_kv after
    %% the server list for the bucket is updated. So that the states of the
    %% vbucket on newly added nodes are applied.
    lists:foreach(fun (Bucket) ->
                          run_janitor_pre_rebalance(Bucket)
                  end, ns_bucket:get_bucket_names()),

    %% Fetch new BucketConfigs and re build DeltaRecoveryBuckets, as janitor run
    %% might have updated vbucket map.
    BucketConfigs = ns_bucket:get_buckets(),
    KVKeep = ns_cluster_membership:service_nodes(KeepNodes, kv),
    DeltaRecoveryBuckets = case build_delta_recovery_buckets(
                                  KVKeep, KVDeltaNodes,
                                  BucketConfigs, DeltaRecoveryBucketNames) of
                               {ok, DRB} ->
                                   DRB;
                               {error, not_possible} ->
                                   throw({error, delta_recovery_not_possible})
                           end,
    master_activity_events:note_rebalance_stage_started(
      [kv, kv_delta_recovery], KVDeltaNodes),
    ok = apply_delta_recovery_buckets(DeltaRecoveryBuckets,
                                      KVDeltaNodes, BucketConfigs),
    ok = check_test_condition(after_apply_delta_recovery),
    ok = maybe_clear_recovery_type(KeepNodes),
    master_activity_events:note_rebalance_stage_completed(
      [kv, kv_delta_recovery]),
    ok = service_janitor:cleanup(),

    ok = leader_activities:activate_quorum_nodes(KeepNodes),
    ns_cluster_membership:activate(KeepNodes),

    pull_and_push_config(EjectNodesAll ++ KeepNodes),

    %% Eject failed nodes first so they don't cause trouble
    FailedNodes = FailedNodesAll -- [node()],
    eject_nodes(FailedNodes),

    ok = check_test_condition(rebalance_cluster_nodes_active),

    rebalance_kv(KeepNodes, EjectNodesAll, BucketConfigs, DeltaRecoveryBuckets),
    master_activity_events:note_rebalance_stage_completed(kv),
    rebalance_services(KeepNodes, EjectNodesAll),

    ok = leader_activities:deactivate_quorum_nodes(EjectNodesAll),

    %% Note that we "unprepare" rebalance only if it terminates normally. If
    %% it's interrupted or fails, that's likely because some of the nodes are
    %% unhealthy. Specifically, in the case of autofailover interrupting
    %% rebalance we don't want to get stuck trying to reach the node that
    %% needs to be auto failed over.
    unprepare_rebalance(LiveNodes),

    %% don't eject ourselves at all here; this will be handled by
    %% ns_orchestrator
    EjectNowNodes = EjectNodesAll -- [node()],
    eject_nodes(EjectNowNodes),

    ok.

make_progress_fun(BucketCompletion, NumBuckets) ->
    fun (P) ->
            Progress = dict:map(fun (_, N) ->
                                        N / NumBuckets + BucketCompletion
                                end, P),
            update_kv_progress(Progress)
    end.

update_kv_progress(Progress) ->
    ns_rebalance_observer:update_progress(kv, Progress).

update_kv_progress(Nodes, Progress) ->
    update_kv_progress(dict:from_list([{N, Progress} || N <- Nodes])).

rebalance_kv(KeepNodes, EjectNodes, BucketConfigs, DeltaRecoveryBuckets) ->
    NumBuckets = length(BucketConfigs),
    ?rebalance_debug("BucketConfigs = ~p", [sanitize(BucketConfigs)]),

    KeepKVNodes = ns_cluster_membership:service_nodes(KeepNodes, kv),
    LiveKVNodes = ns_cluster_membership:service_nodes(KeepNodes ++ EjectNodes, kv),

    case maybe_cleanup_old_buckets(KeepNodes) of
        ok ->
            ok;
        Error ->
            exit(Error)
    end,

    lists:foreach(fun ({I, {BucketName, BucketConfig}}) ->
                          BucketCompletion = I / NumBuckets,
                          update_kv_progress(LiveKVNodes, BucketCompletion),

                          ProgressFun = make_progress_fun(BucketCompletion, NumBuckets),
                          rebalance_bucket(BucketName, BucketConfig, ProgressFun,
                                           KeepKVNodes, EjectNodes, DeltaRecoveryBuckets)
                  end, misc:enumerate(BucketConfigs, 0)),

    update_kv_progress(LiveKVNodes, 1.0).

rebalance_bucket(BucketName, BucketConfig, ProgressFun,
                 KeepKVNodes, EjectNodes, DeltaRecoveryBuckets) ->
    ale:info(?USER_LOGGER, "Started rebalancing bucket ~s", [BucketName]),
    ?rebalance_info("Rebalancing bucket ~p with config ~p",
                    [BucketName, sanitize(BucketConfig)]),
    case proplists:get_value(type, BucketConfig) of
        memcached ->
            rebalance_memcached_bucket(BucketName, KeepKVNodes);
        membase ->
            rebalance_membase_bucket(BucketName, BucketConfig, ProgressFun,
                                     KeepKVNodes, EjectNodes, DeltaRecoveryBuckets)
    end.

rebalance_memcached_bucket(BucketName, KeepKVNodes) ->
    master_activity_events:note_bucket_rebalance_started(BucketName),
    ns_bucket:set_servers(BucketName, KeepKVNodes),
    master_activity_events:note_bucket_rebalance_ended(BucketName).

rebalance_membase_bucket(BucketName, BucketConfig, ProgressFun,
                         KeepKVNodes, EjectNodes, DeltaRecoveryBuckets) ->
    %% Only start one bucket at a time to avoid
    %% overloading things
    ThisEjected = ordsets:intersection(lists:sort(proplists:get_value(servers, BucketConfig, [])),
                                       lists:sort(EjectNodes)),
    ThisLiveNodes = KeepKVNodes ++ ThisEjected,
    ns_bucket:set_servers(BucketName, ThisLiveNodes),
    ?rebalance_info("Waiting for bucket ~p to be ready on ~p", [BucketName, ThisLiveNodes]),
    case janitor_agent:check_bucket_ready(BucketName, ThisLiveNodes,
                                          ?REBALANCER_READINESS_WAIT_TIMEOUT) of
        ready ->
            ?rebalance_info("Bucket is ready on all nodes"),
            ok;
        {_, Zombies} ->
            exit({not_all_nodes_are_ready_yet, Zombies})
    end,

    run_janitor_pre_rebalance(BucketName),

    {ok, NewConf} =
        ns_bucket:get_bucket(BucketName),
    master_activity_events:note_bucket_rebalance_started(BucketName),
    {NewMap, MapOptions} =
        do_rebalance_membase_bucket(BucketName, NewConf,
                                    KeepKVNodes, ProgressFun, DeltaRecoveryBuckets),
    ns_bucket:set_map_opts(BucketName, MapOptions),
    ns_bucket:update_bucket_props(BucketName,
                                  [{deltaRecoveryMap, undefined}]),
    master_activity_events:note_bucket_rebalance_ended(BucketName),
    verify_replication(BucketName, KeepKVNodes, NewMap).

run_janitor_pre_rebalance(BucketName) ->
    case ns_janitor:cleanup(BucketName,
                            [{query_states_timeout, ?REBALANCER_QUERY_STATES_TIMEOUT},
                             {apply_config_timeout, ?REBALANCER_APPLY_CONFIG_TIMEOUT}]) of
        ok ->
            ok;
        Error ->
            exit({pre_rebalance_janitor_run_failed, BucketName, Error})
    end.

%% @doc Rebalance the cluster. Operates on a single bucket. Will
%% either return ok or exit with reason 'stopped' or whatever reason
%% was given by whatever failed.
do_rebalance_membase_bucket(Bucket, Config,
                            KeepNodes, ProgressFun, DeltaRecoveryBuckets) ->
    Map = proplists:get_value(map, Config),
    AdjustedMap = case cluster_compat_mode:is_cluster_madhatter() of
                      true ->
                          NumReplicas = ns_bucket:num_replicas(Config),
                          mb_map:align_replicas(Map, NumReplicas);
                      false ->
                          %% Expect equal length map pre mad-hatter, as the
                          %% janitor fixes it for us.
                          %% See fun ns_janitor:compute_vbucket_map_fixup.
                          Map
                  end,
    {FastForwardMap, MapOptions} =
        case lists:keyfind(Bucket, 1, DeltaRecoveryBuckets) of
            false ->
                generate_vbucket_map(AdjustedMap, KeepNodes, Config);
            {_, _, V, _} ->
                V
        end,

    ns_bucket:update_vbucket_map_history(FastForwardMap, MapOptions),
    ?rebalance_debug("Target map options: ~p (hash: ~p)", [MapOptions, erlang:phash2(MapOptions)]),
    {run_mover(Bucket, Config, KeepNodes, ProgressFun, Map, FastForwardMap),
     MapOptions}.

run_mover(Bucket, Config, KeepNodes, ProgressFun, Map, FastForwardMap) ->
    Servers = ns_bucket:bucket_nodes(Config),

    %% At this point the server list must have already been updated to include
    %% all future nodes in addition to the old ones (some of which might be
    %% being removed).
    true = ((KeepNodes -- Servers) =:= []),

    ?rebalance_info("Target map (distance: ~p):~n~p", [(catch mb_map:vbucket_movements(Map, FastForwardMap)), FastForwardMap]),
    ns_bucket:set_fast_forward_map(Bucket, FastForwardMap),
    misc:with_trap_exit(
      fun () ->
              {ok, Pid} = ns_vbucket_mover:start_link(Bucket, Servers,
                                                      Map, FastForwardMap,
                                                      ProgressFun),
              wait_for_mover(Pid)
      end),

    HadRebalanceOut = ((Servers -- KeepNodes) =/= []),
    case HadRebalanceOut of
        true ->
            SecondsToWait = ns_config:read_key_fast(rebalance_out_delay_seconds, 10),
            ?rebalance_info("Waiting ~w seconds before completing rebalance out."
                            " So that clients receive graceful not my vbucket instead of silent closed connection", [SecondsToWait]),
            timer:sleep(SecondsToWait * 1000);
        false ->
            ok
    end,
    ns_bucket:set_fast_forward_map(Bucket, undefined),
    ns_bucket:set_servers(Bucket, KeepNodes),
    FastForwardMap.

unbalanced(Map, BucketConfig) ->
    Servers = proplists:get_value(servers, BucketConfig, []),
    NumServers = length(Servers),

    R = lists:any(
          fun (Chain) ->
                  lists:member(
                    undefined,
                    %% Don't warn about missing replicas when you have
                    %% fewer servers than your copy count!
                    lists:sublist(Chain, NumServers))
          end, Map),

    R orelse do_unbalanced(Map, Servers).

do_unbalanced(Map, Servers) ->
    {Masters, Replicas} =
        lists:foldl(
          fun ([M | R], {AccM, AccR}) ->
                  {[M | AccM], R ++ AccR}
          end, {[], []}, Map),
    Masters1 = lists:sort([M || M <- Masters, lists:member(M, Servers)]),
    Replicas1 = lists:sort([R || R <- Replicas, lists:member(R, Servers)]),

    MastersCounts = misc:uniqc(Masters1),
    ReplicasCounts = misc:uniqc(Replicas1),

    NumServers = length(Servers),

    lists:any(
      fun (Counts0) ->
              Counts1 = [C || {_, C} <- Counts0],
              Len = length(Counts1),
              Counts = case Len < NumServers of
                           true ->
                               lists:duplicate(NumServers - Len, 0) ++ Counts1;
                           false ->
                               true = Len =:= NumServers,
                               Counts1
                       end,
              Counts =/= [] andalso lists:max(Counts) - lists:min(Counts) > 1
      end, [MastersCounts, ReplicasCounts]).

map_options_changed(BucketConfig) ->
    Config = ns_config:get(),

    Servers = proplists:get_value(servers, BucketConfig, []),

    Opts = generate_vbucket_map_options(Servers, BucketConfig, Config),
    OptsHash = proplists:get_value(map_opts_hash, BucketConfig),
    case OptsHash of
        undefined ->
            true;
        _ ->
            erlang:phash2(Opts) =/= OptsHash
    end.

%%
%% Internal functions
%%

%% @private


%% @doc Eject a list of nodes from the cluster, making sure this node is last.
eject_nodes(Nodes) ->
    %% Leave myself last
    LeaveNodes = case lists:member(node(), Nodes) of
                     true ->
                         (Nodes -- [node()]) ++ [node()];
                     false ->
                         Nodes
                 end,
    lists:foreach(fun (N) ->
                          ns_cluster_membership:deactivate([N]),
                          ns_cluster:leave(N)
                  end, LeaveNodes).

verify_replication(Bucket, Nodes, Map) ->
    ExpectedReplicators0 = ns_bucket:map_to_replicas(Map),
    ExpectedReplicators = lists:sort(ExpectedReplicators0),

    {ActualReplicators, BadNodes} = janitor_agent:get_src_dst_vbucket_replications(Bucket, Nodes),
    case BadNodes of
        [] -> ok;
        _ ->
            ale:error(?USER_LOGGER, "Rebalance is done, but failed to verify replications on following nodes:~p", [BadNodes]),
            exit(bad_replicas_due_to_bad_results)
    end,

    ok = check_test_condition(verify_replication, Bucket),

    case misc:comm(ExpectedReplicators, ActualReplicators) of
        {[], [], _} ->
            ok;
        {Missing, Extra, _} ->
            ?user_log(?BAD_REPLICATORS,
                      "Bad replicators after rebalance:~nMissing = ~p~nExtras = ~p",
                      [Missing, Extra]),
            exit(bad_replicas)
    end.

wait_for_mover(Pid) ->
    receive
        {'EXIT', Pid, Reason} ->
            case Reason of
                normal ->
                    ok;
                {shutdown, stop} = Stop->
                    exit(Stop);
                _ ->
                    exit({mover_crashed, Reason})
            end;
        {'EXIT', _Pid, {shutdown, stop} = Stop} ->
            ?log_debug("Got rebalance stop request"),
            TimeoutPid = diag_handler:arm_timeout(
                           5000,
                           fun (_) ->
                                   ?log_debug("Observing slow rebalance stop (mover pid: ~p)", [Pid]),
                                   timeout_diag_logger:log_diagnostics(slow_rebalance_stop)
                           end),
            try
                exit(Pid, Stop),
                wait_for_mover(Pid)
            after
                diag_handler:disarm_timeout(TimeoutPid)
            end;
        {'EXIT', _Pid, Reason} ->
            exit(Reason)
    end.

maybe_cleanup_old_buckets(KeepNodes) ->
    case misc:rpc_multicall_with_plist_result(KeepNodes, ns_storage_conf, delete_unused_buckets_db_files, []) of
        {_, _, DownNodes} when DownNodes =/= [] ->
            ?rebalance_error("Failed to cleanup old buckets on some nodes: ~p",
                             [DownNodes]),
            {buckets_cleanup_failed, DownNodes};
        {Good, ReallyBad, []} ->
            ReallyBadNodes =
                case ReallyBad of
                    [] ->
                        [];
                    _ ->
                        ?rebalance_error(
                           "Failed to cleanup old buckets on some nodes: ~n~p",
                           [ReallyBad]),
                        lists:map(fun ({Node, _}) -> Node end, ReallyBad)
                end,

            FailedNodes =
                lists:foldl(
                  fun ({Node, Result}, Acc) ->
                          case Result of
                              ok ->
                                  Acc;
                              Error ->
                                  ?rebalance_error(
                                     "Failed to cleanup old buckets on node ~p: ~p",
                                     [Node, Error]),
                                  [Node | Acc]
                          end
                  end, [], Good),

            case FailedNodes ++ ReallyBadNodes of
                [] ->
                    ok;
                AllFailedNodes ->
                    {buckets_cleanup_failed, AllFailedNodes}
            end
    end.

node_vbuckets(Map, Node) ->
    [V || {V, Chain} <- misc:enumerate(Map, 0),
          lists:member(Node, Chain)].

find_delta_recovery_map(Config, AllNodes, DeltaNodes, Bucket, BucketConfig) ->
    {map, CurrentMap} = lists:keyfind(map, 1, BucketConfig),
    CurrentOptions = generate_vbucket_map_options(AllNodes, BucketConfig),

    History = ns_bucket:past_vbucket_maps(Config),
    MatchingMaps = mb_map:find_matching_past_maps(AllNodes, CurrentMap,
                                                  CurrentOptions, History),

    FailoverVBs = bucket_failover_vbuckets(Config, Bucket, DeltaNodes),
    case find_delta_recovery_map(CurrentMap, FailoverVBs, MatchingMaps) of
        not_found ->
            false;
        {ok, Map} ->
            {{Map, CurrentOptions}, FailoverVBs}
    end.

find_delta_recovery_map(CurrentMap, FailoverVBs, MatchingMaps) ->
    CurrentVBs = map_to_vbuckets_dict(CurrentMap),
    MergeFun   = ?cut(lists:umerge(_2, _3)),
    DesiredVBs = dict:merge(MergeFun, FailoverVBs, CurrentVBs),

    Pred = ?cut(compare_vb_dict(map_to_vbuckets_dict(_), DesiredVBs)),
    misc:find_by(Pred, MatchingMaps).

compare_vb_dict(D1, D2) ->
    lists:sort(dict:to_list(D1)) =:= lists:sort(dict:to_list(D2)).


map_to_vbuckets_dict(Map) ->
    lists:foldr(
      fun ({V, Chain}, Acc) ->
              lists:foldl(fun (N, D) ->
                                  misc:dict_update(N, [V|_], [], D)
                          end,
                          Acc, lists:filter(_ =/= undefined, Chain))
      end, dict:new(), misc:enumerate(Map, 0)).

node_failover_vbuckets(Config, Node) ->
    ns_config:search(Config, {node, Node, failover_vbuckets}, []).

bucket_failover_vbuckets(Config, Bucket, DeltaNodes) ->
    dict:from_list(
      lists:map(
        fun (Node) ->
                VBs = proplists:get_value(Bucket,
                                          node_failover_vbuckets(Config, Node),
                                          []),
                {Node, lists:usort(VBs)}
        end, DeltaNodes)).

membase_delta_recovery_buckets(DeltaRecoveryBuckets, MembaseBucketConfigs) ->
    MembaseBuckets = [Bucket || {Bucket, _} <- MembaseBucketConfigs],

    case DeltaRecoveryBuckets of
        all ->
            MembaseBuckets;
        _ when is_list(DeltaRecoveryBuckets) ->
            ordsets:to_list(ordsets:intersection(ordsets:from_list(MembaseBuckets),
                                                 ordsets:from_list(DeltaRecoveryBuckets)))
    end.

build_delta_recovery_buckets(_AllNodes, [] = _DeltaNodes, _AllBucketConfigs, _DeltaRecoveryBuckets) ->
    {ok, []};
build_delta_recovery_buckets(AllNodes, DeltaNodes, AllBucketConfigs, DeltaRecoveryBuckets0) ->
    Config = ns_config:get(),

    MembaseBuckets = [P || {_, BucketConfig} = P <- AllBucketConfigs,
                           proplists:get_value(type, BucketConfig) =:= membase],
    DeltaRecoveryBuckets = membase_delta_recovery_buckets(DeltaRecoveryBuckets0, MembaseBuckets),

    %% such non-lazy computation of recovery map is suboptimal, but
    %% it's not that big deal suboptimal. I'm doing it for better
    %% testability of build_delta_recovery_buckets_loop
    MappedConfigs = [{Bucket,
                      BucketConfig,
                      find_delta_recovery_map(Config, AllNodes, DeltaNodes,
                                              Bucket, BucketConfig)}
                     || {Bucket, BucketConfig} <- MembaseBuckets],

    case build_delta_recovery_buckets_loop(MappedConfigs, DeltaRecoveryBuckets, []) of
        {ok, Recovered0} ->
            RV = [{Bucket,
                   build_transitional_bucket_config(BucketConfig, Map, Opts, DeltaNodes),
                   {Map, Opts},
                   FailoverVBs}
                  || {Bucket,
                      BucketConfig,
                      {{Map, Opts}, FailoverVBs}} <- Recovered0],
            {ok, RV};
        Error ->
            Error
    end.

build_delta_recovery_buckets_loop([] = _MappedConfigs, _DeltaRecoveryBuckets, Acc) ->
    {ok, Acc};
build_delta_recovery_buckets_loop(MappedConfigs, DeltaRecoveryBuckets, Acc) ->
    [{Bucket, BucketConfig, RecoverResult0} | RestMapped] = MappedConfigs,

    NeedBucket = lists:member(Bucket, DeltaRecoveryBuckets),
    RecoverResult = case NeedBucket andalso
                         not ns_bucket:replica_change(BucketConfig) of
                        true ->
                            RecoverResult0;
                        false ->
                            false
                    end,
    case RecoverResult of
        {MapOpts, _FailoverVBs} ->
            ?rebalance_debug("Found delta recovery map for bucket ~s: ~p",
                             [Bucket, MapOpts]),

            NewAcc = [{Bucket, BucketConfig, RecoverResult} | Acc],
            build_delta_recovery_buckets_loop(RestMapped, DeltaRecoveryBuckets, NewAcc);
        false ->
            case NeedBucket of
                true ->
                    ?rebalance_debug("Couldn't delta recover bucket ~s when we care about delta recovery of that bucket", [Bucket]),
                    %% run rest of elements for logging
                    _ = build_delta_recovery_buckets_loop(RestMapped, DeltaRecoveryBuckets, []),
                    {error, not_possible};
                false ->
                    build_delta_recovery_buckets_loop(RestMapped, DeltaRecoveryBuckets, Acc)
            end
    end.

apply_delta_recovery_buckets([], _DeltaNodes, _CurrentBuckets) ->
    ok;
apply_delta_recovery_buckets(DeltaRecoveryBuckets, DeltaNodes, CurrentBuckets) ->
    Buckets = [Bucket || {Bucket, _, _, _} <- DeltaRecoveryBuckets],
    prepare_delta_recovery(DeltaNodes, Buckets),

    lists:foreach(
      fun ({Bucket, BucketConfig, _, FailoverVBuckets}) ->
              prepare_delta_recovery_bucket(Bucket,
                                            BucketConfig, FailoverVBuckets)
      end, DeltaRecoveryBuckets),

    NewBuckets = misc:update_proplist(
                   CurrentBuckets,
                   [{Bucket, BucketConfig} ||
                       {Bucket, BucketConfig, _, _} <- DeltaRecoveryBuckets]),
    NodeChanges = [[{{node, N, failover_vbuckets}, []},
                    {{node, N, membership}, active}] || N <- DeltaNodes],
    BucketChanges = {buckets, [{configs, NewBuckets}]},

    Changes = lists:flatten([BucketChanges, NodeChanges]),
    ok = ns_config:set(Changes),

    case ns_config_rep:ensure_config_seen_by_nodes(DeltaNodes) of
        ok ->
            cool;
        {error, SyncFailedNodes} ->
            exit({delta_recovery_config_synchronization_failed, SyncFailedNodes})
    end,

    complete_delta_recovery(DeltaNodes),

    ok = check_test_condition(apply_delta_recovery),
    lists:foreach(
      fun ({Bucket, BucketConfig, _, _}) ->
              ok = wait_for_bucket(Bucket, DeltaNodes),
              ok = ns_janitor:cleanup_apply_config(
                     Bucket, DeltaNodes, BucketConfig,
                     [{apply_config_timeout, ?REBALANCER_APPLY_CONFIG_TIMEOUT}])
      end, DeltaRecoveryBuckets),

    ok.

maybe_clear_recovery_type(Nodes) ->
    NodeChanges = [[{{node, N, recovery_type}, none},
                    {{node, N, failover_vbuckets}, []}]
                   || N <- Nodes],
    ok = ns_config:set(lists:flatten(NodeChanges)).

wait_for_bucket(Bucket, Nodes) ->
    ?log_debug("Waiting until bucket ~p gets ready on nodes ~p", [Bucket, Nodes]),
    do_wait_for_bucket(Bucket, Nodes).

do_wait_for_bucket(Bucket, Nodes) ->
    case janitor_agent:check_bucket_ready(Bucket, Nodes, 60000) of
        ready ->
            ?log_debug("Bucket ~p became ready on nodes ~p", [Bucket, Nodes]),
            ok;
        {warming_up, Zombies} ->
            ?log_debug("Bucket ~p still not ready on nodes ~p",
                       [Bucket, Zombies]),
            do_wait_for_bucket(Bucket, Zombies);
        {failed, Zombies} ->
            ?log_error("Bucket ~p not available on nodes ~p",
                       [Bucket, Zombies]),
            fail
    end.

build_transitional_bucket_config(BucketConfig, TargetMap, Options, DeltaNodes) ->
    {num_replicas, NumReplicas} = lists:keyfind(num_replicas, 1, BucketConfig),
    {map, CurrentMap} = lists:keyfind(map, 1, BucketConfig),
    {servers, Servers} = lists:keyfind(servers, 1, BucketConfig),
    TransitionalMap =
        lists:map(
          fun ({CurrentChain, TargetChain}) ->
                  case CurrentChain of
                      [undefined | _] ->
                          CurrentChain;
                      _ ->
                          ChainDeltaNodes = [N || N <- TargetChain,
                                                  lists:member(N, DeltaNodes)],
                          PreservedNodes = lists:takewhile(
                                             fun (N) ->
                                                     N =/= undefined andalso
                                                         not lists:member(N, DeltaNodes)
                                             end, CurrentChain),

                          TransitionalChain0 = PreservedNodes ++ ChainDeltaNodes,
                          N = length(TransitionalChain0),
                          true = N =< NumReplicas + 1,

                          TransitionalChain0 ++
                              lists:duplicate(NumReplicas - N + 1, undefined)
                  end
          end, lists:zip(CurrentMap, TargetMap)),

    NewServers = DeltaNodes ++ Servers,

    misc:update_proplist(BucketConfig, [{map, TransitionalMap},
                                        {servers, NewServers},
                                        {deltaRecoveryMap, {TargetMap, Options}}]).

get_delta_recovery_nodes(Config, Nodes) ->
    [N || N <- Nodes,
          ns_cluster_membership:get_cluster_membership(N, Config) =:= inactiveAdded
              andalso ns_cluster_membership:get_recovery_type(Config, N) =:= delta].

start_link_graceful_failover(Nodes) ->
    proc_lib:start_link(erlang, apply, [fun run_graceful_failover/1, [Nodes]]).

run_graceful_failover(Nodes) ->
    pull_and_push_config(ns_node_disco:nodes_wanted()),

    case check_failover_possible(Nodes) of
        ok ->
            ok;
        Error ->
            erlang:exit(Error)
    end,

    AllBucketConfigs = ns_bucket:get_buckets(),
    InterestingBuckets = [BC || BC = {_, Conf} <- AllBucketConfigs,
                                proplists:get_value(type, Conf) =:= membase,
                                %% when bucket doesn't have a vbucket map,
                                %% there's not much to do with respect to
                                %% graceful failover; so we skip these;
                                %%
                                %% note, that failover will still operate on
                                %% these buckets and, if needed, will remove
                                %% the node from server list
                                proplists:get_value(map, Conf, []) =/= []],
    NumBuckets = length(InterestingBuckets),

    case check_graceful_failover_possible(Nodes, InterestingBuckets) of
        true -> ok;
        {false, Type} ->
            erlang:exit(Type)
    end,
    proc_lib:init_ack({ok, self()}),

    ok = leader_activities:run_activity(
           graceful_failover, majority,
           fun () ->
                   ale:info(?USER_LOGGER,
                            "Starting vbucket moves for "
                            "graceful failover of ~p", [Nodes]),

                   lists:foldl(
                     fun ({BucketName, BucketConfig}, I) ->
                             do_run_graceful_failover_moves(Nodes,
                                                            BucketName,
                                                            BucketConfig,
                                                            I / NumBuckets,
                                                            NumBuckets),
                             I+1
                     end, 0, InterestingBuckets),
                   ok = orchestrate_failover(Nodes, []),

                   ok
           end).

do_run_graceful_failover_moves(Nodes, BucketName, BucketConfig, I, N) ->
    run_janitor_pre_rebalance(BucketName),

    Map = proplists:get_value(map, BucketConfig, []),
    Map1 = mb_map:promote_replicas_for_graceful_failover(Map, Nodes),

    ActiveNodes = ns_cluster_membership:active_nodes(),
    InvolvedNodes = ns_cluster_membership:service_nodes(ActiveNodes, kv),
    master_activity_events:note_rebalance_stage_started(kv, InvolvedNodes),
    ProgressFun = make_progress_fun(I, N),
    RV = run_mover(BucketName, BucketConfig,
                   proplists:get_value(servers, BucketConfig),
                   ProgressFun, Map, Map1),
    master_activity_events:note_rebalance_stage_completed(kv),
    RV.

check_graceful_failover_possible(Nodes, BucketsAll) ->
    %% No graceful failovers for non KV node
    case lists:all(?cut(lists:member(kv, ns_cluster_membership:node_services(_))),
                   Nodes) of
        true ->
            check_graceful_failover_possible_rec(Nodes, BucketsAll);
        false ->
            {false, non_kv_node}
    end.

check_graceful_failover_possible_rec(_Nodes, []) ->
    true;
check_graceful_failover_possible_rec(Nodes, [{_BucketName, BucketConfig} | RestBucketConfigs]) ->
    Map = proplists:get_value(map, BucketConfig, []),
    Servers = proplists:get_value(servers, BucketConfig, []),
    case lists:any(lists:member(_, Servers), Nodes) of
        true ->
            Map1 = mb_map:promote_replicas_for_graceful_failover(Map, Nodes),
            %% Do not allow graceful failover if the returned map, Map1, has any
            %% of the nodes to be removed as the head of Chain in vbucket map.
            case lists:any(?cut(lists:member(hd(_), Nodes)), Map1) of
                true ->
                    {false, not_graceful};
                false ->
                    check_graceful_failover_possible_rec(Nodes, RestBucketConfigs)
            end;
        false ->
            check_graceful_failover_possible_rec(Nodes, RestBucketConfigs)
    end.

check_failover_possible(Nodes) ->
    ActiveNodes = lists:sort(ns_cluster_membership:active_nodes()),
    FailoverNodes = lists:sort(Nodes),
    case ActiveNodes of
        FailoverNodes ->
            last_node;
        _ ->
            case lists:subtract(FailoverNodes, ActiveNodes) of
                [] ->
                    case ns_cluster_membership:service_nodes(ActiveNodes, kv) of
                        FailoverNodes ->
                            last_node;
                        _ ->
                            ok
                    end;
                _ ->
                    unknown_node
            end
    end.

drop_old_2i_indexes(KeepNodes) ->
    Config = ns_config:get(),
    NewNodes = KeepNodes -- ns_cluster_membership:active_nodes(Config),
    %% Only delta recovery is supported for index service.
    %% Note that if a node is running both KV and index service,
    %% and if user selects the full recovery option for such
    %% a node, then recovery_type will be set to full.
    %% But, we will treat delta and full recovery the same for
    %% the index data.
    %% Also, delta recovery for index service is different
    %% from that for the KV service. In case of index, it just
    %% means that we will not drop the indexes and their meta data.
    CleanupNodes = [N || N <- NewNodes,
                         ns_cluster_membership:get_recovery_type(Config, N) =:= none],
    ?rebalance_info("Going to drop possible old 2i indexes on nodes ~p",
                    [CleanupNodes]),
    {Oks, RPCErrors, Downs} = misc:rpc_multicall_with_plist_result(
                                CleanupNodes,
                                ns_storage_conf, delete_old_2i_indexes, []),
    RecoveryNodes = NewNodes -- CleanupNodes,
    ?rebalance_info("Going to keep possible 2i indexes on nodes ~p",
                    [RecoveryNodes]),
    %% Clear recovery type for non-KV nodes here.
    %% recovery_type for nodes running KV services gets cleared later.
    NonKV = [N || N <- RecoveryNodes,
                  not lists:member(kv, ns_cluster_membership:node_services(Config, N))],
    NodeChanges = [[{{node, N, recovery_type}, none},
                    {{node, N, membership}, active}] || N <- NonKV],
    ok = ns_config:set(lists:flatten(NodeChanges)),
    Errors = [{N, RV}
              || {N, RV} <- Oks,
                 RV =/= ok]
        ++ RPCErrors
        ++ [{N, node_down} || N <- Downs],
    case Errors of
        [] ->
            ?rebalance_debug("Cleanup succeeded: ~p", [Oks]),
            ok;
        _ ->
            ?rebalance_error("Failed to cleanup indexes: ~p", [Errors]),
            {old_indexes_cleanup_failed, Errors}
    end.

%%
%% Check whether user wants us to fail or delay the specified step
%% during rebalance.
%%
%% There are following 3 types of rebalance test conditions:
%%  1. Applicable to a bucket or service. E.g. the service_rebalance_start
%%      test condition can be used to fail or delay the start of rebalance
%%      of any topology aware service.
%%  2. Applicable to certain step during vBucket move for specified bucket.
%%  3. Applicable to entire rebalance. E.g. delay rebalance at the start.
%%
%% The delay can be used to inject other failures. E.g. Introduce a delay
%% of 60s during rebalance of a bucket. During those 60s, user can
%% SIGSTOP memcached on a node.
%%
%% 'Kind' can be a bucket or a service.
%%
check_test_condition(Step) ->
    check_test_condition(Step, []).

check_test_condition(Step, Kind) ->
    case testconditions:get(Step) of
        fail ->
            %% E.g. fail rebalance at the start.
            %% Triggered by: testconditions:set(rebalance_start, fail)
            trigger_failure(Step, []);
        {delay, Sleep} ->
            %% E.g. delay rebalance by 60s at the start.
            %% Triggered by:
            %%  testconditions:set(rebalance_start, {delay, 60000})
            trigger_delay(Step, [], Sleep);
        {fail, Kind} ->
            %% E.g. fail verify_replication for bucket "test".
            %% Triggered by:
            %%  testconditions:set(verify_replication, {fail, “test”})
            trigger_failure(Step, Kind);
        {delay, Kind, Sleep} ->
            %% E.g. delay service_rebalance_start by 1s for index service.
            %% Triggered by:
            %%  testconditions:set(service_rebalance_start,
            %%                     {delay, index, 1000})
            trigger_delay(Step, Kind, Sleep);
        {for_vb_move, Kind, N, Condition} ->
            %% Trigger the test condition for Nth vBucket move.
            %% Note it is NOT vBucket #N, but rather the Nth vBucket
            %% that is being moved. The actual vBucket # may be anything.
            %% This is done because generally rebalance does not move all
            %% vBuckets and normally users don’t know which vBuckets will
            %% move during a particular rebalance.
            %% E.g. during a rebalance, users may not know whether
            %% vBucket #678 will move. So, instead they can set the
            %% test condition to fail rebalance during say 10th vBucket move.
            %% The 10th vBucket to move may be any vBucket e.g. vBucket #348.
            %% E.g. fail rebalance after backfill for 5th vBucket,
            %% bucket "test".
            %% Triggered by:
            %%  testconditions:set(backfill_done,
            %%                     {for_vb_move, "test", 5, fail}).
            trigger_condition_for_Nth_move(Step, Kind, N, Condition);
        _ ->
            ok
    end.

trigger_failure(Step, Kind) ->
    Msg = case Kind of
              [] ->
                  io_lib:format("Failure triggered by test during ~p", [Step]);
              _ ->
                  io_lib:format("Failure triggered by test during ~p for ~p",
                                [Step, Kind])
          end,
    ?rebalance_error("~s", [lists:flatten(Msg)]),
    testconditions:delete(Step),
    fail_by_test_condition.

trigger_delay(Step, Kind, Sleep) ->
    Msg = case Kind of
              [] ->
                  io_lib:format("Delay triggered by test during ~p. "
                                "Sleeping for ~p ms", [Step, Sleep]);
              _ ->
                  io_lib:format("Delay triggered by test during ~p for ~p. "
                                "Sleeping for ~p ms", [Step, Kind, Sleep])
          end,
    ?rebalance_error("~s", [lists:flatten(Msg)]),
    testconditions:delete(Step),
    timer:sleep(Sleep).

trigger_condition_for_Nth_move(Step, Kind, 1, Condition) ->
    case Condition of
        fail ->
            trigger_failure(Step, Kind);
        {delay, Sleep} ->
            trigger_delay(Step, Kind, Sleep)
    end;
trigger_condition_for_Nth_move(Step, Kind, N, Condition) ->
    testconditions:set(Step, {for_vb_move, Kind, N - 1, Condition}).


-ifdef(TEST).
find_delta_recovery_map_test() ->
    Map = [[b, undefined],
           [b, undefined],
           [b, undefined],
           [b, c],
           [c, b],
           [c, b],
           [d, c],
           [d, c]],
    FailoverVBs = dict:from_list([{a, [0, 1, 2]}]),

    Matching = [[a, b],
                [a, b],
                [b, a],
                [b, c],
                [c, b],
                [c, b],
                [d, c],
                [d, c]],

    NonMatching1 = [[a, b],
                    [a, b],
                    [b, a],
                    [b, a],
                    [c, b],
                    [c, b],
                    [d, c],
                    [d, c]],

    NonMatching2 = [[a, b],
                    [a, b],
                    [b, a],
                    [b, c],
                    [c, b],
                    [c, b],
                    [d, b],
                    [d, b]],

    {ok, Matching} = find_delta_recovery_map(Map, FailoverVBs, [Matching]),

    not_found = find_delta_recovery_map(Map, FailoverVBs, [NonMatching1]),
    not_found = find_delta_recovery_map(Map, FailoverVBs, [NonMatching2]),
    not_found = find_delta_recovery_map(Map, FailoverVBs,
                                        [NonMatching1, NonMatching2]),

    {ok, Matching} = find_delta_recovery_map(Map, FailoverVBs,
                                             [NonMatching1,
                                              Matching, NonMatching2]),

    %% This test is essentially for compare_vb_dict, and this fun was
    %% introduced as dict's don't support proper comparison, i.e., D1 =:= D2
    %% is not an accurate comparison.
    Map2 = [['n_0@10.17.2.22', 'n_1@127.0.0.1'],
            ['n_0@10.17.2.22', 'n_2@127.0.0.1'],
            ['n_1@127.0.0.1', 'n_0@10.17.2.22'],
            ['n_1@127.0.0.1', undefined],
            ['n_2@127.0.0.1', 'n_0@10.17.2.22'],
            ['n_2@127.0.0.1', undefined],
            ['n_1@127.0.0.1', undefined],
            ['n_2@127.0.0.1', undefined]],
    MatchingMaps = [['n_0@10.17.2.22', 'n_1@127.0.0.1'],
                    ['n_0@10.17.2.22', 'n_2@127.0.0.1'],
                    ['n_1@127.0.0.1', 'n_0@10.17.2.22'],
                    ['n_1@127.0.0.1', 'n_3@127.0.0.1'],
                    ['n_2@127.0.0.1', 'n_0@10.17.2.22'],
                    ['n_2@127.0.0.1', 'n_3@127.0.0.1'],
                    ['n_3@127.0.0.1', 'n_1@127.0.0.1'],
                    ['n_3@127.0.0.1', 'n_2@127.0.0.1']],
    FailoverVBs2 = dict:from_list([{'n_3@127.0.0.1', [3, 5, 6, 7]}]),
    {ok, MatchingMaps} = find_delta_recovery_map(Map2, FailoverVBs2, [MatchingMaps]).

compare_vb_dict_test() ->
    List1 = [{aa2, [0, 1, 2]}, {c, [0, 1, 2]}, {aa1, [0, 1, 2]}],
    List2 = [{aa3, [0, 1, 2]}],

    D1 = dict:from_list(List1),
    D2 = dict:from_list(List2),
    DMerge = dict:merge(fun (_K, _V1, _V2) -> [] end, D1, D2),

    ListAll = lists:sort(List1 ++ List2),
    DAll = dict:from_list(ListAll),

    ?assertEqual(false, DAll =:= DMerge),
    ?assertEqual(true, compare_vb_dict(DAll,DMerge)).

map_to_vbuckets_dict_test() ->
    Map = [[a, b],
           [a, b],
           [b, a],
           [b, c],
           [c, b],
           [c, b]],
    ?assertEqual([{a, [0, 1, 2]},
                  {b, [0, 1, 2, 3, 4, 5]},
                  {c, [3, 4, 5]}],
                 lists:sort(dict:to_list(map_to_vbuckets_dict(Map)))).

membase_delta_recovery_buckets_test() ->
    MembaseBuckets = [{"b1", conf}, {"b3", conf}],
    ["b1", "b3"] = membase_delta_recovery_buckets(["b1", "b2", "b3", "b4"], MembaseBuckets),
    ["b1", "b3"] = membase_delta_recovery_buckets(all, MembaseBuckets).

build_delta_recovery_buckets_loop_test() ->
    %% Fake num_replicas so that we don't crash in
    %% build_delta_recovery_buckets_loop.
    Conf1 = [{num_replicas, 1}, conf1],
    Conf2 = [{num_replicas, 1}, conf2],
    MappedConfigs = [{"b1", Conf1, {map, opts}},
                     {"b2", Conf2, false}],
    All = membase_delta_recovery_buckets(all, [{"b1", conf}, {"b2", conf}]),

    {ok, []} = build_delta_recovery_buckets_loop([], All, []),
    {error, not_possible} = build_delta_recovery_buckets_loop(MappedConfigs, All, []),
    {error, not_possible} = build_delta_recovery_buckets_loop(MappedConfigs, ["b2"], []),
    {error, not_possible} = build_delta_recovery_buckets_loop(MappedConfigs, ["b1", "b2"], []),
    {ok, []} = build_delta_recovery_buckets_loop(MappedConfigs, [], []),
    ?assertEqual({ok, [{"b1", Conf1, {map, opts}}]},
                 build_delta_recovery_buckets_loop(MappedConfigs, ["b1"], [])),
    ?assertEqual({ok, [{"b1", Conf1, {map, opts}}]},
                 build_delta_recovery_buckets_loop([hd(MappedConfigs)], All, [])).
-endif.

prepare_rebalance(Nodes) ->
    case cluster_compat_mode:is_cluster_madhatter() of
        true ->
            do_prepare_rebalance(Nodes);
        false ->
            ok
    end.

do_prepare_rebalance(Nodes) ->
    case rebalance_agent:prepare_rebalance(Nodes, self()) of
        ok ->
            ok;
        Error ->
            exit({prepare_rebalance_failed, Error})
    end.

unprepare_rebalance(Nodes) ->
    case cluster_compat_mode:is_cluster_madhatter() of
        true ->
            do_unprepare_rebalance(Nodes);
        false ->
            ok
    end.

do_unprepare_rebalance(Nodes) ->
    case rebalance_agent:unprepare_rebalance(Nodes, self()) of
        ok ->
            ok;
        Error ->
            ?log_error("Failed to reach rebalance_agent on "
                       "some nodes to cleanup after reblance: ~p",
                       [Error])
    end.

prepare_delta_recovery(Nodes, Buckets) ->
    case cluster_compat_mode:is_cluster_madhatter() of
        true ->
            do_prepare_delta_recovery(Nodes, Buckets);
        false ->
            ok
    end.

do_prepare_delta_recovery(Nodes, Buckets) ->
    case rebalance_agent:prepare_delta_recovery(Nodes, self(), Buckets) of
        ok ->
            ok;
        Errors ->
            ?log_error("Failed to prepare delta "
                       "recovery for bucket ~p on some nodes:~n~p",
                       [Buckets, Errors]),
            exit({prepare_delta_recovery_failed, Buckets, Errors})
    end.

prepare_delta_recovery_bucket(Bucket, BucketConfig, FailoverVBuckets) ->
    case cluster_compat_mode:is_cluster_madhatter() of
        true ->
            do_prepare_delta_recovery_bucket(Bucket, BucketConfig,
                                             FailoverVBuckets);
        false ->
            ok
    end.

do_prepare_delta_recovery_bucket(Bucket, BucketConfig, FailoverVBuckets) ->
    Map = proplists:get_value(map, BucketConfig, []),
    VBucketsToRecover =
        dict:fold(
          fun (_Node, VBuckets, Acc) ->
                  sets:union(sets:from_list(VBuckets), Acc)
          end, sets:new(), FailoverVBuckets),

    ?log_debug("Going to get failover logs for delta recovery.~n"
               "Bucket: ~p~n"
               "VBuckets: ~p",
               [Bucket, sets:to_list(VBucketsToRecover)]),
    FailoverLogs = get_active_failover_logs(Bucket, Map, VBucketsToRecover),
    ?log_debug("Got the following failover logs:~n~p", [FailoverLogs]),

    FailoverVBucketsList = dict:to_list(FailoverVBuckets),
    ?log_debug("Going to prepare bucket ~p on some nodes for delta recovery.~n"
               "Nodes: ~p",
               [Bucket, FailoverVBucketsList]),
    case rebalance_agent:prepare_delta_recovery_bucket(
           self(), Bucket, FailoverVBucketsList, FailoverLogs) of
        ok ->
            Nodes = dict:fetch_keys(FailoverVBuckets),
            ?log_debug("Prepared bucket ~p for delta "
                       "recovery on ~p successfully.", [Bucket, Nodes]);
        Errors ->
            ?log_error("Failed to prepare bucket ~p for delta recovery "
                       "on some nodes:~n~p", [Bucket, Errors]),
            exit({prepare_delta_recovery_failed, Bucket, Errors})
    end.

get_active_failover_logs(Bucket, Map, VBucketsSet) ->
    NodeVBuckets0   = find_active_nodes_of_vbuckets(Map, VBucketsSet),
    MissingVBuckets = maps:get(undefined, NodeVBuckets0, []),

    NodeVBuckets = maps:to_list(maps:remove(undefined, NodeVBuckets0)),
    case janitor_agent:get_failover_logs(Bucket, NodeVBuckets) of
        {ok, FailoverLogs} ->
            Result = maps:from_list([{V, missing} || V <- MissingVBuckets]),
            lists:foldl(
              fun ({_Node, NodeFailoverLogs}, Acc) ->
                      maps:merge(Acc, maps:from_list(NodeFailoverLogs))
              end, Result, FailoverLogs);
        Errors ->
            ?log_error("Failed to get failover logs "
                       "from some nodes for delta recovery.~n"
                       "Bucket: ~p~n"
                       "Requests: ~p~n"
                       "Errors: ~p",
                       [Bucket, NodeVBuckets, Errors]),
            exit({get_failover_logs_failed, Bucket, NodeVBuckets, Errors})
    end.

find_active_nodes_of_vbuckets(Map, VBucketsSet) ->
    lists:foldl(
      fun ({VBucket, [Active|_]}, Acc) ->
              case sets:is_element(VBucket, VBucketsSet) of
                  true ->
                      maps:update_with(Active, [VBucket | _], [VBucket], Acc);
                  false ->
                      Acc
              end
      end, #{}, misc:enumerate(Map, 0)).

-ifdef(TEST).
find_active_nodes_of_vbuckets_test() ->
    Map = [[a, b],
           [b, a],
           [a, b],
           [undefined, undefined]],

    SortMap = ?cut(maps:map(?cut(lists:sort(_2)), _)),

    ?assertEqual(#{ a => [0, 2],
                    b => [1],
                    undefined => [3] },
                 SortMap(find_active_nodes_of_vbuckets(
                           Map, sets:from_list([0, 1, 2, 3])))),

    ?assertEqual(#{ a => [0],
                    b => [1],
                    undefined => [3] },
                 SortMap(find_active_nodes_of_vbuckets(
                           Map, sets:from_list([0, 1, 3])))),


    ?assertEqual(#{ a => [0, 2] },
                 SortMap(find_active_nodes_of_vbuckets(
                           Map, sets:from_list([0, 2])))).
-endif.

complete_delta_recovery(Nodes) ->
    case cluster_compat_mode:is_cluster_madhatter() of
        true ->
            do_complete_delta_recovery(Nodes);
        false ->
            ok
    end.

do_complete_delta_recovery(Nodes) ->
    ?log_debug("Going to complete delta "
               "recovery preparation on nodes ~p", [Nodes]),
    case rebalance_agent:complete_delta_recovery(Nodes, self()) of
        ok ->
            ?log_debug("Delta recovery preparation completed.");
        Errors ->
            ?log_error("Failed to complete delta recovery "
                       "preparation on some nodes:~n~p", [Errors]),
            exit({complete_delta_recovery_failed, Errors})
    end.
