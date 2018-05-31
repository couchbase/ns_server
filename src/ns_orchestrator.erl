%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-2018 Couchbase, Inc.
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
-module(ns_orchestrator).

-behaviour(gen_statem).

-include("ns_common.hrl").

%% Constants and definitions

-record(idle_state, {}).
-record(janitor_state, {cleanup_id = undefined :: undefined | pid()}).

-record(rebalancing_state, {rebalancer,
                            progress,
                            keep_nodes,
                            eject_nodes,
                            failed_nodes,
                            stop_timer,
                            type}).

-record(recovery_state, {pid :: pid()}).


%% API
-export([create_bucket/3,
         update_bucket/4,
         delete_bucket/1,
         flush_bucket/1,
         failover/2,
         try_autofailover/1,
         needs_rebalance/0,
         request_janitor_run/1,
         rebalance_progress/0,
         rebalance_progress_full/0,
         rebalance_progress_full/1,
         start_link/0,
         start_rebalance/3,
         stop_rebalance/0,
         update_progress/2,
         is_rebalance_running/0,
         start_recovery/1,
         stop_recovery/2,
         commit_vbucket/3,
         recovery_status/0,
         recovery_map/2,
         is_recovery_running/0,
         ensure_janitor_run/1,
         start_graceful_failover/1]).

-define(SERVER, {via, leader_registry, ?MODULE}).

-define(DELETE_BUCKET_TIMEOUT,  ?get_timeout(delete_bucket, 30000)).
-define(FLUSH_BUCKET_TIMEOUT,   ?get_timeout(flush_bucket, 60000)).
-define(CREATE_BUCKET_TIMEOUT,  ?get_timeout(create_bucket, 5000)).
-define(JANITOR_RUN_TIMEOUT,    ?get_timeout(ensure_janitor_run, 30000)).
-define(JANITOR_INTERVAL,       ?get_param(janitor_interval, 5000)).
-define(STOP_REBALANCE_TIMEOUT, ?get_timeout(stop_rebalance, 60000)).

%% gen_statem callbacks
-export([code_change/4,
         init/1,
         callback_mode/0,
         handle_event/4,
         terminate/3]).

%% States
-export([idle/2, idle/3,
         janitor_running/2, janitor_running/3,
         rebalancing/2, rebalancing/3,
         recovery/2, recovery/3]).

%%
%% API
%%

start_link() ->
    misc:start_singleton(gen_statem, ?MODULE, [], []).

wait_for_orchestrator() ->
    misc:wait_for_global_name(?MODULE).


-spec create_bucket(memcached|membase, nonempty_string(), list()) ->
                           ok | {error, {already_exists, nonempty_string()}} |
                           {error, {still_exists, nonempty_string()}} |
                           {error, {port_conflict, integer()}} |
                           {error, {invalid_name, nonempty_string()}} |
                           rebalance_running | in_recovery.
create_bucket(BucketType, BucketName, NewConfig) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {create_bucket, BucketType, BucketName,
                              NewConfig}, infinity).

-spec update_bucket(memcached|membase, undefined|couchstore|ephemeral,
                    nonempty_string(), list()) ->
                           ok | {exit, {not_found, nonempty_string()}, []}
                               | rebalance_running.
update_bucket(BucketType, StorageMode, BucketName, UpdatedProps) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {update_bucket, BucketType,
                              StorageMode, BucketName,
                              UpdatedProps}, infinity).

%% Deletes bucket. Makes sure that once it returns it's already dead.
%% In implementation we make sure config deletion is propagated to
%% child nodes. And that ns_memcached for bucket being deleted
%% dies. But we don't wait more than ?DELETE_BUCKET_TIMEOUT.
%%
%% Return values are ok if it went fine at least on local node
%% (failure to stop ns_memcached on any nodes is merely logged);
%% rebalance_running if delete bucket request came while rebalancing;
%% and {exit, ...} if bucket does not really exists
-spec delete_bucket(bucket_name()) ->
                           ok | rebalance_running | in_recovery |
                           {shutdown_failed, [node()]} |
                           {exit, {not_found, bucket_name()}, _}.
delete_bucket(BucketName) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {delete_bucket, BucketName}, infinity).

-spec flush_bucket(bucket_name()) ->
                          ok |
                          rebalance_running |
                          in_recovery |
                          bucket_not_found |
                          flush_disabled |
                          {prepare_flush_failed, _, _} |
                          {initial_config_sync_failed, _} |
                          {flush_config_sync_failed, _} |
                          {flush_wait_failed, _, _} |
                          {old_style_flush_failed, _, _}.
flush_bucket(BucketName) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {flush_bucket, BucketName}, infinity).

-spec failover([node()], boolean()) ->
                      ok |
                      rebalance_running |
                      in_recovery |
                      last_node |
                      unknown_node |
                      orchestration_unsafe |
                      %% the following is needed just to trick the dialyzer;
                      %% otherwise it wouldn't let the callers cover what it
                      %% believes to be an impossible return value if all
                      %% other options are also covered
                      any().
failover(Nodes, AllowUnsafe) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {failover, Nodes, AllowUnsafe}, infinity).

-spec try_autofailover(list()) -> ok |
                                  rebalance_running |
                                  in_recovery |
                                  orchestration_unsafe |
                                  {autofailover_unsafe, [bucket_name()]}.
try_autofailover(Nodes) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {try_autofailover, Nodes}, infinity).

-spec needs_rebalance() -> boolean().
needs_rebalance() ->
    NodesWanted = ns_node_disco:nodes_wanted(),
    ServicesNeedRebalance =
        lists:any(fun (S) ->
                          service_needs_rebalance(S, NodesWanted)
                  end, ns_cluster_membership:cluster_supported_services()),
    ServicesNeedRebalance orelse buckets_need_rebalance(NodesWanted).

service_needs_rebalance(Service, NodesWanted) ->
    ServiceNodes = ns_cluster_membership:service_nodes(NodesWanted, Service),
    ActiveServiceNodes = ns_cluster_membership:service_active_nodes(Service),
    lists:sort(ServiceNodes) =/= lists:sort(ActiveServiceNodes) orelse
        topology_aware_service_needs_rebalance(Service, ActiveServiceNodes).

topology_aware_service_needs_rebalance(Service, ServiceNodes) ->
    case lists:member(Service,
                      ns_cluster_membership:topology_aware_services()) of
        true ->
            %% TODO: consider caching this
            Statuses = ns_doctor:get_nodes(),
            lists:any(
              fun (Node) ->
                      NodeStatus = misc:dict_get(Node, Statuses, []),
                      ServiceStatus =
                          proplists:get_value({service_status, Service},
                                              NodeStatus, []),
                      proplists:get_value(needs_rebalance, ServiceStatus, false)
              end, ServiceNodes);
        false ->
            false
    end.

-spec buckets_need_rebalance([node(), ...]) -> boolean().
buckets_need_rebalance(NodesWanted) ->
    KvNodes = ns_cluster_membership:service_nodes(NodesWanted, kv),
    lists:any(fun ({_, BucketConfig}) ->
                      ns_bucket:needs_rebalance(BucketConfig, KvNodes)
              end,
              ns_bucket:get_buckets()).

-spec rebalance_progress_full() -> {running, [{atom(), float()}]} | not_running.
rebalance_progress_full() ->
    gen_statem:call(?SERVER, rebalance_progress, 2000).

-spec rebalance_progress_full(non_neg_integer()) ->
                                     {running, [{atom(), float()}]} |
                                     not_running.
rebalance_progress_full(Timeout) ->
    gen_statem:call(?SERVER, rebalance_progress, Timeout).

-spec rebalance_progress() -> {running, [{atom(), float()}]} | not_running.
rebalance_progress() ->
    try rebalance_progress_full()
    catch
        Type:Err ->
            ?log_error("Couldn't talk to orchestrator: ~p", [{Type, Err}]),
            not_running
    end.


-spec request_janitor_run(janitor_item()) -> ok.
request_janitor_run(Item) ->
    gen_statem:cast(?SERVER, {request_janitor_run, Item}).

-spec ensure_janitor_run(janitor_item()) ->
                                ok |
                                in_recovery |
                                rebalance_running |
                                janitor_failed |
                                bucket_deleted.
ensure_janitor_run(Item) ->
    wait_for_orchestrator(),
    misc:poll_for_condition(
      fun () ->
              case gen_statem:call(?SERVER, {ensure_janitor_run, Item},
                                   infinity) of
                  warming_up ->
                      false;
                  interrupted ->
                      false;
                  Ret ->
                      Ret
              end
      end, ?JANITOR_RUN_TIMEOUT, 1000).

-spec start_rebalance([node()], [node()], all | [bucket_name()]) ->
                             ok | in_progress | already_balanced |
                             nodes_mismatch | no_active_nodes_left |
                             in_recovery | delta_recovery_not_possible |
                             no_kv_nodes_left.
start_rebalance(KnownNodes, EjectNodes, DeltaRecoveryBuckets) ->
    wait_for_orchestrator(),
    gen_statem:call(
      ?SERVER,
      {maybe_start_rebalance, KnownNodes, EjectNodes, DeltaRecoveryBuckets}).

-spec start_graceful_failover([node()]) ->
                                     ok | in_progress | in_recovery |
                                     non_kv_node | not_graceful | unknown_node |
                                     last_node | {config_sync_failed, any()} |
                                     %% the following is needed just to trick
                                     %% the dialyzer; otherwise it wouldn't
                                     %% let the callers cover what it believes
                                     %% to be an impossible return value if
                                     %% all other options are also covered
                                     any().
start_graceful_failover(Nodes) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {start_graceful_failover, Nodes}).

-spec stop_rebalance() -> ok | not_rebalancing.
stop_rebalance() ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, stop_rebalance).

-spec start_recovery(bucket_name()) ->
                            {ok, UUID, RecoveryMap} |
                            unsupported |
                            rebalance_running |
                            not_present |
                            not_needed |
                            {error, {failed_nodes, [node()]}}
                                when UUID :: binary(),
                                     RecoveryMap :: dict:dict().
start_recovery(Bucket) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {start_recovery, Bucket}).

-spec recovery_status() -> not_in_recovery | {ok, Status}
                               when Status :: [{bucket, bucket_name()} |
                                               {uuid, binary()} |
                                               {recovery_map, RecoveryMap}],
                                    RecoveryMap :: dict:dict().
recovery_status() ->
    case is_recovery_running() of
        false ->
            not_in_recovery;
        _ ->
            wait_for_orchestrator(),
            gen_statem:call(?SERVER, recovery_status)
    end.

-spec recovery_map(bucket_name(), UUID) -> bad_recovery | {ok, RecoveryMap}
                                               when RecoveryMap :: dict:dict(),
                                                    UUID :: binary().
recovery_map(Bucket, UUID) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {recovery_map, Bucket, UUID}).

-spec commit_vbucket(bucket_name(), UUID, vbucket_id()) ->
                            ok | recovery_completed |
                            vbucket_not_found | bad_recovery |
                            {error, {failed_nodes, [node()]}}
                                when UUID :: binary().
commit_vbucket(Bucket, UUID, VBucket) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {commit_vbucket, Bucket, UUID, VBucket}).

-spec stop_recovery(bucket_name(), UUID) -> ok | bad_recovery
                                                when UUID :: binary().
stop_recovery(Bucket, UUID) ->
    wait_for_orchestrator(),
    gen_statem:call(?SERVER, {stop_recovery, Bucket, UUID}).

-spec is_recovery_running() -> boolean().
is_recovery_running() ->
    recovery_server:is_recovery_running().

%%
%% gen_statem callbacks
%%

callback_mode() ->
    handle_event_function.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

init([]) ->
    process_flag(trap_exit, true),
    self() ! janitor,
    timer2:send_interval(?JANITOR_INTERVAL, janitor),

    consider_switching_compat_mode_dont_exit(),

    {ok, idle, #idle_state{}}.

%% In the mixed mode, depending upon the node from which the update bucket
%% request is being sent, the length of the message could vary. In order to
%% be backward compatible we need to field both types of messages.

handle_event({call, From}, {update_bucket, memcached, BucketName, UpdatedProps},
             _StateName, _State) ->
    {keep_state_and_data,
     [{next_event, {call, From},
       {update_bucket, memcached, undefined, BucketName, UpdatedProps}}]};

handle_event({call, From}, {update_bucket, membase, BucketName, UpdatedProps},
             _StateName, _State) ->
    {keep_state_and_data,
     [{next_event, {call, From},
       {update_bucket, membase, couchstore, BucketName, UpdatedProps}}]};

handle_event({call, From}, {update_bucket, _, _, _, _}, rebalancing, _State) ->
    {keep_state_and_data, [{reply, From, rebalance_running}]};

handle_event({call, From},
             {update_bucket, BucketType, StorageMode, BucketName, UpdatedProps},
             _StateName, _State) ->
    Reply = ns_bucket:update_bucket_props(BucketType, StorageMode,
                                          BucketName, UpdatedProps),
    case Reply of
        ok ->
            %% request janitor run to fix map if the replica # has changed
            request_janitor_run({bucket, BucketName});
        _ -> ok
    end,
    {keep_state_and_data, [{reply, From, Reply}]};

handle_event({call, From},
             {maybe_start_rebalance, KnownNodes, EjectedNodes,
              DeltaRecoveryBuckets},
             _StateName, _State) ->
    case {EjectedNodes -- KnownNodes,
          lists:sort(ns_node_disco:nodes_wanted()),
          lists:sort(KnownNodes)} of
        {[], X, X} ->
            Config = ns_config:get(),

            MaybeKeepNodes = KnownNodes -- EjectedNodes,
            FailedNodes =
                [N || N <- KnownNodes,
                      ns_cluster_membership:get_cluster_membership(N, Config)
                          =:= inactiveFailed],
            KeepNodes = MaybeKeepNodes -- FailedNodes,
            DeltaNodes = ns_rebalancer:get_delta_recovery_nodes(Config,
                                                                KeepNodes),
            case KeepNodes of
                [] ->
                    {keep_state_and_data,
                     [{reply, From, no_active_nodes_left}]};
                _ ->
                    case rebalance_allowed(Config) of
                        ok ->
                            StartEvent = {start_rebalance,
                                          KeepNodes,
                                          EjectedNodes -- FailedNodes,
                                          FailedNodes,
                                          DeltaNodes,
                                          DeltaRecoveryBuckets},
                            {keep_state_and_data,
                             [{next_event, {call, From}, StartEvent}]};
                        {error, Msg} ->
                            set_rebalance_status(rebalance, {none, Msg},
                                                 undefined),
                            {keep_state_and_data, [{reply, From, ok}]}
                    end
            end;
        _ ->
            {keep_state_and_data, [{reply, From, nodes_mismatch}]}
    end;

handle_event({call, From}, recovery_status, StateName, State) ->
    case StateName of
        recovery ->
            ?MODULE:recovery(recovery_status, From, State);
        _ ->
            {keep_state_and_data, [{reply, From, not_in_recovery}]}
    end;

handle_event({call, From}, Msg, StateName, State)
  when element(1, Msg) =:= recovery_map;
       element(1, Msg) =:= commit_vbucket;
       element(1, Msg) =:= stop_recovery ->
    case StateName of
        recovery ->
            ?MODULE:recovery(Msg, From, State);
        _ ->
            {keep_state_and_data, [{reply, From, bad_recovery}]}
    end;

handle_event(info, Event, StateName, StateData)->
    handle_info(Event, StateName, StateData);
handle_event(cast, Event, StateName, StateData) ->
    ?MODULE:StateName(Event, StateData);
handle_event({call, From}, Event, StateName, StateData) ->
    ?MODULE:StateName(Event, From, StateData).

handle_info(janitor, idle, _State) ->
    misc:verify_name(?MODULE), % MB-3180: Make sure we're still registered
    consider_switching_compat_mode(),
    {ok, ID} = ns_janitor_server:start_cleanup(
                 fun(Pid, UnsafeNodes, CleanupID) ->
                         Pid ! {cleanup_done, UnsafeNodes, CleanupID},
                         ok
                 end),
    {next_state, janitor_running, #janitor_state{cleanup_id = ID}};

handle_info(janitor, StateName, _StateData) ->
    ?log_info("Skipping janitor in state ~p", [StateName]),
    keep_state_and_data;

handle_info({'EXIT', Pid, Reason}, rebalancing,
            #rebalancing_state{rebalancer=Pid} = State) ->
    handle_rebalance_completion(Reason, State);

handle_info({'EXIT', Pid, Reason}, recovery, #recovery_state{pid = Pid}) ->
    ale:error(?USER_LOGGER,
              "Recovery process ~p terminated unexpectedly: ~p", [Pid, Reason]),
    {next_state, idle, #idle_state{}};

handle_info({cleanup_done, UnsafeNodes, ID}, janitor_running,
            #janitor_state{cleanup_id = CleanupID}) ->
    %% If we get here we don't expect the IDs to be different.
    ID = CleanupID,

    %% If any 'unsafe nodes' were found then trigger an auto_reprovision
    %% operation via the orchestrator.
    case UnsafeNodes =/= [] of
        true ->
            %% The unsafe nodes only affect the ephemeral buckets.
            Buckets = ns_bucket:get_bucket_names_of_type(membase, ephemeral),
            RV = auto_reprovision:reprovision_buckets(Buckets, UnsafeNodes),
            ?log_info("auto_reprovision status = ~p "
                      "(Buckets = ~p, UnsafeNodes = ~p)",
                      [RV, Buckets, UnsafeNodes]),

            %% Trigger the janitor cleanup immediately as the buckets need to be
            %% brought online.
            self() ! janitor;
        false ->
            ok
    end,
    consider_switching_compat_mode(),
    {next_state, idle, #idle_state{}};

handle_info({timeout, _TRef, stop_timeout} = Msg, rebalancing, StateData) ->
    ?MODULE:rebalancing(Msg, StateData);

%% Backward compitibility: handle messages from nodes that are older than
%%                         Mad-Hatter which use gen_fsm api's
%%
%% Here we rely on the fact that gen_fsm:reply/2 and gen_statem:reply/2
%% do essentially the same thing, so when we accept call from gen_fsm
%% we actually can reply using gen_statem:reply/2 and that'll work.
%% This assumption needs to be re-evaluated on the new erlang upgrade.
%% This warning can be removed when vulcan support is dropped.

handle_info({'$gen_sync_all_state_event', From, Event}, _StateName,
            _StateData) ->
    {keep_state_and_data, [{next_event, {call, From}, Event}]};
handle_info({'$gen_sync_event', From, Event}, _StateName, _StateData) ->
    {keep_state_and_data, [{next_event, {call, From}, Event}]};
handle_info({'$gen_event', Event}, _StateName, _StateData) ->
    {keep_state_and_data, [{next_event, cast, Event}]};

%% end of backward compatibility code

handle_info(Msg, StateName, StateData) ->
    ?log_warning("Got unexpected message ~p in state ~p with data ~p",
                 [Msg, StateName, StateData]),
    {next_state, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
    ok.

%%
%% States
%%

%% Asynchronous idle events
idle({request_janitor_run, Item}, State) ->
    do_request_janitor_run(Item, idle, State);
idle(_Event, _State) ->
    %% This will catch stray progress messages
    keep_state_and_data.

janitor_running({request_janitor_run, Item}, State) ->
    do_request_janitor_run(Item, janitor_running, State);
janitor_running(_Event, _State) ->
    keep_state_and_data.

%% Synchronous idle events
idle({create_bucket, BucketType, BucketName, NewConfig}, From, _State) ->
    Reply = case ns_bucket:name_conflict(BucketName) of
                false ->
                    {Results, FailedNodes} =
                        rpc:multicall(ns_node_disco:nodes_wanted(),
                                      ns_memcached, active_buckets, [],
                                      ?CREATE_BUCKET_TIMEOUT),
                    case FailedNodes of
                        [] -> ok;
                        _ ->
                            ?log_warning("Best-effort check for presense of "
                                         "bucket failed to be made on "
                                         "following nodes: ~p", [FailedNodes])
                    end,
                    case lists:any(
                           fun (StartedBucket) ->
                                   ns_bucket:names_conflict(StartedBucket,
                                                            BucketName)
                           end, lists:append(Results)) of
                        true ->
                            {error, {still_exists, BucketName}};
                        _ ->
                            ns_bucket:create_bucket(BucketType, BucketName,
                                                    NewConfig)
                    end;
                true ->
                    {error, {already_exists, BucketName}}
            end,
    case Reply of
        ok ->
            master_activity_events:note_bucket_creation(BucketName, BucketType,
                                                        NewConfig),
            request_janitor_run({bucket, BucketName});
        _ -> ok
    end,
    {keep_state_and_data, [{reply, From, Reply}]};
idle({flush_bucket, BucketName}, From, _State) ->
    RV = perform_bucket_flushing(BucketName),
    case RV of
        ok -> ok;
        _ ->
            ale:info(?USER_LOGGER, "Flushing ~p failed with error: ~n~p",
                     [BucketName, RV])
    end,
    {keep_state_and_data, [{reply, From, RV}]};
idle({delete_bucket, BucketName}, From, _State) ->
    menelaus_users:cleanup_bucket_roles(BucketName),
    DeleteRV = ns_bucket:delete_bucket_returning_config(BucketName),

    case DeleteRV of
        {ok, _} ->
            master_activity_events:note_bucket_deletion(BucketName),
            ns_janitor_server:delete_bucket_request(BucketName);
        _ ->
            ok
    end,

    Reply =
        case DeleteRV of
            {ok, BucketConfig} ->
                Nodes = ns_bucket:bucket_nodes(BucketConfig),
                Pred = fun (Active) ->
                               not lists:member(BucketName, Active)
                       end,
                LeftoverNodes =
                    case wait_for_nodes(Nodes, Pred, ?DELETE_BUCKET_TIMEOUT) of
                        ok ->
                            [];
                        {timeout, LeftoverNodes0} ->
                            ?log_warning("Nodes ~p failed to delete bucket ~p "
                                         "within expected time.",
                                         [LeftoverNodes0, BucketName]),
                            LeftoverNodes0
                    end,

                LiveNodes = Nodes -- LeftoverNodes,

                ?log_info("Restarting moxi on nodes ~p", [LiveNodes]),
                case multicall_moxi_restart(LiveNodes,
                                            ?DELETE_BUCKET_TIMEOUT) of
                    ok ->
                        ok;
                    FailedNodes ->
                        ?log_warning("Failed to restart moxi on following "
                                     "nodes ~p", [FailedNodes])
                end,
                case LeftoverNodes of
                    [] ->
                        ok;
                    _ ->
                        {shutdown_failed, LeftoverNodes}
                end;
            _ ->
                DeleteRV
        end,

    {keep_state_and_data, [{reply, From, Reply}]};
idle({failover, Node}, From, _State) ->
    %% calls from pre-5.5 nodes
    {keep_state_and_data,
     [{next_event, {call, From}, {failover, [Node], false}}]};
idle({failover, Nodes, AllowUnsafe}, From, _State) ->
    Result = ns_rebalancer:run_failover(Nodes, AllowUnsafe),

    {keep_state_and_data, [{reply, From, Result}]};
idle({try_autofailover, Nodes}, From, _State) ->
    case ns_rebalancer:validate_autofailover(Nodes) of
        {error, UnsafeBuckets} ->
            {keep_state_and_data,
             [{reply, From, {autofailover_unsafe, UnsafeBuckets}}]};
        ok ->
            {keep_state_and_data,
             [{next_event, {call, From}, {failover, Nodes, false}}]}
    end;
idle({start_graceful_failover, Node}, From, _State) when is_atom(Node) ->
    %% calls from pre-madhatter nodes
    {keep_state_and_data,
     [{next_event, {call, From}, {start_graceful_failover, [Node], false}}]};
idle({start_graceful_failover, Nodes}, From, _State) ->
    case ns_rebalancer:start_link_graceful_failover(Nodes) of
        {ok, Pid} ->
            Type = graceful_failover,
            ns_cluster:counter_inc(Type, start),
            set_rebalance_status(Type, running, Pid),

            ActiveNodes = ns_cluster_membership:active_nodes(),
            Progress = rebalance_progress:init(ActiveNodes, [kv]),

            {next_state, rebalancing,
             #rebalancing_state{rebalancer=Pid,
                                eject_nodes = [],
                                keep_nodes = [],
                                failed_nodes = [],
                                progress=Progress,
                                type=Type},
             [{reply, From, ok}]};
        {error, RV} ->
            {keep_state_and_data, [{reply, From, RV}]}
    end;
idle(rebalance_progress, From, _State) ->
    {keep_state_and_data, [{reply, From, not_running}]};
%% NOTE: this is not remotely called but is used by maybe_start_rebalance
idle({start_rebalance, KeepNodes, EjectNodes,
      FailedNodes, DeltaNodes, DeltaRecoveryBuckets}, From, _State) ->
    case ns_rebalancer:start_link_rebalance(KeepNodes, EjectNodes,
                                            FailedNodes, DeltaNodes,
                                            DeltaRecoveryBuckets) of
        {ok, Pid} ->
            case DeltaNodes =/= [] of
                true ->
                    ale:info(?USER_LOGGER,
                             "Starting rebalance, KeepNodes = ~p, "
                             "EjectNodes = ~p, Failed over and being ejected "
                             "nodes = ~p, Delta recovery nodes = ~p, "
                             " Delta recovery buckets = ~p",
                             [KeepNodes, EjectNodes, FailedNodes, DeltaNodes,
                              DeltaRecoveryBuckets]);
                _ ->
                    ale:info(?USER_LOGGER,
                             "Starting rebalance, KeepNodes = ~p, "
                             "EjectNodes = ~p, Failed over and being ejected "
                             "nodes = ~p; no delta recovery nodes~n",
                             [KeepNodes, EjectNodes, FailedNodes])
            end,

            Type = rebalance,
            ns_cluster:counter_inc(Type, start),
            set_rebalance_status(Type, running, Pid),

            {next_state, rebalancing,
             #rebalancing_state{rebalancer=Pid,
                                progress=rebalance_progress:init(
                                           KeepNodes ++ EjectNodes),
                                keep_nodes=KeepNodes,
                                eject_nodes=EjectNodes,
                                failed_nodes=FailedNodes,
                                type=Type},
             [{reply, From, ok}]};
        {error, no_kv_nodes_left} ->
            {keep_state_and_data, [{reply, From, no_kv_nodes_left}]};
        {error, delta_recovery_not_possible} ->
            {keep_state_and_data, [{reply, From, delta_recovery_not_possible}]}
    end;
idle({move_vbuckets, Bucket, Moves}, From, _State) ->
    Pid = spawn_link(
            fun () ->
                    ns_rebalancer:move_vbuckets(Bucket, Moves)
            end),

    Type = move_vbuckets,
    ns_cluster:counter_inc(Type, start),
    set_rebalance_status(Type, running, Pid),

    Nodes = ns_cluster_membership:active_nodes(),
    Progress = rebalance_progress:init(Nodes, [kv]),

    {next_state, rebalancing,
     #rebalancing_state{rebalancer=Pid,
                        progress=Progress,
                        keep_nodes=ns_node_disco:nodes_wanted(),
                        eject_nodes=[],
                        failed_nodes=[],
                        type=Type},
     [{reply, From, ok}]};
idle(stop_rebalance, From, _State) ->
    ns_janitor:stop_rebalance_status(
      fun () ->
              ale:info(?USER_LOGGER,
                       "Resetting rebalance status since rebalance stop "
                       "was requested but rebalance isn't orchestrated on "
                       "our node"),
              none
      end),
    {keep_state_and_data, [{reply, From, not_rebalancing}]};
idle({start_recovery, Bucket}, {FromPid, _} = From, _State) ->
    case recovery_server:start_recovery(Bucket, FromPid) of
        {ok, Pid, UUID, Map} ->
            {next_state, recovery, #recovery_state{pid = Pid},
             [{reply, From, {ok, UUID, Map}}]};
        Error ->
            {keep_state_and_data, [{reply, From, Error}]}
    end;
idle({ensure_janitor_run, Item}, From, State) ->
    do_request_janitor_run(
      Item,
      fun (Reason) ->
              gen_statem:reply(From, Reason)
      end, idle, State).

%% Synchronous janitor_running events
janitor_running(rebalance_progress, From, _State) ->
    {keep_state_and_data, [{reply, From, not_running}]};
janitor_running({ensure_janitor_run, Item}, From, State) ->
    do_request_janitor_run(
      Item,
      fun (Reason) ->
              gen_statem:reply(From, Reason)
      end, janitor_running, State);

janitor_running(Msg, From, #janitor_state{cleanup_id = ID})
  when ID =/= undefined ->
    %% When handling some call while janitor is running we kill janitor
    %% and then handle original call in idle state
    ok = ns_janitor_server:terminate_cleanup(ID),

    %% Eat up the cleanup_done message that gets sent by ns_janitor_server when
    %% the cleanup process ends.
    receive
        {cleanup_done, _, _} ->
            ok
    end,
    {next_state, idle, #idle_state{}, [{next_event, {call, From}, Msg}]}.

%% Asynchronous rebalancing events
rebalancing({update_progress, Service, ServiceProgress},
            #rebalancing_state{progress=Old} = State) ->
    NewProgress = rebalance_progress:update(Service, ServiceProgress, Old),
    {next_state, rebalancing,
     State#rebalancing_state{progress=NewProgress}};
rebalancing({timeout, _Tref, stop_timeout},
            #rebalancing_state{rebalancer = Pid} = State) ->
    ?log_debug("Stop rebalance timeout, brutal kill pid = ~p", [Pid]),
    exit(Pid, kill),
    Reason =
        receive
            {'EXIT', Pid, killed} ->
                %% still treat this as user-stopped rebalance
                {shutdown, stop};
            {'EXIT', Pid, R} ->
                R
        end,
    handle_rebalance_completion(Reason, State).

%% Synchronous rebalancing events
rebalancing({start_rebalance, _KeepNodes, _EjectNodes,
             _FailedNodes, _DeltaNodes, _DeltaRecoveryBuckets},
            From, _State) ->
    ale:info(?USER_LOGGER,
             "Not rebalancing because rebalance is already in progress.~n"),
    {keep_state_and_data, [{reply, From, in_progress}]};
rebalancing({start_graceful_failover, _}, From, _State) ->
    {keep_state_and_data, [{reply, From, in_progress}]};
rebalancing(stop_rebalance, From,
            #rebalancing_state{rebalancer=Pid} = State) ->
    ?log_debug("Sending stop to rebalancer: ~p", [Pid]),
    exit(Pid, {shutdown, stop}),
    TRef = erlang:start_timer(?STOP_REBALANCE_TIMEOUT, self(), stop_timeout),
    {keep_state, State#rebalancing_state{stop_timer = TRef},
     [{reply, From, ok}]};
rebalancing(rebalance_progress, From,
            #rebalancing_state{progress = Progress}) ->
    AggregatedProgress =
        dict:to_list(rebalance_progress:get_progress(Progress)),
    {keep_state_and_data, [{reply, From, {running, AggregatedProgress}}]};
rebalancing(Event, From, _State) ->
    ?log_warning("Got event ~p while rebalancing.", [Event]),
    {keep_state_and_data, [{reply, From, rebalance_running}]}.

%% Asynchronous recovery events
recovery(Event, _State) ->
    ?log_warning("Got unexpected event: ~p", [Event]),
    keep_state_and_data.

%% Synchronous recovery events
recovery({start_recovery, _Bucket}, From, _State) ->
    {keep_state_and_data, [{reply, From, recovery_running}]};
recovery({commit_vbucket, Bucket, UUID, VBucket}, From, State) ->
    Result = call_recovery_server(State,
                                  commit_vbucket, [Bucket, UUID, VBucket]),
    case Result of
        recovery_completed ->
            {next_state, idle, #idle_state{}, [{reply, From, Result}]};
        _ ->
            {keep_state_and_data, [{reply, From, Result}]}
    end;
recovery({stop_recovery, Bucket, UUID}, From, State) ->
    case call_recovery_server(State, stop_recovery, [Bucket, UUID]) of
        ok ->
            {next_state, idle, #idle_state{}, [{reply, From, ok}]};
        Error ->
            {keep_state_and_data, [{reply, From, Error}]}
    end;
recovery(recovery_status, From, State) ->
    {keep_state_and_data,
     [{reply, From, call_recovery_server(State, recovery_status)}]};
recovery({recovery_map, Bucket, RecoveryUUID}, From, State) ->
    {keep_state_and_data,
     [{reply, From,
       call_recovery_server(State, recovery_map, [Bucket, RecoveryUUID])}]};

recovery(rebalance_progress, From, _State) ->
    {keep_state_and_data, [{reply, From, not_running}]};
recovery(stop_rebalance, From, _State) ->
    {keep_state_and_data, [{reply, From, not_rebalancing}]};
recovery(_Event, From, _State) ->
    {keep_state_and_data, [{reply, From, in_recovery}]}.

%%
%% Internal functions
%%

do_request_janitor_run(Item, FsmState, State) ->
    do_request_janitor_run(Item, fun(_Reason) -> ok end,
                           FsmState, State).

do_request_janitor_run(Item, Fun, FsmState, State) ->
    RV = ns_janitor_server:request_janitor_run({Item, [Fun]}),
    case FsmState =:= idle andalso RV =:= added of
        true ->
            self() ! janitor;
        false ->
            ok
    end,
    {next_state, FsmState, State}.

-spec update_progress(service(), dict:dict()) -> ok.
update_progress(Service, ServiceProgress) ->
    gen_statem:cast(?SERVER, {update_progress, Service, ServiceProgress}).

wait_for_nodes_loop(Nodes) ->
    receive
        {done, Node} ->
            NewNodes = Nodes -- [Node],
            case NewNodes of
                [] ->
                    ok;
                _ ->
                    wait_for_nodes_loop(NewNodes)
            end;
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
              Nodes1 =
                  lists:filter(
                    fun (N) ->
                            Status = ns_doctor:get_node(N, Statuses),
                            not wait_for_nodes_check_pred(Status, Pred)
                    end, Nodes),

              erlang:send_after(Timeout, Self, timeout),
              wait_for_nodes_loop(Nodes1)
      end).

%% quickly and _without_ communication to potentially remote
%% ns_orchestrator find out if rebalance is running.
is_rebalance_running() ->
    ns_config:search(rebalance_status) =:= {value, running}.

consider_switching_compat_mode() ->
    case consider_switching_compat_mode_dont_exit() of
        {changed, _, _} ->
            exit(normal);
        unchanged ->
            ok
    end.

consider_switching_compat_mode_dont_exit() ->
    OldVersion = cluster_compat_mode:get_compat_version(),

    case cluster_compat_mode:consider_switching_compat_mode() of
        changed ->
            NewVersion = cluster_compat_mode:get_compat_version(),
            ale:warn(?USER_LOGGER, "Changed cluster compat mode from ~p to ~p",
                     [OldVersion, NewVersion]),
            {changed, OldVersion, NewVersion};
        ok ->
            unchanged
    end.

perform_bucket_flushing(BucketName) ->
    case ns_bucket:get_bucket(BucketName) of
        not_present ->
            bucket_not_found;
        {ok, BucketConfig} ->
            case proplists:get_value(flush_enabled, BucketConfig, false) of
                true ->
                    perform_bucket_flushing_with_config(BucketName,
                                                        BucketConfig);
                false ->
                    flush_disabled
            end
    end.


perform_bucket_flushing_with_config(BucketName, BucketConfig) ->
    ale:info(?MENELAUS_LOGGER, "Flushing bucket ~p from node ~p",
             [BucketName, erlang:node()]),
    case ns_bucket:bucket_type(BucketConfig) =:= memcached of
        true ->
            do_flush_old_style(BucketName, BucketConfig);
        _ ->
            RV = do_flush_bucket(BucketName, BucketConfig),
            case RV of
                ok ->
                    ?log_info("Requesting janitor run to actually "
                              "revive bucket ~p after flush", [BucketName]),
                    JanitorRV = ns_janitor:cleanup(
                                  BucketName, [{query_states_timeout, 1000}]),
                    case JanitorRV of
                        ok -> ok;
                        _ ->
                            ?log_error("Flusher's janitor run failed: ~p",
                                       [JanitorRV])
                    end,
                    RV;
                _ ->
                    RV
            end
    end.

do_flush_bucket(BucketName, BucketConfig) ->
    Nodes = ns_bucket:bucket_nodes(BucketConfig),
    case ns_config_rep:ensure_config_seen_by_nodes(Nodes) of
        ok ->
            case janitor_agent:mass_prepare_flush(BucketName, Nodes) of
                {_, [], []} ->
                    continue_flush_bucket(BucketName, BucketConfig, Nodes);
                {_, BadResults, BadNodes} ->
                    %% NOTE: I'd like to undo prepared flush on good
                    %% nodes, but given we've lost information whether
                    %% janitor ever marked them as warmed up I
                    %% cannot. We'll do it after some partial
                    %% janitoring support is achieved. And for now
                    %% we'll rely on janitor cleaning things up.
                    {error, {prepare_flush_failed, BadNodes, BadResults}}
            end;
        {error, SyncFailedNodes} ->
            {error, {initial_config_sync_failed, SyncFailedNodes}}
    end.

continue_flush_bucket(BucketName, BucketConfig, Nodes) ->
    OldFlushCount = proplists:get_value(flushseq, BucketConfig, 0),
    NewConfig = lists:keystore(flushseq, 1, BucketConfig,
                               {flushseq, OldFlushCount + 1}),
    ns_bucket:set_bucket_config(BucketName, NewConfig),
    case ns_config_rep:ensure_config_seen_by_nodes(Nodes) of
        ok ->
            finalize_flush_bucket(BucketName, Nodes);
        {error, SyncFailedNodes} ->
            {error, {flush_config_sync_failed, SyncFailedNodes}}
    end.

finalize_flush_bucket(BucketName, Nodes) ->
    {_GoodNodes, FailedCalls, FailedNodes} =
        janitor_agent:complete_flush(BucketName, Nodes, ?FLUSH_BUCKET_TIMEOUT),
    case FailedCalls =:= [] andalso FailedNodes =:= [] of
        true ->
            ok;
        _ ->
            {error, {flush_wait_failed, FailedNodes, FailedCalls}}
    end.

do_flush_old_style(BucketName, BucketConfig) ->
    Nodes = ns_bucket:bucket_nodes(BucketConfig),
    {Results, BadNodes} =
        rpc:multicall(Nodes, ns_memcached, flush, [BucketName],
                      ?MULTICALL_DEFAULT_TIMEOUT),
    case BadNodes =:= [] andalso lists:all(fun(A) -> A =:= ok end, Results) of
        true ->
            ok;
        false ->
            {old_style_flush_failed, Results, BadNodes}
    end.

%% NOTE: 2.0.1 and earlier nodes only had
%% ns_port_sup. I believe it's harmless not to clean
%% their moxis
-spec multicall_moxi_restart([node()], _) -> ok | [{node(), _} | node()].
multicall_moxi_restart(Nodes, Timeout) ->
    {Results, FailedNodes} = rpc:multicall(Nodes, ns_ports_setup, restart_moxi,
                                           [], Timeout),
    BadResults = [Pair || {_N, R} = Pair <- lists:zip(Nodes -- FailedNodes,
                                                      Results),
                          R =/= ok],
    case BadResults =:= [] andalso FailedNodes =:= [] of
        true ->
            ok;
        _ ->
            FailedNodes ++ BadResults
    end.

set_rebalance_status(_Type, Status, undefined) ->
    do_set_rebalance_status(Status, undefined, undefined);
set_rebalance_status(rebalance, Status, Pid) when is_pid(Pid) ->
    do_set_rebalance_status(Status, Pid, undefined);
set_rebalance_status(graceful_failover, Status, Pid) when is_pid(Pid) ->
    do_set_rebalance_status(Status, Pid, Pid);
set_rebalance_status(move_vbuckets, Status, Pid) ->
    set_rebalance_status(rebalance, Status, Pid);
set_rebalance_status(service_upgrade, Status, Pid) ->
    set_rebalance_status(rebalance, Status, Pid).

do_set_rebalance_status(Status, RebalancerPid, GracefulPid) ->
    ns_config:set([{rebalance_status, Status},
                   {rebalance_status_uuid, couch_uuids:random()},
                   {rebalancer_pid, RebalancerPid},
                   {graceful_failover_pid, GracefulPid}]).

cancel_stop_timer(State) ->
    do_cancel_stop_timer(State#rebalancing_state.stop_timer).

do_cancel_stop_timer(undefined) ->
    ok;
do_cancel_stop_timer(TRef) when is_reference(TRef) ->
    _ = erlang:cancel_timer(TRef),
    receive {timeout, TRef, _} -> 0
    after 0 -> ok
    end.

handle_rebalance_completion(Reason, State) ->
    cancel_stop_timer(State),
    maybe_reset_autofailover_count(Reason, State),
    maybe_reset_reprovision_count(Reason, State),
    log_rebalance_completion(Reason, State),
    update_rebalance_counters(Reason, State),
    update_rebalance_status(Reason, State),
    rpc:eval_everywhere(diag_handler, log_all_dcp_stats, []),

    R = consider_switching_compat_mode_dont_exit(),
    case maybe_start_service_upgrader(Reason, R, State) of
        {started, NewState} ->
            {next_state, rebalancing, NewState};
        not_needed ->
            maybe_eject_myself(Reason, State),
            maybe_exit(R, State),
            {next_state, idle, #idle_state{}}
    end.

maybe_eject_myself(Reason, State) ->
    case need_eject_myself(Reason, State) of
        true ->
            eject_myself(State);
        false ->
            ok
    end.

need_eject_myself(normal, #rebalancing_state{eject_nodes = EjectNodes,
                                             failed_nodes = FailedNodes}) ->
    lists:member(node(), EjectNodes) orelse lists:member(node(), FailedNodes);
need_eject_myself(_Reason, #rebalancing_state{failed_nodes = FailedNodes}) ->
    lists:member(node(), FailedNodes).

eject_myself(#rebalancing_state{keep_nodes = KeepNodes}) ->
    ok = ns_config_rep:ensure_config_seen_by_nodes(KeepNodes),
    ns_rebalancer:eject_nodes([node()]).

maybe_reset_autofailover_count(normal, #rebalancing_state{type = rebalance}) ->
    auto_failover:reset_count_async();
maybe_reset_autofailover_count(_, _) ->
    ok.

maybe_reset_reprovision_count(normal, #rebalancing_state{type = rebalance}) ->
    auto_reprovision:reset_count();
maybe_reset_reprovision_count(_, _) ->
    ok.

log_rebalance_completion(Reason, #rebalancing_state{type = Type}) ->
    do_log_rebalance_completion(Reason, Type).

do_log_rebalance_completion(normal, Type) ->
    ale:info(?USER_LOGGER,
             "~s completed successfully.", [rebalance_type2text(Type)]);
do_log_rebalance_completion({shutdown, stop}, Type) ->
    ale:info(?USER_LOGGER,
             "~s stopped by user.", [rebalance_type2text(Type)]);
do_log_rebalance_completion(Error, Type) ->
    ale:error(?USER_LOGGER,
              "~s exited with reason ~p", [rebalance_type2text(Type), Error]).

rebalance_type2text(rebalance) ->
    <<"Rebalance">>;
rebalance_type2text(move_vbuckets) ->
    rebalance_type2text(rebalance);
rebalance_type2text(graceful_failover) ->
    <<"Graceful failover">>;
rebalance_type2text(service_upgrade) ->
    <<"Service upgrade">>.

update_rebalance_counters(Reason, #rebalancing_state{type = Type}) ->
    Counter =
        case Reason of
            normal ->
                success;
            {shutdown, stop} ->
                stop;
            _Error ->
                fail
        end,

    ns_cluster:counter_inc(Type, Counter).

update_rebalance_status(Reason, #rebalancing_state{type = Type}) ->
    set_rebalance_status(Type, reason2status(Reason, Type), undefined).

reason2status(normal, _Type) ->
    none;
reason2status({shutdown, stop}, _Type) ->
    none;
reason2status(_Error, Type) ->
    Msg = io_lib:format(
            "~s failed. See logs for detailed reason. "
            "You can try again.",
            [rebalance_type2text(Type)]),
    {none, iolist_to_binary(Msg)}.

maybe_start_service_upgrader(normal, unchanged, _State) ->
    not_needed;
maybe_start_service_upgrader(normal, {changed, OldVersion, NewVersion},
                             #rebalancing_state{keep_nodes = KeepNodes}
                             = State) ->
    Old = ns_cluster_membership:topology_aware_services_for_version(OldVersion),
    New = ns_cluster_membership:topology_aware_services_for_version(NewVersion),

    Services = [S || S <- New -- Old,
                     ns_cluster_membership:service_nodes(KeepNodes, S) =/= []],
    case Services of
        [] ->
            not_needed;
        _ ->
            ale:info(?USER_LOGGER,
                     "Starting upgrade for the following services: ~p",
                     [Services]),
            Pid = start_service_upgrader(KeepNodes, Services),

            Type = service_upgrade,
            set_rebalance_status(Type, running, Pid),
            ns_cluster:counter_inc(Type, start),
            Progress = rebalance_progress:init(KeepNodes, Services),

            NewState = State#rebalancing_state{type = Type,
                                               progress = Progress,
                                               rebalancer = Pid},

            {started, NewState}
    end;
maybe_start_service_upgrader(_Reason, _SwitchCompatResult, _State) ->
    %% rebalance failed, so we'll just let the user start rebalance again
    not_needed.

start_service_upgrader(KeepNodes, Services) ->
    proc_lib:spawn_link(
      fun () ->
              Config = ns_config:get(),
              EjectNodes = [],

              ok = service_janitor:cleanup(Config),

              %% since we are not actually ejecting anything here, we can
              %% ignore the return value
              _ = ns_rebalancer:rebalance_topology_aware_services(
                    Config, Services, KeepNodes, EjectNodes)
      end).

maybe_exit(SwitchCompatResult, #rebalancing_state{type = Type}) ->
    case need_exit(SwitchCompatResult, Type) of
        true ->
            exit(normal);
        false ->
            ok
    end.

need_exit({changed, _, _}, _Type) ->
    %% switched compat version, but didn't have to upgrade services
    true;
need_exit(_, service_upgrade) ->
    %% needed to upgrade the services, so we need to exit because we must have
    %% upgraded the compat version just before that
    true;
need_exit(_, _) ->
    false.

call_recovery_server(State, Call) ->
    call_recovery_server(State, Call, []).

call_recovery_server(#recovery_state{pid = Pid}, Call, Args) ->
    erlang:apply(recovery_server, Call, [Pid | Args]).

rebalance_allowed(Config) ->
    case cluster_compat_mode:is_cluster_madhatter(Config) of
        true ->
            ok;
        false ->
            functools:sequence_(Config, [fun check_for_passwordless_default/1,
                                         fun check_for_moxi_buckets/1])
    end.

check_for_moxi_buckets(Config) ->
    case [Name || {Name, BucketConfig} <- ns_bucket:get_buckets(Config),
                  ns_bucket:moxi_port(BucketConfig) =/= undefined] of
        [] ->
            ok;
        Buckets ->
            BucketsStr = string:join(Buckets, ","),
            Msg = io_lib:format("Please remove proxy ports from the "
                                "following buckets: ~s", [BucketsStr]),
            {error, Msg}
    end.

check_for_passwordless_default(Config) ->
    case cluster_compat_mode:is_cluster_50(Config) of
        false ->
            ok;
        true ->
            case lists:member({"default", local},
                              menelaus_users:get_passwordless()) andalso
                lists:keymember("default", 1, ns_bucket:get_buckets(Config)) of
                true ->
                    {error, "Please reset password for user 'default'"};
                false ->
                    ok
            end
    end.
