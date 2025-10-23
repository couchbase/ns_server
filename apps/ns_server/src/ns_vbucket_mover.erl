%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(ns_vbucket_mover).

-behavior(gen_server).

-include_lib("ns_common/include/cut.hrl").
-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(MOVES_BEFORE_COMPACTION,
        ns_config:read_key_fast(rebalance_moves_before_compaction, 64)).
-define(MAX_INFLIGHT_MOVES_PER_NODE,
        ns_config:read_key_fast(rebalance_inflight_moves_per_node, 64)).

%% API
-export([start_link/8]).

%% gen_server callbacks
-export([code_change/3, init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-export([inhibit_view_compaction/3]).
-export([note_move_done/2, note_backfill_done/2, update_vbucket_map/2]).

-type progress_callback() :: fun((dict:dict()) -> any()).

-record(state, {bucket :: bucket_name(),
                disco_events_subscription :: pid(),
                map :: array:array(),
                uploaders :: array:array() | undefined,
                uploader_moves :: array:array() | undefined,
                pending_map_sync :: undefined | [{pid(), any()}],
                moves_scheduler_state,
                progress_callback :: progress_callback(),
                all_nodes_set :: sets:set()}).

%%
%% API
%%

%% @doc Start the mover.
-spec start_link(ns_bucket:name(), ns_bucket:config(), [node()],
                 vbucket_map(), vbucket_map(), progress_callback(),
                 list() | undefined,
                 fusion_uploaders:fast_forward_info() | undefined) ->
          {ok, pid()} | {error, any()}.
start_link(Bucket, BucketConfig, Nodes, OldMap, NewMap, ProgressCallback,
           RebalancePlan, FusionUploadersInfo) ->
    gen_server:start_link(
      ?MODULE, {Bucket, BucketConfig, Nodes, OldMap, NewMap, ProgressCallback,
                RebalancePlan, FusionUploadersInfo}, []).

note_move_done(Pid, Worker) ->
    Pid ! {move_done, Worker}.

note_backfill_done(Pid, Worker) ->
    Pid ! {backfill_done, Worker}.

update_vbucket_map(Pid, Worker) ->
    gen_server:call(Pid, {update_vbucket_map, Worker}, infinity).

%%
%% gen_server callbacks
%%

code_change(_OldVsn, _Extra, State) ->
    {ok, State}.

assert_dict_mapping(Dict, E1, E2) ->
    case dict:find(E1, Dict) of
        error ->
            dict:store(E1, E2, Dict);
        {ok, E2} -> % note: E2 is bound
            Dict;
        {ok, _SomethingElse} ->
            erlang:throw(not_swap)
    end.

is_swap_rebalance(OldMap, NewMap) ->
    MapTriples = lists:zip3(lists:seq(0, length(OldMap) - 1),
                            OldMap,
                            NewMap),
    OldNodes = lists:usort(lists:append(OldMap)) -- [undefined],
    NewNodes = lists:usort(lists:append(NewMap)) -- [undefined],
    AddedNodes = ordsets:subtract(NewNodes, OldNodes),
    RemovedNodes = ordsets:subtract(OldNodes, NewNodes),

    try
        length(OldNodes) =/= length(NewNodes) andalso erlang:throw(not_swap),
        lists:foldl(
          fun ({_VB, OldChain, NewChain}, Dict0) ->
                  length(OldChain) =/= length(NewChain) andalso throw(not_swap),
                  Changed = [Pair || {From, To} = Pair <- lists:zip(OldChain, NewChain),
                                     From =/= To,
                                     From =/= undefined,
                                     To =/= undefined],
                  lists:foldl(
                    fun ({From, To}, Dict) ->
                            RemovedNodes =:= [] orelse ordsets:is_element(From, RemovedNodes) orelse erlang:throw(not_swap),
                            AddedNodes =:= [] orelse ordsets:is_element(To, AddedNodes) orelse erlang:throw(not_swap),
                            Dict2 = assert_dict_mapping(Dict, From, To),
                            assert_dict_mapping(Dict2, To, From)
                    end, Dict0, Changed)
          end, dict:new(), MapTriples),
        true
    catch throw:not_swap ->
            false
    end.

file_based_backfill_enabled(BucketConfig) ->
    ns_config:read_key_fast(file_based_backfill_enabled,
                            ?DATA_SERVICE_FILE_BASED_BACKFILL_DEFAULT) andalso
        ns_bucket:is_persistent(BucketConfig) andalso
        not ns_bucket:storage_mode_migration_in_progress(BucketConfig) andalso
        not ns_bucket:eviction_policy_migration_in_progress(BucketConfig)
        andalso
    %% MB-68800: Enable FBR only for fullEviction temporarily
        ns_bucket:eviction_policy(BucketConfig) =:= full_eviction andalso
        lists:member(ns_bucket:get_fusion_state(BucketConfig),
                     [disabled, stopped]).

init({Bucket, BucketConfig, Nodes, OldMap, NewMap, ProgressCallback,
      RebalancePlan, FusionUploadersInfo}) ->
    case is_swap_rebalance(OldMap, NewMap) of
        true ->
            ale:info(?USER_LOGGER, "Bucket ~p rebalance appears to be swap "
                     "rebalance", [Bucket]);
        false ->
            ale:info(?USER_LOGGER, "Bucket ~p rebalance does not seem to be "
                     "swap rebalance", [Bucket])
    end,
    self() ! spawn_initial,
    process_flag(trap_exit, true),
    Self = self(),
    Subscription = ns_pubsub:subscribe_link(
                     ns_node_disco_events,
                     fun ({ns_node_disco_events, _, _} = Event) ->
                             Self ! Event;
                         (_) ->
                             ok
                     end),

    ok = janitor_agent:prepare_nodes_for_rebalance(Bucket, Nodes, self()),

    ets:new(compaction_inhibitions, [named_table, private, set]),
    ets:new(workers, [named_table, private, set]),

    Quirks = rebalance_quirks:get_quirks(Nodes, project_intact),
    Options =
        [{fusion_use_snapshot, true} || RebalancePlan =/= undefined] ++
        [{file_based_backfill_enabled, true} ||
            file_based_backfill_enabled(BucketConfig)],
    SchedulerState = vbucket_move_scheduler:prepare(
                       OldMap, NewMap, Quirks,
                       menelaus_web_settings:get_rebalance_moves_per_node(),
                       ?MOVES_BEFORE_COMPACTION,
                       ?MAX_INFLIGHT_MOVES_PER_NODE, Options),

    ns_rebalance_observer:submit_master_event(
      {planned_moves, Bucket,
       vbucket_move_scheduler:get_moves(SchedulerState), true}),

    case RebalancePlan of
        undefined ->
            ok;
        _ ->
            VolumesToMount = proplists:get_value(mountedVolumes, RebalancePlan),
            BucketPlan = proplists:get_value(
                           Bucket, proplists:get_value(buckets, RebalancePlan)),
            NodesMap = proplists:get_value(nodes, BucketPlan),
            ?rebalance_info("Mount volumes ~p", [VolumesToMount]),
            ok = janitor_agent:mount_volumes(Bucket, VolumesToMount, NodesMap,
                                             self())
    end,

    {FusionUploaders, FusionUploaderMoves} =
        case FusionUploadersInfo of
            undefined ->
                {undefined, undefined};
            _ ->
                {list_to_array(fusion_uploaders:get_current(
                                 FusionUploadersInfo)),
                 list_to_array(fusion_uploaders:get_moves(FusionUploadersInfo))}
        end,

    {ok, #state{bucket = Bucket,
                disco_events_subscription = Subscription,
                map = list_to_array(OldMap),
                uploaders = FusionUploaders,
                uploader_moves = FusionUploaderMoves,
                moves_scheduler_state = SchedulerState,
                progress_callback = ProgressCallback,
                all_nodes_set = sets:from_list(Nodes)}}.


handle_call({update_vbucket_map, Worker}, From, State) ->
    handle_update_vbucket_map(Worker, From, State);
handle_call(_, _From, _State) ->
    exit(not_supported).


handle_cast(unhandled, unhandled) ->
    exit(unhandled).


handle_info(spawn_initial, State) ->
    report_progress(State),
    spawn_workers(State);
handle_info({inhibited_view_compaction, N, MRef}, State) ->
    true = ets:insert_new(compaction_inhibitions, {N, MRef}),
    {noreply, State};
handle_info({compaction_done, N}, #state{moves_scheduler_state = SubState} = State) ->
    A = {compact, N},
    ?log_debug("noted compaction done: ~p", [A]),
    SubState2 = vbucket_move_scheduler:note_compaction_done(SubState, A),
    spawn_workers(State#state{moves_scheduler_state = SubState2});
handle_info({move_done, Worker}, State) ->
    on_move_done(Worker, State);
handle_info({backfill_done, Worker}, State) ->
    on_backfill_done(Worker, State);
handle_info({ns_node_disco_events, OldNodes, NewNodes} = Event,
            #state{all_nodes_set = AllNodesSet} = State) ->
    WentDownNodes = sets:from_list(ordsets:subtract(OldNodes, NewNodes)),

    case sets:is_disjoint(AllNodesSet, WentDownNodes) of
        true ->
            {noreply, State};
        false ->
            {stop, {important_nodes_went_down, Event}, State}
    end;
handle_info(map_sync, State) ->
    map_sync(State);
handle_info({'EXIT', Pid, _} = Msg,
            #state{disco_events_subscription = Pid} = State) ->
    ?rebalance_error("Got exit from node disco events subscription"),
    {stop, {ns_node_disco_events_exited, Msg}, State};
handle_info({'EXIT', Pid, Reason}, State) ->
    {ok, Action} = take_worker(Pid),
    case Reason =:= normal of
        true ->
            {noreply, State};
        false ->
            ?rebalance_error("Worker ~p (for action ~p) exited with reason ~p",
                             [Pid, Action, Reason]),
            {stop, Reason, State}
    end;
handle_info(Info, State) ->
    ?rebalance_warning("Unhandled message ~p", [Info]),
    {noreply, State}.


terminate(Reason, _State) ->
    case get_all_workers() of
        [] ->
            ok;
        Workers ->
            ?log_debug("ns_vbucket_mover terminating "
                       "when some workers are still running:~n~p", [Workers]),
            Pids = [Pid || {Pid, _} <- Workers],
            misc:terminate_and_wait(Pids, Reason)
    end.

%%
%% Internal functions
%%

-spec list_to_array(list()) -> array:array().
list_to_array(List) ->
    array:fix(array:from_list(List)).

%% @private
%% @doc Report progress using the supplied progress callback.
-spec report_progress(#state{}) -> any().
report_progress(#state{moves_scheduler_state = SubState,
                       progress_callback = Callback}) ->
    Progress = vbucket_move_scheduler:extract_progress(SubState),
    Callback(Progress).

on_backfill_done(Worker, #state{moves_scheduler_state = SubState} = State) ->
    {ok, Move} = find_worker(Worker),
    NextState = State#state{moves_scheduler_state = vbucket_move_scheduler:note_backfill_done(SubState, Move)},
    ?log_debug("noted backfill done: ~p", [Move]),
    {noreply, _} = spawn_workers(NextState).

on_move_done(Worker, #state{bucket = Bucket,
                            map = Map,
                            moves_scheduler_state = SubState} = State) ->
    {ok, Move} = find_worker(Worker),
    {move, {VBucket, _, NewChain, _, _}} = Move,

    %% Make sure the worker switched the chains as expected.
    true = (array:get(VBucket, Map) =:= NewChain),

    NextSubState = vbucket_move_scheduler:note_move_completed(SubState, Move),
    NextState = State#state{moves_scheduler_state = NextSubState},

    master_activity_events:note_move_done(Bucket, VBucket),

    report_progress(NextState),
    spawn_workers(NextState).

get_uploader_options(_VBucket, #state{uploaders = undefined,
                                      uploader_moves = undefined}) ->
    [];
get_uploader_options(VBucket, #state{uploaders = FusionUploaders,
                                     uploader_moves = FusionUploaderMoves}) ->
    case array:get(VBucket, FusionUploaderMoves) of
        same ->
            [];
        NewUploader ->
            {CurrentUploaderNode, _} = array:get(VBucket, FusionUploaders),
            [{uploader, NewUploader} |
             [{delete_uploader, CurrentUploaderNode} ||
                 CurrentUploaderNode =/= undefined]]
    end.

handle_update_vbucket_map(
  Worker, From,
  #state{map = Map, uploaders = FusionUploaders,
         uploader_moves = FusionUploaderMoves} = State) ->
    {ok, {move, Move}} = find_worker(Worker),
    {VBucket, OldChain, NewChain, _, _} = Move,

    true = (array:get(VBucket, Map) =:= OldChain),
    NewMap = array:set(VBucket, NewChain, Map),

    NewFusionUploaders =
        case FusionUploaders of
            undefined ->
                undefined;
            _ ->
                true = FusionUploaderMoves =/= undefined,
                case array:get(VBucket, FusionUploaderMoves) of
                    same ->
                        FusionUploaders;
                    Uploader ->
                        array:set(VBucket, Uploader, FusionUploaders)
                end
        end,

    NewState = State#state{map = NewMap,
                           uploaders = NewFusionUploaders},

    {noreply, maybe_schedule_map_sync(From, NewState)}.

maybe_schedule_map_sync(From, #state{pending_map_sync = undefined} = State) ->
    Delay = ?get_param(map_sync_delay, 5),
    erlang:send_after(Delay, self(), map_sync),

    State#state{pending_map_sync = [From]};
maybe_schedule_map_sync(From, #state{pending_map_sync = Waiters} = State) ->
    State#state{pending_map_sync = [From | Waiters]}.

map_sync(#state{map = Map,
                uploaders = Uploaders,
                bucket = Bucket,
                pending_map_sync = Waiters} = State) ->
    ns_bucket:set_map_and_uploaders(Bucket, array:to_list(Map),
                                    case Uploaders of
                                        undefined ->
                                            undefined;
                                        _ ->
                                            array:to_list(Uploaders)
                                    end),
    lists:foreach(gen_server:reply(_, ok), Waiters),
    ?log_debug("Batched ~b vbucket map syncs together.", [length(Waiters)]),

    {noreply, State#state{pending_map_sync = undefined}}.

spawn_compaction_uninhibitor(Bucket, Node, MRef) ->
    Parent = self(),
    erlang:spawn_link(
      fun () ->
              master_activity_events:note_compaction_uninhibit_started(Bucket, Node),
              case uninhibit_view_compaction(Bucket, Parent, Node, MRef) of
                  ok ->
                      master_activity_events:note_compaction_uninhibit_done(Bucket, Node),
                      ok;
                  nack ->
                      Msg = io_lib:format(
                              "failed to initiate compaction for "
                              "bucket ~p on node ~p",
                              [Bucket, Node]),
                      master_activity_events:note_rebalance_stage_event(
                        kv, Msg),
                      erlang:exit({failed_to_initiate_compaction, Bucket, Node, MRef})
              end,
              Parent ! {compaction_done, Node}
      end).

-spec uninhibit_view_compaction(bucket_name(), pid(), node(), reference()) -> ok | nack.
uninhibit_view_compaction(Bucket, Rebalancer, Node, MRef) ->
    janitor_agent:uninhibit_view_compaction(Bucket, Rebalancer, Node, MRef).

-spec inhibit_view_compaction(bucket_name(), pid(), [node()]) -> ok.
inhibit_view_compaction(Bucket, Rebalancer, Nodes) ->
    misc:parallel_map(
      fun (N) ->
              RV = janitor_agent:inhibit_view_compaction(Bucket, Rebalancer, N),
              case RV of
                  {ok, MRef} ->
                      master_activity_events:note_compaction_inhibited(Bucket,
                                                                       N),
                      Rebalancer ! {inhibited_view_compaction, N, MRef};
                  _ ->
                      ?log_debug("Got nack for inhibited_view_compaction. "
                                 "Thats normal: ~p", [{N, RV}])
              end
      end, Nodes, infinity),

    ok.

%% @doc Spawn workers up to the per-node maximum.
-spec spawn_workers(#state{}) -> {noreply, #state{}} | {stop, normal, #state{}}.
spawn_workers(#state{bucket = Bucket,
                     moves_scheduler_state = SubState,
                     all_nodes_set = AllNodesSet} = State) ->
    {Actions, NewSubState} = vbucket_move_scheduler:choose_action(SubState),
    ?log_debug("Got actions: ~p", [Actions]),
    lists:foreach(
      fun (Action) ->
              case spawn_worker(Action, State) of
                  done ->
                      ok;
                  {ok, Worker} ->
                      store_worker(Worker, Action)
              end
      end, Actions),

    NextState = State#state{moves_scheduler_state = NewSubState},
    Done = Actions =:= [] andalso begin
                                      true = (NewSubState =:= SubState),
                                      vbucket_move_scheduler:is_done(NewSubState)
                                  end,
    case Done of
        true ->
            janitor_agent:finish_rebalance(Bucket, sets:to_list(AllNodesSet), self()),
            {stop, normal, NextState};
        _ ->
            {noreply, NextState}
    end.

spawn_worker({move, {VBucket, OldChain, NewChain, Quirks, Options}},
             #state{bucket = Bucket} = State) ->
    UploaderOptions = get_uploader_options(VBucket, State),
    Pid = ns_single_vbucket_mover:spawn_mover(
            Bucket, VBucket, OldChain, NewChain, Quirks,
            Options ++ UploaderOptions),
    {ok, Pid};
spawn_worker({compact, Node}, #state{bucket = Bucket}) ->
    case ets:take(compaction_inhibitions, Node) of
        [] ->
            self() ! {compaction_done, Node},
            done;
        [{Node, MRef}] ->
            Pid = spawn_compaction_uninhibitor(Bucket, Node, MRef),
            {ok, Pid}
    end.

store_worker(Pid, Action) ->
    true = ets:insert_new(workers, {Pid, Action}).

find_worker(Pid) ->
    case ets:lookup(workers, Pid) of
        [{_, Action}] ->
            {ok, Action};
        [] ->
            not_found
    end.

take_worker(Pid) ->
    R = find_worker(Pid),
    ets:delete(workers, Pid),
    R.

get_all_workers() ->
    ets:tab2list(workers).

-ifdef(TEST).
is_swap_rebalance_test() ->
    ?assertEqual(true,  is_swap_rebalance([], [])),
    ?assertEqual(true,  is_swap_rebalance([[1]], [[2]])),
    ?assertEqual(true,  is_swap_rebalance([[1]], [[1]])),
    ?assertEqual(true,  is_swap_rebalance([[1], [1]], [[2], [2]])),
    ?assertEqual(true,  is_swap_rebalance([[1,2], [2,3]], [[1,4], [4,3]])),
    ?assertEqual(false, is_swap_rebalance([[1,2], [2,3]], [[4,1], [4,3]])),
    ?assertEqual(true,  is_swap_rebalance([[1,2,3], [2,3,4], [3,4,1]],
                                          [[1,5,3], [5,3,4], [3,4,1]])),
    ?assertEqual(false, is_swap_rebalance([[1,2,3], [2,3,4], [3,4,1]],
                                          [[1,5,3], [4,3,5], [3,4,1]])),
    ?assertEqual(true,  is_swap_rebalance([[1,2,undefined], [2,3,undefined]],
                                          [[1,5,undefined], [5,3,undefined]])),
    ?assertEqual(false, is_swap_rebalance([[1,2,undefined], [2,3,undefined]],
                                          [[1,5,undefined], [3,5,undefined]])),
    ?assertEqual(false, is_swap_rebalance([[1,undefined], [1,undefined]],
                                          [[1,2], [1,2]])),
    ?assertEqual(false, is_swap_rebalance([[1,2], [1,2]],
                                          [[1,undefined], [1,undefined]])),
    ?assertEqual(false, is_swap_rebalance([[1,2,3], [2,3,1], [3,1,2]],
                                          [[1,5,undefined],[5,1,undefined],
                                           [1,5,undefined]])),
    ok.
-endif.
