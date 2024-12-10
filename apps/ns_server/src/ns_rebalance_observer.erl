%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2013-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

-module(ns_rebalance_observer).

-behavior(gen_server).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/4,
         get_detailed_progress/0,
         get_aggregated_progress/1,
         get_rebalance_info/0,
         get_current_stage/0,
         get_progress_for_alerting/1,
         record_rebalance_report/1,
         update_progress/3,
         submit_master_event/1,
         get_current_rebalance_report/0]).

%% gen_server callbacks
-export([code_change/3, init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, {via, leader_registry, ?MODULE}).
-define(DOCS_LEFT_REFRESH_INTERVAL, 5000).

-record(stat_info, {start_time = false,
                    end_time = false}).

-record(replica_building_stats, {node :: node(),
                                 in_docs_total :: non_neg_integer(),
                                 in_docs_left :: non_neg_integer()}).

-record(vbucket_info, {before_chain :: [node()],
                       after_chain :: [node()],
                       stats :: [#replica_building_stats{}],
                       move = #stat_info{},
                       backfill = #stat_info{},
                       takeover = #stat_info{},
                       persistence = #stat_info{}}).

-record(total_stat_info, {total_time = 0,
                          completed_count = 0}).

-record(vbucket_level_info, {move = #total_stat_info{},
                             backfill = #total_stat_info{},
                             takeover = #total_stat_info{},
                             persistence = #total_stat_info{},
                             vbucket_info = dict:new()}).

-record(compaction_info, {per_node = [] :: [{node(), #total_stat_info{}}],
                          in_progress = [] :: [{node(), #stat_info{}}]}).

-record(per_node_replication_stats, {in_docs_total = 0 :: non_neg_integer(),
                                     in_docs_left = 0 :: non_neg_integer(),
                                     out_docs_total = 0 :: non_neg_integer(),
                                     out_docs_left = 0 :: non_neg_integer()}).

-record(bucket_level_info, {bucket_name,
                            storage_mode,
                            bucket_timeline = #stat_info{},
                            replication_info = dict:new(),
                            compaction_info = #compaction_info{},
                            vbucket_level_info = #vbucket_level_info{}}).

-record(state, {bucket :: bucket_name() | undefined,
                buckets_count :: pos_integer(),
                bucket_number :: non_neg_integer(),
                stage_info :: rebalance_stage_info:stage_info(),
                nodes_info :: [{atom(), [node()]}],
                type :: atom(),
                rebalance_id :: binary(),
                bucket_info :: dict:dict(),
                rebalance_time :: #stat_info{}}).

start_link(Stages, NodesInfo, Type, Id) ->
    gen_server:start_link(?SERVER, ?MODULE, {Stages, NodesInfo, Type, Id}, []).

is_timeout(exit, timeout) ->
    true;
is_timeout(exit, {timeout, _}) ->
    true;
is_timeout(_, _) ->
    false.

generic_get_call(Call) ->
    generic_get_call(Call, ?REBALANCE_OBSERVER_TASK_DEFAULT_TIMEOUT).
generic_get_call(Call, Timeout) ->
    try
        gen_server:call(?SERVER, Call, Timeout)
    catch
        Type:Reason ->
            case is_timeout(Type, Reason) of
                true ->
                    ?log_info("Request ~p timed out after ~p secs",
                              [Call, Timeout/1000]),
                    {error, timeout};
                false ->
                    ?log_error("Unexpected exception ~p", [{Type, Reason}]),
                    not_running
            end
    end.

get_detailed_progress() ->
    generic_get_call(get_detailed_progress).

get_aggregated_progress(Timeout) ->
    generic_get_call(get_aggregated_progress, Timeout).

get_rebalance_info() ->
    generic_get_call({get_rebalance_info, []}).

-spec get_current_stage() -> atom() | {error, timeout} | not_running.
get_current_stage() ->
    generic_get_call(get_current_stage).

%% Get a progress indicator which only changes when the service is making
%% forwards progress. Doesn't have to be a percentage, as long as
%% "progress value increases" => "rebalance progress is being made"
-spec get_progress_for_alerting(atom()) ->
    {binary(), term()} | {error, timeout} | not_running.
get_progress_for_alerting(Service) ->
    generic_get_call({get_progress_for_alerting, Service}).

record_rebalance_report(Args) ->
    generic_get_call({record_rebalance_report, Args}).

get_current_rebalance_report() ->
    generic_get_call(get_current_rebalance_report).

update_progress(Stage, NotifyMetric, StageProgress) ->
    gen_server:cast(?SERVER, {update_progress, Stage, NotifyMetric,
                              StageProgress}).

get_registered_local_name() ->
    ?MODULE.

submit_master_event(Event) ->
    gen_server:cast(get_registered_local_name(), {note, Event}).

get_stage_nodes(Services, NodesInfo) ->
    ActiveNodes = proplists:get_value(active_nodes, NodesInfo, []),
    lists:filtermap(
      fun (Service) ->
              case ns_cluster_membership:service_nodes(ActiveNodes, Service) of
                  [] ->
                      false;
                  Nodes ->
                      {true, {Service, Nodes}}
              end
      end, lists:usort(Services)).

init({Services, NodesInfo, Type, Id}) ->
    Self = self(),
    StageInfo = rebalance_stage_info:init(get_stage_nodes(Services, NodesInfo)),
    Buckets = ns_bucket:get_buckets(),
    BucketsCount = length(Buckets),
    BucketLevelInfo = dict:from_list(
                        [{BN,
                          #bucket_level_info{
                             bucket_name = BN,
                             storage_mode = ns_bucket:storage_mode(Config)}}
                         || {BN, Config} <- Buckets]),
    proc_lib:spawn_link(erlang, apply, [fun docs_left_updater_init/1, [Self]]),
    erlang:register(get_registered_local_name(), self()),

    {ok, #state{bucket = undefined,
                buckets_count = BucketsCount,
                bucket_number = 0,
                stage_info = StageInfo,
                nodes_info = NodesInfo,
                type = Type,
                rebalance_id = Id,
                bucket_info = BucketLevelInfo,
                rebalance_time = #stat_info{start_time = os:timestamp()}}}.

get_event(rebalance, success) ->
    rebalance_completed;
get_event(rebalance, failure) ->
    rebalance_failed;
get_event(rebalance, interrupted) ->
    rebalance_interrupted;
get_event(graceful_failover, success) ->
    graceful_failover_completed;
get_event(graceful_failover, failure) ->
    graceful_failover_failed;
get_event(graceful_failover, interrupted) ->
    graceful_failover_interrupted;
get_event(hard_failover, success) ->
    hard_failover_completed;
get_event(hard_failover, failure) ->
    hard_failover_failed;
get_event(hard_failover, interrupted) ->
    hard_failover_interrupted;
get_event(auto_failover, success) ->
    auto_failover_completed;
get_event(auto_failover, failure) ->
    auto_failover_failed.

add_event_log(#state{type = Type,
                     nodes_info = NodesInfo,
                     rebalance_id = Id,
                     rebalance_time = #stat_info{start_time = StartTime,
                                                 end_time = EndTime}},
              ResultType, ExitInfo) ->
    TimeTaken = rebalance_stage_info:diff_timestamp(EndTime, StartTime),
    event_log:add_log(get_event(Type, ResultType),
                      [{operation_id, Id},
                       {nodes_info, {NodesInfo}},
                       {time_taken, TimeTaken},
                       {completion_message, ExitInfo}]).

maybe_add_event_log(#state{type = Type} = State,
                    ResultType, ExitInfo) when Type =:= rebalance orelse
                                               Type =:= graceful_failover orelse
                                               Type =:= hard_failover orelse
                                               Type =:= auto_failover ->
    add_event_log(State, ResultType, ExitInfo);
maybe_add_event_log(_, _, _) ->
    ok.

handle_call(get, _From, State) ->
    {reply, State, State};
handle_call(get_detailed_progress, _From, State) ->
    {reply, do_get_detailed_progress(State), State};
handle_call(get_aggregated_progress, _From,
            #state{stage_info = StageInfo} = State) ->
    {reply, {ok, dict:to_list(rebalance_stage_info:get_progress(StageInfo))},
     State};
handle_call({get_rebalance_info, Options}, _From,
            #state{stage_info = StageInfo,
                   nodes_info = NodesInfo,
                   rebalance_id = Id} = State) ->
    StageDetails = get_all_stage_rebalance_details(State, Options),
    RebalanceInfo = [{stageInfo, rebalance_stage_info:get_stage_info(
                                   StageInfo, StageDetails)},
                     {rebalanceId, Id},
                     {nodesInfo, {NodesInfo}},
                     {masterNode, atom_to_binary(node(), latin1)}],
    {reply, {ok, RebalanceInfo}, State};
handle_call(get_current_stage, _From,
            #state{stage_info = StageInfo} = State) ->
    Stage = rebalance_stage_info:get_current_stage(StageInfo),
    {reply, Stage, State};
handle_call({get_progress_for_alerting, kv}, From,
            #state{bucket = Bucket,
                   rebalance_id = Id} = State) ->
    %% Get the vbucket moves in progress
    spawn_link(
      fun () ->
              MinSeqnos =
                  case Bucket of
                      undefined ->
                          [];
                      _ ->
                          Moves = dict:to_list(get_all_vb_info(State, Bucket)),
                          SeqnosPerVB = get_seqnos_per_vb(Moves, Bucket),
                          [{VB, lists:min(Seqnos)} ||
                              {VB, [_ | _] = Seqnos} <- SeqnosPerVB]

                  end,
              gen_server:reply(From, {Id, MinSeqnos})
      end),
    {noreply, State};
handle_call({get_progress_for_alerting, Stage}, _From,
            #state{stage_info = StageInfo,
                   rebalance_id = Id} = State) ->
    {reply,
     {Id, rebalance_stage_info:get_progress_for_stage(Stage, StageInfo, [])},
     State};
handle_call({record_rebalance_report, {ResultType, ExitInfo}}, From,
            #state{nodes_info = NodesInfo,
                   rebalance_time = TotalTime0} = State0) ->
    EndTime = os:timestamp(),
    StartTime = TotalTime0#stat_info.start_time,
    TimeTaken = rebalance_stage_info:diff_timestamp(EndTime, StartTime),

    TotalTime = TotalTime0#stat_info{end_time = EndTime},
    State = State0#state{rebalance_time = TotalTime},

    {_, {ok, RebalanceInfo}, NewState} = handle_call(
                                           {get_rebalance_info,
                                            [{add_vbucket_info, true}]},
                                           From,
                                           State),

    maybe_add_event_log(NewState, ResultType, ExitInfo),

    Report = {RebalanceInfo ++
              [{startTime,
                rebalance_stage_info:binarify_timestamp(StartTime)},
               {completedTime,
                rebalance_stage_info:binarify_timestamp(EndTime)},
               {timeTaken, TimeTaken},
               {completionMessage, ExitInfo}]},

    KeepNodes = proplists:get_value(keep_nodes, NodesInfo, [node()]),
    RV = case ns_rebalance_report_manager:record_rebalance_report(
                ejson:encode(Report), KeepNodes) of
             ok ->
                 ok;
             Err ->
                 ?log_info("Unable to record report ~p, Error ~p",
                           [Report, Err], [{chars_limit, -1}]),
                 Err
         end,
    {reply, RV, NewState};
handle_call(get_current_rebalance_report, From,
            #state{rebalance_time = TotalTime0} = State) ->
    Now = os:timestamp(),
    StartTime = TotalTime0#stat_info.start_time,
    TimeTaken = rebalance_stage_info:diff_timestamp(Now, StartTime),

    {_, {ok, RebalanceInfo}, _NewState} = handle_call(
                                            {get_rebalance_info,
                                             [{add_vbucket_info, true}]},
                                            From,
                                            State),
    Report = {RebalanceInfo ++
              [{startTime,
                rebalance_stage_info:binarify_timestamp(StartTime)},
               {reportingTime,
                rebalance_stage_info:binarify_timestamp(Now)},
               {timeTaken, TimeTaken}]},
    {reply, {ok, Report}, State};
handle_call(Req, From, State) ->
    ?log_error("Got unknown request: ~p from ~p", [Req, From]),
    {reply, unknown_request, State}.

handle_cast({note, Event}, State) ->
    {noreply, handle_master_event(Event, State)};

handle_cast({update_stats, BucketName, VBucket, NodeToDocsLeft}, State) ->
    ?log_debug("Got update_stats: ~p, ~p", [VBucket, NodeToDocsLeft],
               [{chars_limit, -1}]),
    {noreply,
     update_move(
       State, BucketName, VBucket,
       fun (Move) ->
               NewStats =
                   [case lists:keyfind(Stat#replica_building_stats.node, 1,
                                       NodeToDocsLeft) of
                        {_, NewLeft} ->
                            #replica_building_stats{in_docs_total = Total,
                                                    in_docs_left = Left} = Stat,

                            case NewLeft >= Left of
                                true ->
                                    %% our initial estimates are imprecise, so
                                    %% we can end up in a situation where new
                                    %% in_docs_left is greater than
                                    %% in_docs_total;
                                    %%
                                    %% another possibility is that there're new
                                    %% mutations coming; in such case if we
                                    %% didn't adjust in_docs_total it would seem
                                    %% to the user that number of transfered
                                    %% items went down which is probably not
                                    %% desireable;
                                    %%
                                    %% obviously, this adjustment may lose some
                                    %% mutations (meaning that final doc_total
                                    %% wouldn't be precise) but user
                                    %% experience-wise it seems to be better.
                                    Increase = NewLeft - Left,
                                    Stat#replica_building_stats{
                                      in_docs_left = NewLeft,
                                      in_docs_total = Total + Increase};
                                false ->
                                    Stat#replica_building_stats{
                                      in_docs_left = NewLeft}
                            end;
                        false ->
                            Stat
                    end || Stat <- Move#vbucket_info.stats],
               Move#vbucket_info{stats = NewStats}
       end)};

handle_cast({update_progress, Stage, NotifyMetric, StageProgress},
            #state{stage_info = Old} = State) ->
    NewStageInfo = rebalance_stage_info:update_progress(
                     Stage, NotifyMetric, StageProgress, Old),
    {noreply, State#state{stage_info = NewStageInfo}};

handle_cast(Req, _State) ->
    ?log_error("Got unknown cast: ~p", [Req]),
    erlang:error({unknown_cast, Req}).

initiate_bucket_rebalance(BucketName, _, _Verbose, OldState)
  when OldState#state.bucket =:= BucketName ->
    OldState;
initiate_bucket_rebalance(BucketName, {Moves, UndefinedMoves}, Verbose,
                          OldState) ->
    BuildDestinations0 = [{MasterNode, VB}
                          || {VB, [MasterNode|_], _ChainAfter, _} <- Moves],
    BuildDestinations1 = [{N, VB} || {VB, [MasterNode|_], ChainAfter, _} <- Moves,
                                     N <- ChainAfter, N =/= undefined, N =/= MasterNode],

    BuildDestinations =
        %% the following groups vbuckets to per node. [{a, 1}, {a, 2}, {b, 3}] => [{a, [1,2]}, {b, [3]}]
        keygroup_sorted(lists:merge(lists:sort(BuildDestinations0),
                                    lists:sort(BuildDestinations1))),

    SomeEstimates0 = misc:parallel_map(
                       fun ({Node, VBs}) ->
                               {ok, DcpEstimates} =
                                   janitor_agent:get_mass_dcp_docs_estimate(BucketName, Node, VBs),

                               [{{Node, VB}, {VBEstimate, VBChkItems}} ||
                                   {VB, {VBEstimate, VBChkItems, _}} <-
                                       lists:zip(VBs, DcpEstimates)]
                       end, BuildDestinations, infinity),


    SomeEstimates = lists:append(SomeEstimates0),

    Verbose andalso ?log_debug("Initial estimates:~n~p", [SomeEstimates],
                               [{chars_limit, -1}]),

    BuiltMoves =
        [begin
             {_, {MasterEstimate, _}} = lists:keyfind({MasterNode, VB}, 1, SomeEstimates),
             RBStats =
                 [begin
                      {_, {ReplicaEstimate, _}} = lists:keyfind({Replica, VB}, 1, SomeEstimates),
                      Estimate = case ReplicaEstimate =< MasterEstimate of
                                     true ->
                                         MasterEstimate - ReplicaEstimate;
                                     _ ->
                                         MasterEstimate
                                 end,
                      #replica_building_stats{node = Replica,
                                              in_docs_total = Estimate,
                                              in_docs_left = Estimate}
                  end || Replica <- ChainAfter,
                         Replica =/= undefined,
                         Replica =/= MasterNode],
             {VB, #vbucket_info{before_chain = ChainBefore,
                                after_chain = ChainAfter,
                                stats = RBStats}}
         end || {VB, [MasterNode|_] = ChainBefore, ChainAfter, _} <- Moves],

    BuiltUndefinedMoves = [{VB, #vbucket_info{before_chain = ChainBefore,
                                              after_chain = ChainAfter,
                                              stats = []}}
                           || {VB, ChainBefore, ChainAfter, _} <- UndefinedMoves],

    AllMoves = BuiltMoves ++ BuiltUndefinedMoves,
    Verbose andalso ?log_debug("Moves:~n~p", [AllMoves], [{chars_limit, -1}]),
    TmpState = update_vb_and_rep_info(OldState, BucketName,
                                      dict:from_list(AllMoves)),
    TmpState#state{bucket = BucketName}.

handle_master_event({rebalance_stage_started, Stage, Nodes}, State) ->
    update_stage(Stage, {started, Nodes}, State);

handle_master_event({rebalance_stage_completed, Stage}, State) ->
    update_stage(Stage, completed, State);

handle_master_event({rebalance_stage_event, Stage, Text}, State) ->
    update_stage(Stage, {notable_event, Text}, State);

handle_master_event({failover, Nodes}, State) ->
    update_stage([failover], {started, Nodes}, State);

handle_master_event({failover_ended}, State) ->
    update_stage([failover], completed, State);

handle_master_event({bucket_failover_started, BucketName, Nodes, _}, State) ->
    update_stage([failover, BucketName], {started, Nodes}, State);

handle_master_event({bucket_failover_ended, BucketName, _, _}, State) ->
    update_stage([failover, BucketName], completed, State);

handle_master_event({bucket_rebalance_started, BucketName, _Pid},
                    #state{bucket_number = Number} = State) ->
    TmpState = update_info(bucket_rebalance_started, State,
                           {os:timestamp(), BucketName, undefined, undefined}),
    TmpState#state{bucket_number = Number + 1};

handle_master_event({bucket_rebalance_ended, BucketName, _Pid}, State) ->
    update_info(bucket_rebalance_ended, State,
                {os:timestamp(), BucketName, undefined, undefined});

handle_master_event({planned_moves, BucketName, MovesTuple, Verbose}, State) ->
    initiate_bucket_rebalance(BucketName, MovesTuple, Verbose, State);

handle_master_event({vbucket_move_start, _Pid, BucketName,
                     _Node, VBucketId, _, _}, State) ->
    ?log_debug("Noted vbucket move start (vbucket ~p)", [VBucketId]),
    update_info(vbucket_move_start, State, {os:timestamp(), BucketName,
                                            VBucketId, undefined});

handle_master_event({vbucket_move_done, BucketName, VBucket}, State) ->
    State1 = update_move(
               State, BucketName, VBucket,
               fun (#vbucket_info{stats=Stats} = Move) ->
                       Stats1 = [S#replica_building_stats{in_docs_left=0} ||
                                    S <- Stats],
                       Move#vbucket_info{stats=Stats1}
               end),
    ?log_debug("Noted vbucket move end (vbucket ~p)", [VBucket]),
    update_info(vbucket_move_done, State1,
                {os:timestamp(), BucketName, VBucket, undefined});

handle_master_event({Event, BucketName, Node}, State)
  when Event =:= compaction_uninhibit_started;
       Event =:= compaction_uninhibit_done ->
    update_info(Event, State, {os:timestamp(), BucketName, undefined, Node});

handle_master_event({Event, BucketName, VBucket, _, _}, State)
  when Event =:= takeover_started;
       Event =:= takeover_ended;
       Event =:= seqno_waiting_started;
       Event =:= seqno_waiting_ended ->
    update_info(Event, State, {os:timestamp(), BucketName, VBucket, undefined});

handle_master_event({Event, BucketName, VBucket}, State)
  when Event =:= backfill_phase_started;
       Event =:= backfill_phase_ended ->
    update_info(Event, State, {os:timestamp(), BucketName, VBucket, undefined});

handle_master_event(_, State) ->
    State.

update_stage(Stage, Info, #state{stage_info = Old} = State) ->
    State#state{stage_info =
                    rebalance_stage_info:update_stage_info(
                      Stage, Info, os:timestamp(), Old)}.

update_move(State, BucketName, VBucket, Fun) ->
    update_vb_and_rep_info(State, BucketName,
                           dict:update(VBucket, Fun,
                                       get_all_vb_info(State, BucketName))).

handle_info(Msg, State) ->
    ?log_error("Got unexpected message: ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

docs_left_updater_init(Parent) ->
    send_refresh_msg(),
    docs_left_updater_loop(Parent).

docs_left_updater_loop(Parent) ->
    State = gen_server:call(Parent, get, infinity),
    BucketName = State#state.bucket,
    Moves = dict:to_list(get_all_vb_info(State, BucketName)),
    case BucketName of
        undefined ->
            ok;
        _ ->
            %% This log can get spammy if the rebalance is slow to make
            %% progress. So log the info into the trace.log file.
            ?log_trace("Starting docs_left_updater_loop:~p~n~p~n",
                       [BucketName, Moves], [{chars_limit, -1}])
    end,
    [update_docs_left_for_move(Parent, BucketName, VB, VBInfo)
     || {VB, VBInfo} <- Moves,
        hd(VBInfo#vbucket_info.before_chain) =/= undefined,
        VBInfo#vbucket_info.move#stat_info.start_time =/= false,
        VBInfo#vbucket_info.move#stat_info.end_time =:= false],
    receive
        refresh ->
            send_refresh_msg(),
            docs_left_updater_loop(Parent)
    end.

get_docs_estimate(BucketName, VBucket, #vbucket_info{before_chain = [MasterNode|_],
                                                     stats = RStats}) ->
    ReplicaNodes = [S#replica_building_stats.node || S <- RStats],
    janitor_agent:get_dcp_docs_estimate(BucketName, MasterNode, VBucket, ReplicaNodes).

update_docs_left_for_move(Parent, BucketName, VBucket,
                          #vbucket_info{stats = RStats} = MoveState) ->
    try get_docs_estimate(BucketName, VBucket, MoveState) of
        NewLefts ->
            Stuff =
                lists:flatmap(
                  fun ({OkE, Stat}) ->
                          {ok, {E, _, Status}} = OkE,

                          %% we expect vbucket to still be replicated; if it
                          %% is not the case, we will get bad estimate
                          case Status =:= <<"backfilling">> orelse
                              Status =:= <<"backfill completed">> of
                              true ->
                                  [{Stat#replica_building_stats.node, E}];
                              false ->
                                  []
                          end
                  end, lists:zip(NewLefts, RStats)),

            case Stuff of
                [] ->
                    ok;
                _ ->
                    gen_server:cast(Parent,
                                    {update_stats, BucketName, VBucket, Stuff})
            end
    catch
        error:{janitor_agent_servant_died, _} ->
            ?log_debug("Apparently move of ~p is already done", [VBucket]),
            ok;
        T:E ->
            %% Ignore exceptions from get_docs_estimate, we expect rebalance to
            %% fail on continued exception.
            ?log_debug("Exception in get_docs_estimate ~p", [{T, E}]),
            ok
    end.

send_refresh_msg() ->
    erlang:send_after(?DOCS_LEFT_REFRESH_INTERVAL, self(), refresh).

keygroup_sorted(Items) ->
    lists:foldr(
      fun ({K, V}, Acc) ->
              case Acc of
                  [{K, AccVs} | Rest] ->
                      [{K, [V | AccVs]} | Rest];
                  _ ->
                      [{K, [V]} | Acc]
              end
      end, [], Items).

get_replication_info(#state{bucket_info = BI}, BucketName) ->
    {ok, BLI} = dict:find(BucketName, BI),
    BLI#bucket_level_info.replication_info.

do_get_detailed_progress(#state{bucket = undefined}) ->
    not_running;
do_get_detailed_progress(#state{bucket = Bucket,
                                buckets_count = BucketsCount,
                                bucket_number = BucketNumber} = State) ->
    AllMoves = get_all_vb_info(State, Bucket),
    {CurrentMoves, PendingMoves} =
        dict:fold(
          fun (_, #vbucket_info{move = MoveStat} = VBInfo, {CM, PM}) ->
                  case {MoveStat#stat_info.start_time,
                        MoveStat#stat_info.end_time} of
                      {false, _} ->
                          {CM, [VBInfo | PM]};
                      {_, false} ->
                          {[VBInfo | CM], PM};
                      {_, _} ->
                          {CM, PM}
                  end
          end, {[], []}, AllMoves),

    Inc = fun (undefined, Dict) ->
                  Dict;
              (Node, Dict) ->
                  dict:update(Node,
                              fun (C) ->
                                      C + 1
                              end, 1, Dict)
          end,

    {MovesInActive, MovesOutActive, MovesInReplica, MovesOutReplica} =
        lists:foldl(
          fun (#vbucket_info{before_chain=[OldMaster|OldReplicas],
                             after_chain=[NewMaster|NewReplicas]},
               {AccInA, AccOutA, AccInR, AccOutR}) ->
                  {AccInA1, AccOutA1} =
                      case OldMaster =:= NewMaster of
                          true ->
                              {AccInA, AccOutA};
                          false ->
                              {Inc(NewMaster, AccInA), Inc(OldMaster, AccOutA)}
                      end,

                  AccInR1 =
                      lists:foldl(
                        fun (N, Acc) ->
                                Inc(N, Acc)
                        end, AccInR, NewReplicas -- OldReplicas),

                  AccOutR1 =
                      lists:foldl(
                        fun (N, Acc) ->
                                Inc(N, Acc)
                        end, AccOutR, OldReplicas -- NewReplicas),

                  {AccInA1, AccOutA1, AccInR1, AccOutR1}
          end, {dict:new(), dict:new(), dict:new(), dict:new()},
          CurrentMoves ++ PendingMoves),

    ReplicationInfo = get_replication_info(State, Bucket),
    NodesProgress =
        lists:foldl(
          fun (N, Acc) ->
                  PerNode = misc:dict_get(N, ReplicationInfo,
                                          #per_node_replication_stats{}),
                  #per_node_replication_stats{
                     in_docs_total = InTotal,
                     in_docs_left = InLeft,
                     out_docs_total = OutTotal,
                     out_docs_left = OutLeft} = PerNode,

                  InA = misc:dict_get(N, MovesInActive, 0),
                  OutA = misc:dict_get(N, MovesOutActive, 0),
                  InR = misc:dict_get(N, MovesInReplica, 0),
                  OutR = misc:dict_get(N, MovesOutReplica, 0),

                  Ingoing = [{docsTotal, InTotal},
                             {docsTransferred, InTotal - InLeft},
                             {activeVBucketsLeft, InA},
                             {replicaVBucketsLeft, InR}],

                  Outgoing = [{docsTotal, OutTotal},
                              {docsTransferred, OutTotal - OutLeft},
                              {activeVBucketsLeft, OutA},
                              {replicaVBucketsLeft, OutR}],

                  Info = {N, Ingoing, Outgoing},
                  [Info | Acc]
          end, [], ns_node_disco:nodes_wanted()),

    GlobalDetails = [{bucket, list_to_binary(Bucket)},
                     {bucketNumber, BucketNumber},
                     {bucketsCount, BucketsCount}],
    {ok, GlobalDetails, NodesProgress}.


moves_stats(Moves) ->
    dict:fold(
      fun (_, #vbucket_info{stats=Stats,
                            before_chain=[OldMaster|_]}, Acc) ->
              true = (OldMaster =/= undefined orelse Stats =:= []),

              lists:foldl(
                fun (#replica_building_stats{node=DstNode,
                                             in_docs_total=Total,
                                             in_docs_left=Left},
                     Dict) ->
                        true = (Left =< Total),

                        TmpDict = dict:update(
                                    OldMaster,
                                    fun (#per_node_replication_stats{
                                            out_docs_total = AccTotal,
                                            out_docs_left = AccLeft} = RI) ->
                                            RI#per_node_replication_stats{
                                              out_docs_total = AccTotal + Total,
                                              out_docs_left = AccLeft + Left}
                                    end,
                                    #per_node_replication_stats{
                                       out_docs_total = Total,
                                       out_docs_left = Left},
                                    Dict),
                        dict:update(DstNode,
                                    fun (#per_node_replication_stats{
                                            in_docs_total = AccTotal,
                                            in_docs_left = AccLeft} = RI) ->
                                            RI#per_node_replication_stats{
                                              in_docs_total = AccTotal + Total,
                                              in_docs_left = AccLeft + Left}
                                    end,
                                    #per_node_replication_stats{
                                       in_docs_total = Total,
                                       in_docs_left = Left},
                                    TmpDict)
                end, Acc, Stats)
      end, dict:new(), Moves).

ignore_event_for_bucket(Event,
                        #bucket_level_info{storage_mode = StorageMode}) ->
    (StorageMode =:= undefined orelse StorageMode =:= ephemeral) andalso
        (Event =:= compaction_uninhibit_started orelse
         Event =:= compaction_uninhibit_done orelse
         Event =:= seqno_waiting_started orelse
         Event =:= seqno_waiting_ended).

update_info(Event,
            #state{bucket_info = OldBucketLevelInfo} = State,
            {_TS, BucketName, _VB, _EventSpecific} = UpdateArgs) ->
    NewBucketLevelInfo =
        dict:update(
          BucketName,
          fun (BLI0) ->
                  case ignore_event_for_bucket(Event, BLI0) of
                      false ->
                          BLI1 = update_bucket_level_info(Event, BLI0,
                                                          UpdateArgs),
                          update_vbucket_level_info(Event, BLI1, UpdateArgs);
                      true ->
                          BLI0
                  end
          end, OldBucketLevelInfo),
    State#state{bucket_info = NewBucketLevelInfo}.

update_bucket_level_info(compaction_uninhibit_started,
                         BucketLevelInfo,
                         {TS, _Bucket, _VB, Node}) ->
    Compaction = BucketLevelInfo#bucket_level_info.compaction_info,
    InProgress = Compaction#compaction_info.in_progress,
    case lists:keyfind(Node, 1, InProgress) of
        false ->
            NewInprogress = [{Node, #stat_info{start_time = TS}} | InProgress],
            NewCompaction = Compaction#compaction_info{
                              in_progress = NewInprogress},
            BucketLevelInfo#bucket_level_info{compaction_info = NewCompaction};
        _ ->
            BucketLevelInfo
    end;
update_bucket_level_info(compaction_uninhibit_done,
                         BucketLevelInfo,
                         {TS, _Bucket, _VB, Node}) ->
    Compaction = BucketLevelInfo#bucket_level_info.compaction_info,
    InProgress = Compaction#compaction_info.in_progress,
    case lists:keytake(Node, 1, InProgress) of
        false ->
            BucketLevelInfo;
        {value, {Node, CompactionStat}, NewInprogress} ->
            BucketLevelInfo#bucket_level_info{
              compaction_info = update_on_compaction_end(
                                  Compaction, Node,
                                  CompactionStat#stat_info{end_time = TS},
                                  NewInprogress)}
    end;
update_bucket_level_info(bucket_rebalance_started, BucketLevelInfo,
                         {TS, _Bucket, _, _}) ->
    BucketLevelInfo#bucket_level_info{
      bucket_timeline = #stat_info{start_time = TS}};
update_bucket_level_info(bucket_rebalance_ended, BucketLevelInfo,
                         {TS, _Bucket, _, _}) ->
    NewBucketLevelInfo = update_replication_info(BucketLevelInfo),
    TL = NewBucketLevelInfo#bucket_level_info.bucket_timeline,
    NewBucketLevelInfo#bucket_level_info{
      bucket_timeline = TL#stat_info{end_time = TS}};
update_bucket_level_info(_, BLI, _) ->
    BLI.

is_bucket_rebalance_running(#bucket_level_info{bucket_timeline = BT}) ->
    BT#stat_info.start_time =/= false andalso BT#stat_info.end_time =:= false.

update_replication_info(BucketLevelInfo) ->
    case is_bucket_rebalance_running(BucketLevelInfo) of
        true ->
            BucketLevelInfo#bucket_level_info{
              replication_info = moves_stats(get_all_vb_info(
                                               BucketLevelInfo))};
        false ->
            BucketLevelInfo
    end.

update_on_compaction_end(#compaction_info{per_node = OldPerNode},
                         Node,
                         NewCompactionStat,
                         NewInprogress) ->
    NewPerNode = case lists:keytake(Node, 1, OldPerNode) of
                     {value, {Node, TotalStat}, PerNode} ->
                         NewTotalStat = update_total_stat(TotalStat,
                                                          NewCompactionStat),
                         [{Node, NewTotalStat} | PerNode];
                    false ->
                         NewTotalStat = update_total_stat(#total_stat_info{},
                                                          NewCompactionStat),
                         [{Node, NewTotalStat} | OldPerNode]
                 end,
    #compaction_info{per_node = NewPerNode,
                     in_progress = NewInprogress}.

get_all_vb_info(_, undefined) ->
    dict:new();
get_all_vb_info(#state{bucket_info = BucketInfo}, BucketName) ->
    {ok, BucketLevelInfo} = dict:find(BucketName, BucketInfo),
    get_all_vb_info(BucketLevelInfo).

get_all_vb_info(BucketLevelInfo) ->
    BucketLevelInfo#bucket_level_info.vbucket_level_info#vbucket_level_info.vbucket_info.

update_vb_and_rep_info(#state{bucket_info = OldBucketInfo} = State,
                       BucketName, NewAllVBInfo) ->
    NewBucketInfo = dict:update(
                      BucketName,
                      fun (BLI) ->
                              TmpBLI = update_all_vb_info(BLI, NewAllVBInfo),
                              update_replication_info(TmpBLI)
                      end, OldBucketInfo),
    State#state{bucket_info = NewBucketInfo}.

update_all_vb_info(#bucket_level_info{
                      vbucket_level_info = VBLevelInfo} = BucketLevelInfo,
                   AllVBInfo) ->
    NewVBLevelInfo = VBLevelInfo#vbucket_level_info{vbucket_info = AllVBInfo},
    BucketLevelInfo#bucket_level_info{vbucket_level_info = NewVBLevelInfo}.

update_vbucket_level_info(_Event, BucketLevelInfo,
                          {_TS, _BucketName, undefined, _Args}) ->
    BucketLevelInfo;
update_vbucket_level_info(Event, BucketLevelInfo,
                          {_TS, _BucketName, VB, _Args} = UpdateArgs) ->
    AllVBInfo = get_all_vb_info(BucketLevelInfo),
    case dict:find(VB, AllVBInfo) of
        {ok, VBInfo} ->
            NewVBInfo = update_vbucket_info(Event, VBInfo, UpdateArgs),
            BLI = update_vbucket_level_info_inner(Event, BucketLevelInfo, NewVBInfo),
            update_all_vb_info(BLI, dict:store(VB, NewVBInfo, AllVBInfo));
        _ ->
            BucketLevelInfo
    end.

find_event_action(Event) ->
    %% {Event, TotalElement, StatElement, stat_op}
    EventAction = [
                   {vbucket_move_start, undefined,
                    #vbucket_info.move, start_time},
                   {vbucket_move_done, #vbucket_level_info.move,
                    #vbucket_info.move, end_time},

                   {backfill_phase_started, undefined,
                    #vbucket_info.backfill, start_time},
                   {backfill_phase_ended, #vbucket_level_info.backfill,
                    #vbucket_info.backfill, end_time},

                   {takeover_started, undefined,
                    #vbucket_info.takeover, start_time},
                   {takeover_ended, #vbucket_level_info.takeover,
                    #vbucket_info.takeover, end_time},

                   {seqno_waiting_started, undefined,
                    #vbucket_info.persistence, start_time},
                   {seqno_waiting_ended, #vbucket_level_info.persistence,
                    #vbucket_info.persistence, end_time}
                  ],
    lists:keyfind(Event, 1, EventAction).

update_stat(start_time, _, TS) ->
    #stat_info{start_time = TS};
update_stat(end_time, Stat, TS) ->
    Stat#stat_info{end_time = TS}.

update_vbucket_info(Event, VBInfo, {TS, _Bucket, _VB, _Args}) ->
    case find_event_action(Event) of
        false ->
            VBInfo;
        {Event, _TotalElement, StatElement, StatOp} ->
            misc:update_field(StatElement, VBInfo,
                              ?cut(update_stat(StatOp, _, TS)))
    end.

update_total_stat(TotalStat, #stat_info{end_time = false}) ->
    TotalStat;
update_total_stat(#total_stat_info{total_time = TT, completed_count = C},
                  #stat_info{start_time = ST, end_time = ET}) ->
    NewTime = rebalance_stage_info:diff_timestamp(ET, ST),
    #total_stat_info{total_time = TT + NewTime,
                     completed_count = C + 1}.

update_vbucket_level_info_inner(
  Event,
  #bucket_level_info{vbucket_level_info = VBLevelInfo} = BucketLevelInfo,
  NewVBInfo) ->
    case find_event_action(Event) of
        false ->
            BucketLevelInfo;
        {_, undefined, _, _} ->
            BucketLevelInfo;
        {Event, TotalElement, StatElement, _StatOp} ->
            Stat = erlang:element(StatElement, NewVBInfo),
            TotalInfo = erlang:element(TotalElement, VBLevelInfo),
            NewTotalInfo = update_total_stat(TotalInfo, Stat),
            NewVBLevelInfo = erlang:setelement(TotalElement, VBLevelInfo,
                                               NewTotalInfo),
            BucketLevelInfo#bucket_level_info{
              vbucket_level_info = NewVBLevelInfo}
    end.

construct_bucket_level_info_json(
  #bucket_level_info{bucket_name = BucketName,
                     bucket_timeline = TL,
                     replication_info = ReplicationInfo,
                     compaction_info = CompactionInfo,
                     vbucket_level_info = VBLevelInfo}, Options) ->
    case construct_compaction_info_json(CompactionInfo) ++
             construct_vbucket_level_info_json(VBLevelInfo, Options) ++
             construct_replication_info(ReplicationInfo) of
        [] ->
            [];
        BLI ->
            {Stat} = construct_stat_info_json(TL),
            [{BucketName, {BLI ++ Stat}}]
    end.

construct_replication_info(ReplicationInfo) ->
    Info = dict:map(fun (_Node, #per_node_replication_stats{
                                   in_docs_total = InTotal,
                                   in_docs_left = InLeft,
                                   out_docs_total = OutTotal,
                                   out_docs_left = OutLeft}) ->
                            {[{inDocsTotal, InTotal},
                              {inDocsLeft, InLeft},
                              {outDocsTotal, OutTotal},
                              {outDocsLeft, OutLeft}]}
                    end, ReplicationInfo),
    case dict:is_empty(Info) of
        true -> [];
        false -> [{replicationInfo, {dict:to_list(Info)}}]
    end.

construct_compaction_info_json(#compaction_info{per_node = PerNode,
                                                in_progress = InProgress}) ->
    InProgressElem = {inProgress,
                      {[{Node, construct_stat_info_json(StatInfo)} ||
                        {Node, StatInfo} <- InProgress]}},
    PerNodeElem = {perNode,
                   {[{Node, construct_total_stat_info_json(TotalStatInfo)} ||
                   {Node, TotalStatInfo} <- PerNode]}},
    case {PerNode, InProgress} of
        {[], []} -> [];
        {[], _} -> [{compactionInfo, {[InProgressElem]}}];
        {_, []} -> [{compactionInfo, {[PerNodeElem]}}];
        _ -> [{compactionInfo, {[InProgressElem, PerNodeElem]}}]
    end.

construct_stat_info_json(#stat_info{start_time = false}) ->
    {[{startTime, rebalance_stage_info:binarify_timestamp(false)}]};
construct_stat_info_json(#stat_info{start_time = ST,
                                    end_time = ET}) ->
    {[{startTime, rebalance_stage_info:binarify_timestamp(ST)},
      {completedTime, rebalance_stage_info:binarify_timestamp(ET)},
      {timeTaken, rebalance_stage_info:diff_timestamp(ET, ST)}]}.

average(_, 0) ->
    0;
average(Total, Count) ->
    Total/Count.

construct_total_stat_info_json(TotalStatInfo) ->
    construct_total_stat_info_json(TotalStatInfo, undefined).

construct_total_stat_info_json(#total_stat_info{total_time = TT,
                                                completed_count = CC},
                               TotalCount) ->
    CountJson = case TotalCount of
                    undefined ->
                        [];
                    _ ->
                        [{totalCount, TotalCount},
                         {remainingCount, TotalCount - CC}]
                end,
    {[{averageTime, average(TT, CC)}] ++ CountJson}.

construct_replica_building_stats_json(#replica_building_stats{
                                         node = Node,
                                         in_docs_total = DT,
                                         in_docs_left = DL}) ->
    {Node, {[{node, Node},
             {inDocsTotal, DT},
             {inDocsLeft, DL}]}}.

construct_vbucket_info_json(Id, #vbucket_info{before_chain = BC,
                                              after_chain = AC,
                                              stats = RBS,
                                              move = Move,
                                              backfill = Backfill,
                                              takeover = Takeover,
                                              persistence = Persistence}) ->
    RInfoJson = case RBS of
                    [] ->
                        [];
                    _ ->
                        [{replicationInfo,
                          {[construct_replica_building_stats_json(X)
                            || X <- RBS]}}]
                end,
    {[{id, Id},
      {beforeChain, BC},
      {afterChain, AC},
      {move, construct_stat_info_json(Move)},
      {backfill, construct_stat_info_json(Backfill)},
      {takeover, construct_stat_info_json(Takeover)},
      {persistence, construct_stat_info_json(Persistence)}] ++ RInfoJson}.

construct_vbucket_level_info_json(VBLevelInfo, Options) ->
    case dict:is_empty(VBLevelInfo#vbucket_level_info.vbucket_info) of
        true ->
            [];
        false ->
            [{vbucketLevelInfo,
              construct_vbucket_level_info_json_inner(VBLevelInfo, Options)}]
    end.

construct_vbucket_level_info_json_inner(
  #vbucket_level_info{move = Move,
                      backfill = Backfill,
                      takeover = Takeover,
                      persistence = Persistence,
                      vbucket_info = AllVBInfo}, Options) ->
    VBI = case proplists:get_bool(add_vbucket_info, Options) of
              true ->
                  [{vbucketInfo,
                    dict:fold(fun (VB, Info, Acc) ->
                                      [construct_vbucket_info_json(VB, Info) | Acc]
                              end, [], AllVBInfo)}];
              _ ->
                  []
          end,
    {[{move, construct_total_stat_info_json(Move, dict:size(AllVBInfo))},
      {backfill, construct_total_stat_info_json(Backfill)},
      {takeover, construct_total_stat_info_json(Takeover)},
      {persistence, construct_total_stat_info_json(Persistence)}]
     ++ VBI}.

get_all_stage_rebalance_details(#state{bucket_info = BucketLevelInfo},
                                Options) ->
    RV = dict:fold(
           fun (_Key, BLI, Acc) ->
                   construct_bucket_level_info_json(BLI, Options) ++ Acc
           end, [], BucketLevelInfo),
    case RV of
        [] -> [];
        _ -> [{kv, {RV}}]
    end.

%% For each vbucket move in progress for a bucket, get the seqno for each
%% node that we will wait for to be caught up
get_seqnos_per_vb(Moves, Bucket) ->
    %% We only care about the vbs that require waiting for seqno persistence,
    %% which is those that are in the after chain and are not the previous
    %% active vbucket
    NodeVBs = [{Node, VB} ||
                  {VB, #vbucket_info{before_chain = [OldNode|_],
                                     after_chain = AfterChain,
                                     move = Move}} <- Moves,
                  Move#stat_info.start_time =/= false,
                  Move#stat_info.end_time =:= false,
                  Node <- AfterChain, Node =/= undefined, Node =/= OldNode],
    %% Sort the moves, grouped by node
    VBsPerNode = keygroup_sorted(lists:sort(NodeVBs)),
    %% Looks up the seqno of a vbucket, with a default value of 0 so that we
    %% can track the vbucket before the replication stream has been set up
    GetVBSeqno =
        fun (Seqnos, VB) ->
                case lists:keyfind(VB, 1, Seqnos) of
                    {VB, _Seqno} = Pair -> Pair;
                    false -> {VB, 0}
                end
        end,
    %% Fetches the seqno of each vbucket in VBs from Node
    GetNodeSeqnos =
        fun ({Node, VBs}) ->
                case janitor_agent:get_all_vb_seqnos(Bucket, Node) of
                    {ok, Seqnos} ->
                        lists:map(GetVBSeqno(Seqnos, _), VBs);
                    _Error ->
                        []
                end
        end,
    %% Get all seqnos for each vbucket in VBsPerNode, by fetching from each
    %% node in parallel
    SeqnosPerVB = lists:append(misc:parallel_map(GetNodeSeqnos, VBsPerNode,
                                                 infinity)),
    keygroup_sorted(lists:sort(SeqnosPerVB)).

-ifdef(TEST).
test_get_rebalance_info() ->
    gen_server:call(?MODULE,
                    {get_rebalance_info, [{add_vbucket_info, true}]},
                    30000).

test_get_progress_for_alerting(Service) ->
    gen_server:call(?MODULE, {get_progress_for_alerting, Service}, 30000).

-define(REBALANCE_ID, <<"rebalanceID">>).

setup_test_ns_rebalance_observer() ->
    meck:new(janitor_agent, [passthrough]),
    meck:expect(janitor_agent, get_mass_dcp_docs_estimate,
                fun (_, _, VBs) ->
                        {ok, lists:duplicate(length(VBs), {10, 2, random_state})}
                end),
    meck:expect(janitor_agent, get_dcp_docs_estimate,
                fun (_, _, VB, _) ->
                        [{ok, {VB, 0, <<"backfilling">>}}]
                end),

    meck:new(cluster_compat_mode, [passthrough]),
    meck:expect(cluster_compat_mode, is_enterprise,
                fun () -> true end),
    meck:expect(cluster_compat_mode, is_cluster_morpheus,
                fun () -> true end),

    meck:new(ns_bucket, [passthrough]),
    meck:expect(ns_bucket, get_buckets,
                fun () ->
                        [{"Bucket1",
                          [{storage_mode, couchstore},
                           {type, membase},
                           {num_vbuckets, 2},
                           {servers, ['n_0', 'n_1']},
                           {map, [['n_0','n_1'], ['n_1','n_0']]}]}]
                end),
    meck:new(ale, [passthrough]),
    meck:expect(ale, debug,
                fun (_, _) -> ok end),
    meck:expect(ale, debug,
                fun (_, _, _) -> ok end),
    meck:expect(ale, debug,
                fun (_, _, _, _) -> ok end),
    {ok, Pid} = gen_server:start_link(?MODULE,
                                      {[], [{active_nodes, [n1, n0]}],
                                       rebalance, ?REBALANCE_ID},
                                      []),
    %% Ensure that gen_server:cast({via, leader_registry makes it to the server
    meck:expect(leader_registry, send,
                fun (Name, {'$gen_cast', Msg}) ->
                        gen_server:cast(Name, Msg)
                end),
    Pid.

teardown_test_ns_rebalance_observer(Pid) ->
    gen_server:stop(Pid),
    meck:unload().

ns_rebalance_observer_test_() ->
    {foreach,
     fun setup_test_ns_rebalance_observer/0,
     fun teardown_test_ns_rebalance_observer/1,
     [{"rebalance", fun rebalance/0},
      {"failover", fun failover/0},
      {"get_all_vb_seqnos", fun get_all_vb_seqnos/0},
      {"get_seqnos_per_vb", fun get_seqnos_per_vb_t/0},
      {"index progress", fun get_index_progress_t/0}]}.

rebalance() ->
    try
        rebalance_inner()
    catch
        exit:{timeout,_} ->
            %% This test occasionally times out when running code validation
            %% on jenkins servers. It's suspected to be related to extensive
            %% logging done by upstream tests. As the failures on jenkins are
            %% intermittent and don't occur locally we'll allow the timeout
            %% rather than comment out the test.
            ok
    end.

rebalance_inner() ->
    submit_master_event({rebalance_stage_started, [kv], [n1, n0]}),
    submit_master_event({rebalance_stage_started, [kv, kv_delta_recovery], [n1]}),
    submit_master_event({rebalance_stage_completed, [kv, kv_delta_recovery]}),
    submit_master_event({bucket_rebalance_started, "Bucket1", unused}),
    submit_master_event({planned_moves, "Bucket1",
                         {[{0, [n_0, n_1], [n_1, n_0], []}], []}, false}),
    submit_master_event({vbucket_move_start, unused, "Bucket1",
                         unused, 0, unused, unused}),
    submit_master_event({backfill_phase_started, "Bucket1", 0}),
    submit_master_event({compaction_uninhibit_started, "Bucket1", n_0}),
    submit_master_event({compaction_uninhibit_started, "Bucket1", n_1}),
    submit_master_event({compaction_uninhibit_done, "Bucket1", n_1}),
    submit_master_event({seqno_waiting_started, "Bucket1", 0, unused, unused}),
    submit_master_event({seqno_waiting_ended, "Bucket1", 0, unused, unused}),
    submit_master_event({backfill_phase_ended, "Bucket1", 0}),
    submit_master_event({takeover_started, "Bucket1", 0, unused, unused}),
    submit_master_event({takeover_ended, "Bucket1", 0, unused, unused}),
    submit_master_event({vbucket_move_done, "Bucket1", 0}),
    submit_master_event({bucket_rebalance_ended, "Bucket1", unused}),
    submit_master_event({rebalance_stage_completed, [kv]}),
    Services = [n1ql, index, eventing],
    [begin
         submit_master_event({rebalance_stage_started, [S], [n1, n0]}),
         submit_master_event({rebalance_stage_completed, [S]})
     end || S <- Services],

    ?assertMatch(
       {ok, [{stageInfo,
              {[{<<"eventing">>,
                 {[{totalProgress, 100.0},
                   {perNodeProgress, {[{n0, 1.0}, {n1, 1.0}]}},
                   {startTime, _},
                   {completedTime, _},
                   {timeTaken, _}]}},
                {<<"index">>,
                 {[{totalProgress, 100.0},
                   {perNodeProgress, {[{n0, 1.0}, {n1, 1.0}]}},
                   {startTime, _},
                   {completedTime, _},
                   {timeTaken, _}]}},
                {<<"query">>,
                 {[{totalProgress, 100.0},
                   {perNodeProgress, {[{n0, 1.0}, {n1, 1.0}]}},
                   {startTime, _},
                   {completedTime, _},
                   {timeTaken, _}]}},
                {<<"data">>,
                 {[{totalProgress, 100.0},
                   {perNodeProgress, {[{n0, 1.0}, {n1, 1.0}]}},
                   {startTime, _},
                   {completedTime, _},
                   {timeTaken, _},
                   {subStages,
                    {[{<<"deltaRecovery">>,
                       {[{totalProgress, 100.0},
                         {perNodeProgress, {[{n1, 1.0}]}},
                         {startTime,  _},
                         {completedTime, _},
                         {timeTaken, _}]}}]}},
                   {details,
                    {[{"Bucket1",
                       {[{compactionInfo,
                          {[{inProgress,
                             {[{n_0,
                                {[{startTime, _},
                                  {completedTime, false},
                                  {timeTaken, _}]}}]}},
                            {perNode, {[{n_1, {[{averageTime, _}]}}]}}]}},
                         {vbucketLevelInfo,
                          {[{move,
                             {[{averageTime, _},
                               {totalCount, 1},
                               {remainingCount, 0}]}},
                            {backfill, {[{averageTime, _}]}},
                            {takeover, {[{averageTime, _}]}},
                            {persistence, {[{averageTime, _}]}},
                            {vbucketInfo,
                             [{[{id,0},
                               {beforeChain, [n_0, n_1]},
                                {afterChain, [n_1, n_0]},
                                {move,
                                 {[{startTime, _},
                                   {completedTime, _},
                                   {timeTaken, _}]}},
                                {backfill,
                                 {[{startTime, _},
                                   {completedTime, _},
                                   {timeTaken, _}]}},
                                {takeover,
                                 {[{startTime, _},
                                   {completedTime, _},
                                   {timeTaken, _}]}},
                                {persistence,
                                 {[{startTime, _},
                                   {completedTime, _},
                                   {timeTaken, _}]}},
                                {replicationInfo,
                                 {[{n_1,
                                    {[{node, n_1},
                                      {inDocsTotal, _},
                                      {inDocsLeft, _}]}}]}}]}]}]}},
                         {replicationInfo,
                          {[{n_0,
                             {[{inDocsTotal, 0},
                               {inDocsLeft, 0},
                               {outDocsTotal, _},
                               {outDocsLeft, 0}]}},
                            {n_1,
                             {[{inDocsTotal, 0},
                               {inDocsLeft, 0},
                               {outDocsTotal, _},
                               {outDocsLeft, 0}]}}]}},
                         {startTime, _},
                         {completedTime, _},
                         {timeTaken, _}]}}]}}]}}]}},
             {rebalanceId, ?REBALANCE_ID},
             {nodesInfo, {[{active_nodes, [n1, n0]}]}},
             {masterNode, _}]},
       test_get_rebalance_info()),
    ?assert(meck:validate(janitor_agent)).

failover() ->
    submit_master_event({failover, [n_1]}),
    submit_master_event({bucket_failover_started, "Bucket1", [n_1], unused}),
    submit_master_event({bucket_failover_ended, "Bucket1", [n_1], unused}),
    submit_master_event({failover_ended}),

    ?assertMatch(
       {ok, [{stageInfo,
              {[{<<"failover">>,
                 {[{totalProgress, 100.0},
                   {perNodeProgress, {[{n_1, 1.0}]}},
                   {startTime, _},
                   {completedTime, _},
                   {timeTaken, _},
                   {subStages,
                    {[{<<"Bucket1">>,
                       {[{totalProgress, 100.0},
                         {perNodeProgress, {[{n_1, 1.0}]}},
                         {startTime, _},
                         {completedTime, _},
                         {timeTaken, _}]}}]}}]}}]}},
             {rebalanceId, ?REBALANCE_ID},
             {nodesInfo, {[{active_nodes, [n1, n0]}]}},
             {masterNode, _}]},
       test_get_rebalance_info()),
    ?assert(meck:validate(janitor_agent)).

get_all_vb_seqnos() ->
    submit_master_event({rebalance_stage_started, [kv], [n_0, n_1, n_2]}),
    submit_master_event({bucket_rebalance_started, "Bucket1", unused}),
    %% Plan an example of each kind of move we might see.
    %% VB 0: Replica only move
    %% VB 1: Active only move
    %% VB 2: Replica -> active + new replica
    submit_master_event({planned_moves, "Bucket1",
                         {[{0, [n_0, n_1], [n_0, n_2], []},
                           {1, [n_0, n_1], [n_2, n_1], []},
                           {2, [n_0, n_1], [n_1, n_2], []}], []}, false}),
    submit_master_event({vbucket_move_start, unused, "Bucket1",
                         unused, 0, unused, unused}),

    %% Test that a replica only move will only consider new the replica's seqno
    meck:expect(janitor_agent, get_all_vb_seqnos,
                fun (_, n_0) ->
                        {ok, [{0, 0}]};
                    (_, n_1) ->
                        {ok, [{0, 1}]};
                    (_, n_2) ->
                        {ok, [{0, 2}]}
                end),
    %% The minimum seqno should be calculated over the nodes that need to catch
    %% up for this vbucket, which in this case is just node 2
    ?assertEqual({?REBALANCE_ID, [{0, 2}]}, test_get_progress_for_alerting(kv)),

    submit_master_event({vbucket_move_done, "Bucket1", 0}),
    submit_master_event({vbucket_move_start, unused, "Bucket1",
                         unused, 1, unused, unused}),

    %% Test that an active only move will consider the new active's seqno
    meck:expect(janitor_agent, get_all_vb_seqnos,
                fun (_, n_0) ->
                        {ok, [{1, 0}]};
                    (_, n_1) ->
                        {ok, [{1, 2}]};
                    (_, n_2) ->
                        {ok, [{1, 1}]}
                end),
    %% The minimum seqno should be calculated over the nodes that need to catch
    %% up for this vbucket, which in this case is nodes 1 and 2
    ?assertEqual({?REBALANCE_ID, [{1, 1}]}, test_get_progress_for_alerting(kv)),


    submit_master_event({vbucket_move_done, "Bucket1", 1}),
    submit_master_event({vbucket_move_start, unused, "Bucket1",
                         unused, 2, unused, unused}),

    %% Test that a replica promotion considers both the new active and replica
    meck:expect(janitor_agent, get_all_vb_seqnos,
                fun (_, n_0) ->
                        {ok, [{2, 0}]};
                    (_, n_1) ->
                        {ok, [{2, 1}]};
                    (_, n_2) ->
                        {ok, [{2, 2}]}
                end),
    %% The minimum seqno should be calculated over the nodes that need to catch
    %% up for this vbucket, which in this case is nodes 1 and 2
    ?assertEqual({?REBALANCE_ID, [{2, 1}]}, test_get_progress_for_alerting(kv)),

    %% Test that empty seqno lists are safely handled
    meck:expect(janitor_agent, get_all_vb_seqnos,
                fun (_, n_0) ->
                        {ok, []};
                    (_, n_1) ->
                        {ok, []};
                    (_, n_2) ->
                        {ok, [{2, 2}]}
                end),
    %% Missing vbuckets that are expected to be part of the running move are
    %% given a default value of 0
    ?assertEqual({?REBALANCE_ID, [{2, 0}]}, test_get_progress_for_alerting(kv)),

    %% Test that janitor_agent giving an error doesn't cause rebalance_observer
    %% to crash
    meck:expect(janitor_agent, get_all_vb_seqnos,
                fun (_, n_0) ->
                        error;
                    (_, n_1) ->
                        error;
                    (_, n_2) ->
                        {ok, [{2, 2}]}
                end),
    %% When we get error from get_all_vb_seqnos, these entries are ignored
    ?assertEqual({?REBALANCE_ID, [{2, 2}]}, test_get_progress_for_alerting(kv)).

get_seqnos_per_vb_t() ->
    Bucket = "Bucket1",
    GetMove = fun (VB, BeforeChain, AfterChain) ->
                      {VB, #vbucket_info{before_chain = BeforeChain,
                                         after_chain = AfterChain,
                                         move = #stat_info{end_time=false,
                                                           start_time = true}}}
              end,
    %% Give each vb a unique seqno for identification
    Seqno = fun (0, n_0) -> 0;
                (0, n_1) -> 1;
                (0, n_2) -> 2;
                (1, n_0) -> 3;
                (1, n_1) -> 4;
                (1, n_2) -> 5
            end,

    meck:expect(janitor_agent, get_all_vb_seqnos,
                fun (_, Node) ->
                        {ok, [{VB, Seqno(VB, Node)} || VB <- [0, 1]]}
                end),
    %% Replica only move should only get the new replica vbucket's seqno
    Move0 = GetMove(0, [n_0, n_1], [n_0, n_2]),
    Exp0 = {0, [Seqno(0, n_2)]},

    %% Active only move should get the new active vbucket and replica seqnos
    Move1 = GetMove(1, [n_0, n_1], [n_2, n_1]),
    Exp1 = {1, [Seqno(1, n_1), Seqno(1, n_2)]},

    Actual = get_seqnos_per_vb([Move0, Move1], Bucket),
    ?assertEqual([Exp0, Exp1], Actual).

test_update_progress(Service, ProgressList) ->
    ns_rebalance_observer:update_progress(Service, false,
                                          dict:from_list(ProgressList)).


get_index_progress_t() ->
    submit_master_event({rebalance_stage_started, [index], [n_0, n_1, n_2]}),
    submit_master_event({set_service_map, "index", [n_0, n_1, n_2]}),

    ?assertEqual({?REBALANCE_ID, [{n_0, 0}, {n_1, 0}, {n_2, 0}]},
                 test_get_progress_for_alerting(index)),

    submit_master_event({rebalance_stage_completed, [index]}),

    test_update_progress(index, [{n_0, 1}, {n_1, 0.5}]),

    ?assertEqual({?REBALANCE_ID, [{n_0, 1}, {n_1, 0.5}, {n_2, 0}]},
                 test_get_progress_for_alerting(index)).
-endif.
