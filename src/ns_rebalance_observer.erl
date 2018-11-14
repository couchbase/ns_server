%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2013-2018 Couchbase, Inc.
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

-module(ns_rebalance_observer).

-behavior(gen_server).

-include("ns_common.hrl").
-include("cut.hrl").

-export([start_link/3,
         get_detailed_progress/0,
         get_aggregated_progress/1,
         get_stage_info/0,
         update_stage_info/2,
         update_progress/2]).

%% gen_server callbacks
-export([code_change/3, init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(SERVER, {via, leader_registry, ?MODULE}).
-define(DOCS_LEFT_REFRESH_INTERVAL, 5000).

-record(stat_info, {start_time = false,
                    end_time = false}).

-record(replica_building_stats, {node :: node(),
                                 docs_total :: non_neg_integer(),
                                 docs_left :: non_neg_integer()}).

-record(vbucket_info, {before_chain :: [node()],
                       after_chain :: [node()],
                       stats :: [#replica_building_stats{}],
                       move = #stat_info{}}).

-record(total_stat_info, {total_time = 0,
                          completed_count = 0}).

-record(vbucket_level_info, {move = #total_stat_info{},
                             vbucket_info = dict:new()}).

-record(bucket_level_info, {bucket_name,
                            vbucket_level_info = #vbucket_level_info{}}).

-record(state, {bucket :: bucket_name() | undefined,
                buckets_count :: pos_integer(),
                bucket_number :: non_neg_integer(),
                stage_info :: rebalance_progress:stage_info(),
                nodes_info :: [{atom(), [node()]}],
                type :: atom(),
                bucket_info :: dict:dict()}).

start_link(Stages, NodesInfo, Type) ->
    gen_server:start_link(?SERVER, ?MODULE, {Stages, NodesInfo, Type}, []).

generic_get_call(Call) ->
    generic_get_call(Call, 10000).
generic_get_call(Call, Timeout) ->
    try
        gen_server:call(?SERVER, Call, Timeout)
    catch
        exit:_Reason ->
            not_running
    end.

get_detailed_progress() ->
    generic_get_call(get_detailed_progress).

get_aggregated_progress(Timeout) ->
    generic_get_call(get_aggregated_progress, Timeout).

get_stage_info() ->
    generic_get_call(get_stage_info).

update_progress(Stage, StageProgress) ->
    gen_server:cast(?SERVER, {update_progress, Stage, StageProgress}).

update_stage_info(Stage, StageInfo) ->
    gen_server:cast(?SERVER, {update_stage_info, Stage, StageInfo}).

is_interesting_master_event({_, bucket_rebalance_started, _Bucket, _Pid}) ->
    fun handle_bucket_rebalance_started/2;
is_interesting_master_event({_, set_ff_map, _BucketName, _Diff}) ->
    fun handle_set_ff_map/2;
is_interesting_master_event({_, vbucket_move_start, _Pid, _BucketName, _Node, _VBucketId, _, _}) ->
    fun handle_vbucket_move_start/2;
is_interesting_master_event({_, vbucket_move_done, _BucketName, _VBucketId}) ->
    fun handle_vbucket_move_done/2;
is_interesting_master_event({_, rebalance_stage_started, _Stage}) ->
    fun handle_rebalance_stage_started/2;
is_interesting_master_event({_, rebalance_stage_completed, _Stage}) ->
    fun handle_rebalance_stage_completed/2;
is_interesting_master_event({_, rebalance_stage_event, _Stage, _Event}) ->
    fun handle_rebalance_stage_event/2;
is_interesting_master_event(_) ->
    undefined.

possible_substages(kv, NodesInfo) ->
    case proplists:get_value(delta_nodes, NodesInfo, []) of
        [] ->
            [];
        DeltaNodes ->
            [{kv_delta_recovery, DeltaNodes, []}]
    end;
possible_substages(_,_) ->
    [].

get_stage_nodes(Services, NodesInfo) ->
    ActiveNodes = proplists:get_value(active_nodes, NodesInfo, []),
    lists:filtermap(
      fun (Service) ->
              case ns_cluster_membership:service_nodes(ActiveNodes, Service) of
                  [] ->
                      false;
                  Nodes ->
                      SubStages = possible_substages(Service, NodesInfo),
                      {true, {Service, Nodes, SubStages}}
              end
      end, lists:usort(Services)).

init({Services, NodesInfo, Type}) ->
    Self = self(),
    ns_pubsub:subscribe_link(master_activity_events,
                             fun (Event, _Ignored) ->
                                     case is_interesting_master_event(Event) of
                                         undefined ->
                                             [];
                                         Fun ->
                                             gen_server:cast(Self, {note, Fun, Event})
                                     end
                             end, []),

    StageInfo = rebalance_stage_info:init(get_stage_nodes(Services, NodesInfo)),
    Buckets = ns_bucket:get_bucket_names(),
    BucketsCount = length(Buckets),
    BucketLevelInfo = dict:from_list([{BN,
                                       #bucket_level_info{bucket_name = BN}} ||
                                      BN <- Buckets]),
    proc_lib:spawn_link(erlang, apply, [fun docs_left_updater_init/1, [Self]]),

    {ok, #state{bucket = undefined,
                buckets_count = BucketsCount,
                bucket_number = 0,
                stage_info = StageInfo,
                nodes_info = NodesInfo,
                type = Type,
                bucket_info = BucketLevelInfo}}.

handle_call(get, _From, State) ->
    {reply, State, State};
handle_call(get_detailed_progress, _From, State) ->
    {reply, do_get_detailed_progress(State), State};
handle_call(get_aggregated_progress, _From,
            #state{stage_info = StageInfo} = State) ->
    {reply, dict:to_list(rebalance_stage_info:get_progress(StageInfo)), State};
handle_call(get_stage_info, _From,
            #state{stage_info = StageInfo} = State) ->
    {reply, rebalance_stage_info:get_stage_info(StageInfo), State};
handle_call(Req, From, State) ->
    ?log_error("Got unknown request: ~p from ~p", [Req, From]),
    {reply, unknown_request, State}.

handle_cast({note, Fun, Ev}, State) ->
    {noreply, NewState} = Fun(Ev, State),
    {noreply, NewState};

handle_cast({update_stats, BucketName, VBucket, NodeToDocsLeft}, State) ->
    ?log_debug("Got update_stats: ~p, ~p", [VBucket, NodeToDocsLeft]),
    {noreply, update_move(
                State, BucketName, VBucket,
                fun (Move) ->
                        NewStats =
                            [case lists:keyfind(Stat#replica_building_stats.node, 1, NodeToDocsLeft) of
                                 {_, NewLeft} ->
                                     #replica_building_stats{docs_total = Total,
                                                             docs_left = Left} = Stat,

                                     case NewLeft >= Left of
                                         true ->
                                             %% our initial estimates are
                                             %% imprecise, so we can end up in
                                             %% a situation where new
                                             %% docs_left is greater than
                                             %% docs_total;
                                             %%
                                             %% another possibility is that
                                             %% there're new mutations coming;
                                             %% in such case if we didn't
                                             %% adjust docs_total it would
                                             %% seem to the user that number
                                             %% of transfered items went down
                                             %% which is probably not desireable;
                                             %%
                                             %% obviously, this adjustment may
                                             %% lose some mutations (meaning
                                             %% that final doc_total wouldn't
                                             %% be precise) but user
                                             %% experience-wise it seems to be
                                             %% better.
                                             Increase = NewLeft - Left,
                                             Stat#replica_building_stats{docs_left = NewLeft,
                                                                         docs_total = Total + Increase};
                                         false ->
                                             Stat#replica_building_stats{docs_left = NewLeft}
                                     end;
                                 false ->
                                     Stat
                             end || Stat <- Move#vbucket_info.stats],
                        Move#vbucket_info{stats = NewStats}
                end)};

handle_cast({update_progress, Stage, StageProgress},
            #state{stage_info = Old} = State) ->
    NewStageInfo = rebalance_stage_info:update_progress(
                     Stage, StageProgress, Old),
    {noreply, State#state{stage_info = NewStageInfo}};
handle_cast({update_stage_info, Stage, StageInfo},
            #state{stage_info = Old} = State) ->
    New = rebalance_stage_info:update_stage_info(Stage, StageInfo, Old),
    {noreply, State#state{stage_info = New}};

handle_cast(Req, _State) ->
    ?log_error("Got unknown cast: ~p", [Req]),
    erlang:error({unknown_cast, Req}).

initiate_bucket_rebalance(BucketName, OldState) when OldState#state.bucket =:= BucketName ->
    OldState;
initiate_bucket_rebalance(BucketName, OldState) ->
    {ok, BucketConfig} = ns_bucket:get_bucket(BucketName),
    Map = proplists:get_value(map, BucketConfig),
    FFMap = case proplists:get_value(fastForwardMap, BucketConfig) of
                undefined ->
                    %% yes this is possible if rebalance completes
                    %% faster than we can start observing it's
                    %% progress
                    Map;
                FFMap0 ->
                    FFMap0
            end,
    VBCount = length(Map),
    Diff = [Triple
            || {_, [MasterNode|_] = ChainBefore, ChainAfter} = Triple <- lists:zip3(lists:seq(0, VBCount-1),
                                                                                    Map,
                                                                                    FFMap),
               MasterNode =/= undefined,
               ChainBefore =/= ChainAfter],
    BuildDestinations0 = [{MasterNode, VB} || {VB, [MasterNode|_], _ChainAfter} <- Diff],
    BuildDestinations1 = [{N, VB} || {VB, [MasterNode|_], ChainAfter} <- Diff,
                                     N <- ChainAfter, N =/= undefined, N =/= MasterNode],

    BuildDestinations =
        %% the following groups vbuckets to per node. [{a, 1}, {a, 2}, {b, 3}] => [{a, [1,2]}, {b, [3]}]
        keygroup_sorted(lists:merge(lists:sort(BuildDestinations0),
                                    lists:sort(BuildDestinations1))),

    dcp = ns_bucket:replication_type(BucketConfig),

    SomeEstimates0 = misc:parallel_map(
                       fun ({Node, VBs}) ->
                               {ok, DcpEstimates} =
                                   janitor_agent:get_mass_dcp_docs_estimate(BucketName, Node, VBs),

                               [{{Node, VB}, {VBEstimate, VBChkItems}} ||
                                   {VB, {VBEstimate, VBChkItems, _}} <-
                                       lists:zip(VBs, DcpEstimates)]
                       end, BuildDestinations, infinity),


    SomeEstimates = lists:append(SomeEstimates0),

    ?log_debug("Initial estimates:~n~p", [SomeEstimates]),

    Moves =
        [begin
             {_, {MasterEstimate, MasterChkItems}} = lists:keyfind({MasterNode, VB}, 1, SomeEstimates),
             RBStats =
                 [begin
                      {_, {ReplicaEstimate, _}} = lists:keyfind({Replica, VB}, 1, SomeEstimates),
                      Estimate = case ReplicaEstimate =< MasterEstimate of
                                     true ->
                                         %% in this case we assume no backfill
                                         %% is required; but the number of
                                         %% items to be transferred can't be
                                         %% less than the number of items in
                                         %% open checkpoint
                                         max(MasterChkItems,
                                             MasterEstimate - ReplicaEstimate);
                                     _ ->
                                         MasterEstimate
                                 end,
                      #replica_building_stats{node = Replica,
                                              docs_total = Estimate,
                                              docs_left = Estimate}
                  end || Replica <- ChainAfter,
                         Replica =/= undefined,
                         Replica =/= MasterNode],
             {VB, #vbucket_info{before_chain = ChainBefore,
                                after_chain = ChainAfter,
                                stats = RBStats}}
         end || {VB, [MasterNode|_] = ChainBefore, ChainAfter} <- Diff],

    ?log_debug("Moves:~n~p", [Moves]),
    TmpState = update_all_vb_info(OldState, BucketName, dict:from_list(Moves)),
    TmpState#state{bucket = BucketName}.

handle_rebalance_stage_started({TS, rebalance_stage_started, Stage},
                               #state{stage_info = Old} = State) ->
    New = rebalance_stage_info:update_stage_info(Stage, {started, TS}, Old),
    {noreply, State#state{stage_info = New}}.

handle_rebalance_stage_completed({TS, rebalance_stage_completed, Stage},
                                 #state{stage_info = Old} = State) ->
    New = rebalance_stage_info:update_stage_info(Stage, {completed, TS}, Old),
    {noreply, State#state{stage_info = New}}.

handle_rebalance_stage_event({TS, rebalance_stage_event, Stage, Text},
                             #state{stage_info = Old} = State) ->
    New = rebalance_stage_info:update_stage_info(Stage,
                                                 {notable_event, TS, Text},
                                                 Old),
    {noreply, State#state{stage_info = New}}.

handle_bucket_rebalance_started({_, bucket_rebalance_started, _BucketName, _Pid},
                                #state{bucket_number = Number} = State) ->
    NewState = State#state{bucket_number=Number + 1},
    {noreply, NewState}.

handle_set_ff_map({_, set_ff_map, BucketName, _Diff}, State) ->
    {noreply, initiate_bucket_rebalance(BucketName, State)}.

handle_vbucket_move_start({TS, vbucket_move_start, _Pid, BucketName,
                           _Node, VBucketId, _, _},
                          State) ->
    ?log_debug("Noted vbucket move start (vbucket ~p)", [VBucketId]),
    {noreply, update_info(vbucket_move_start, State,
                          {TS, BucketName, VBucketId})}.

handle_vbucket_move_done({TS, vbucket_move_done, BucketName, VBucket},
                         State) ->
    State1 = update_move(State, BucketName, VBucket,
                         fun (#vbucket_info{stats=Stats} = Move) ->
                                 Stats1 = [S#replica_building_stats{docs_left=0} ||
                                              S <- Stats],
                                 Move#vbucket_info{stats=Stats1}
                         end),
    ?log_debug("Noted vbucket move end (vbucket ~p)", [VBucket]),
    {noreply, update_info(vbucket_move_done, State1,
                          {TS, BucketName, VBucket})}.

update_move(State, BucketName, VBucket, Fun) ->
    update_all_vb_info(State, BucketName,
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
    {ok, _} = timer2:send_interval(?DOCS_LEFT_REFRESH_INTERVAL, refresh),
    docs_left_updater_loop(Parent).

docs_left_updater_loop(Parent) ->
    State = gen_server:call(Parent, get, infinity),
    BucketName = State#state.bucket,
    Moves = dict:to_list(get_all_vb_info(State, BucketName)),
    case BucketName of
        undefined ->
            ok;
        _ ->
            ?log_debug("Starting docs_left_updater_loop:~p~n~p",
                       [BucketName, Moves])
    end,
    [update_docs_left_for_move(Parent, BucketName, VB, VBInfo) ||
     {VB, VBInfo} <- Moves],
    receive
        refresh ->
            _Lost = misc:flush(refresh),
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
    catch error:{janitor_agent_servant_died, _} ->
            ?log_debug("Apparently move of ~p is already done", [VBucket]),
            ok
    end.

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

    {OutMovesStats, InMovesStats} = moves_stats(AllMoves),

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

    NodesProgress =
        lists:foldl(
          fun (N, Acc) ->
                  {InTotal, InLeft} = misc:dict_get(N, InMovesStats, {0, 0}),
                  {OutTotal, OutLeft} = misc:dict_get(N, OutMovesStats, {0, 0}),

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
              true = (OldMaster =/= undefined),

              lists:foldl(
                fun (#replica_building_stats{node=DstNode,
                                             docs_total=Total,
                                             docs_left=Left},
                     {AccOut, AccIn}) ->
                        true = (Left =< Total),

                        AccOut1 = dict:update(OldMaster,
                                              fun ({AccTotal, AccLeft}) ->
                                                      {AccTotal + Total, AccLeft + Left}
                                              end, {Total, Left}, AccOut),
                        AccIn1 = dict:update(DstNode,
                                             fun ({AccTotal, AccLeft}) ->
                                                     {AccTotal + Total, AccLeft + Left}
                                             end, {Total, Left}, AccIn),

                        {AccOut1, AccIn1}
                end, Acc, Stats)
      end, {dict:new(), dict:new()}, Moves).

update_info(Event,
            #state{bucket_info = OldBucketLevelInfo} = State,
            {_TS, BucketName, _VB} = UpdateArgs) ->
    NewBucketLevelInfo =
        dict:update(
          BucketName,
          fun (BLI) ->
                  update_vbucket_level_info(Event, BLI, UpdateArgs)
          end, OldBucketLevelInfo),
    State#state{bucket_info = NewBucketLevelInfo}.

get_all_vb_info(_, undefined) ->
    dict:new();
get_all_vb_info(#state{bucket_info = BucketInfo}, BucketName) ->
    {ok, BucketLevelInfo} = dict:find(BucketName, BucketInfo),
    get_all_vb_info(BucketLevelInfo).

get_all_vb_info(BucketLevelInfo) ->
    BucketLevelInfo#bucket_level_info.vbucket_level_info#vbucket_level_info.vbucket_info.

update_all_vb_info(#state{bucket_info = OldBucketLevelInfo} = State, BucketName,
                   NewAllVBInfo) ->
    NewBucketLevelInfo = dict:update(BucketName,
                                     ?cut(update_all_vb_info(_, NewAllVBInfo)),
                                     OldBucketLevelInfo),
    State#state{bucket_info = NewBucketLevelInfo}.

update_all_vb_info(#bucket_level_info{
                      vbucket_level_info = VBLevelInfo} = BucketLevelInfo,
                   AllVBInfo) ->
    NewVBLevelInfo = VBLevelInfo#vbucket_level_info{vbucket_info = AllVBInfo},
    BucketLevelInfo#bucket_level_info{vbucket_level_info = NewVBLevelInfo}.

update_vbucket_level_info(Event, BucketLevelInfo,
                          {_TS, _BucketName, VB} = UpdateArgs) ->
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
                    #vbucket_info.move, end_time}
                  ],
    lists:keyfind(Event, 1, EventAction).

update_stat(start_time, _, TS) ->
    #stat_info{start_time = TS};
update_stat(end_time, Stat, TS) ->
    Stat#stat_info{end_time = TS}.

update_vbucket_info(Event, VBInfo, {TS, _Bucket, _VB}) ->
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
