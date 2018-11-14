%% @author Couchbase <info@couchbase.com>
%% @copyright 2016-2018 Couchbase, Inc.
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
-module(rebalance_stage_info).

-export([init/1,
         get_stage_info/2,
         get_progress/1,
         update_progress/3,
         update_stage_info/3,
         diff_timestamp/2,
         binarify_timestamp/1]).
-export_type([stage_info/0]).

-record(stage_details, {
          start_time = false,
          complete_time = false,
          sub_stages = [] :: [{atom(), #stage_details{}}],
          notable_events = []
         }).

-record(stage_info, {
          per_stage_progress :: dict:dict(),
          %% aggregated needed for backward compatibility.
          aggregated :: dict:dict(),
          per_stage_info :: [{atom(), #stage_details{}}]
         }).

-type stage_info() :: #stage_info{}.

init(Stages) ->
    PerStageProgress = dict:from_list(init_per_stage_progress(Stages)),
    Aggregated = aggregate(PerStageProgress),
    StageInfo = init_per_stage_info(Stages),
    #stage_info{per_stage_progress = PerStageProgress,
                aggregated = Aggregated,
                per_stage_info = StageInfo}.

init_per_stage_progress(Stages) ->
    lists:flatten([init_stage_progress(S, N, SS) || {S, N, SS} <- Stages]).

init_stage_progress(_Stage, [], _SubStage) ->
    [];
init_stage_progress(Stage, Nodes, SubStages) ->
    SubStageNodes = init_per_stage_progress(SubStages),
    [{Stage, dict:from_list([{N, 0} || N <- Nodes])} | SubStageNodes].

%% For backward compatibility.
get_progress(#stage_info{aggregated = Aggregated}) ->
    Aggregated.

init_per_stage_info(Stages) ->
    [{Stage, #stage_details{
                start_time = false,
                complete_time = false,
                sub_stages = init_per_stage_info(SubStages),
                notable_events = []
               }} || {Stage, Nodes, SubStages} <- Stages, Nodes =/= []].

update_progress(
  Stage, StageProgress,
  #stage_info{per_stage_progress = OldPerStageProgress} = StageInfo) ->
    NewPerStageProgress = do_update_progress(Stage, StageProgress,
                                             OldPerStageProgress),
    Aggregated = aggregate(NewPerStageProgress),
    StageInfo#stage_info{
      per_stage_progress = NewPerStageProgress,
      aggregated = Aggregated}.

do_update_progress(Stage, StageProgress, PerStage) ->
    dict:update(Stage,
                fun (OldStageProgress) ->
                        dict:merge(fun (_, _, New) ->
                                           New
                                   end, OldStageProgress, StageProgress)
                end, PerStage).

aggregate(PerStage) ->
    TmpAggr = dict:fold(
                fun (_, StageProgress, AggAcc) ->
                        dict:fold(
                          fun (Node, NodeProgress, Acc) ->
                                  misc:dict_update(
                                    Node,
                                    fun ({Count, Sum}) ->
                                            {Count + 1, Sum + NodeProgress}
                                    end, {0, 0}, Acc)
                          end, AggAcc, StageProgress)
                end, dict:new(), PerStage),

    dict:map(fun (_, {Count, Sum}) ->
                     Sum / Count
             end, TmpAggr).

get_stage_info(StageInfo, AllStageDetails) ->
    {get_per_stage_info(StageInfo, AllStageDetails)}.

diff_timestamp(false, false) ->
    false;
diff_timestamp(false, StartTS) ->
    diff_timestamp(os:timestamp(), StartTS);
diff_timestamp(EndTS, StartTS) ->
    round(timer:now_diff(EndTS, StartTS) / 1000).

binarify_timestamp(false) ->
    false;
binarify_timestamp(Time) ->
    erlang:list_to_binary(misc:timestamp_local_iso8601(Time)).

get_per_stage_info(#stage_info{
                      per_stage_progress = PerStageProgress,
                      per_stage_info = PerStageInfo}, AllStageDetails) ->
    AllStageProgress = get_per_stage_progress(PerStageProgress),
    lists:map(
      fun ({Stage, StageInfo}) ->
              construct_per_stage_json(AllStageProgress,
                                       AllStageDetails,
                                       Stage,
                                       StageInfo)
      end, PerStageInfo).

construct_per_stage_json(AllStageProgress, AllStageDetails, Stage, StageInfo) ->
    {ok, PerNodeProgress} = dict:find(Stage, AllStageProgress),
    StageDetails = construct_per_stage_details_json(Stage, AllStageDetails),
    TotalStageProgress = case lists:foldl(fun ({_, P}, {Total, Count}) ->
                                                  {Total + P, Count + 1}
                                          end, {0, 0}, PerNodeProgress) of
                             {_, 0} ->
                                 0;
                             {TotalProgress, NodesCount} ->
                                 TotalProgress * 100.0 / NodesCount
                         end,
    ProgressInfoJson = construct_per_stage_progress_json(TotalStageProgress,
                                                         PerNodeProgress,
                                                         StageInfo),
    StageInfoJson = construct_per_stage_info_json(StageInfo, AllStageProgress,
                                                  AllStageDetails),
    {get_stage_name(Stage), {ProgressInfoJson ++ StageInfoJson ++
                             StageDetails}}.

get_stage_name(Stage) ->
    Stages = [{kv, data},
              {n1ql, query},
              {index, index},
              {fts, search},
              {cbas, analytics},
              {eventing, eventing},
              {kv_delta_recovery, deltaRecovery}],
    case lists:keyfind(Stage, 1, Stages) of
        {Stage, Val} -> Val;
        false -> Stage
    end.

construct_per_stage_details_json(Stage, AllStageDetails) ->
    case lists:keyfind(Stage, 1, AllStageDetails) of
        {Stage, StageDetails} ->
            [{details, StageDetails}];
        false ->
            []
    end.

construct_per_stage_progress_json(
  TSP, _, #stage_details{complete_time = false}) when TSP == 0 ->
    [];
construct_per_stage_progress_json(TotalStageProgress, PerNodeProgress,
                                  #stage_details{complete_time = false}) ->
    [{totalProgress, TotalStageProgress},
     {perNodeProgress, {PerNodeProgress}}];
construct_per_stage_progress_json(_, PerNodeProgress, _StageInfo) ->
    Completed = [{N, 1.0} || {N, _} <- PerNodeProgress],
    [{totalProgress, 100.0},
     {perNodeProgress, {Completed}}].

construct_per_stage_info_json(#stage_details{
                                 start_time = StartTime,
                                 complete_time = EndTime,
                                 sub_stages = SubStages,
                                 notable_events = NotableEvents},
                              AllStageProgress, AllStageDetails) ->
    SubStagesInfo = case SubStages of
                        [] -> [];
                        _ -> [{subStages,
                               {[construct_per_stage_json(AllStageProgress,
                                                          AllStageDetails,
                                                          SubStage,
                                                          SubStageInfo) ||
                                 {SubStage, SubStageInfo} <- SubStages]}}]
                    end,
    Events = case NotableEvents of
                 [] -> [];
                 _ -> [{events, {NotableEvents}}]
             end,

    [{startTime, binarify_timestamp(StartTime)},
     {completedTime, binarify_timestamp(EndTime)},
     {timeTaken, diff_timestamp(EndTime, StartTime)}] ++ SubStagesInfo ++ Events.

get_per_stage_progress(PerStageProgress) ->
    dict:map(fun (_, StageProgress) ->
                     dict:to_list(StageProgress)
             end, PerStageProgress).

update_stage_info({started, Time}, StageInfo) ->
    StageInfo#stage_details{start_time = Time,
                            complete_time = false};
update_stage_info({completed, Time}, StageInfo) ->
    StageInfo#stage_details{complete_time = Time};
update_stage_info({notable_event, TS, Text},
                  #stage_details{notable_events = NotableEvents} = StageInfo) ->
    Time = binarify_timestamp(TS),
    Msg = list_to_binary(Text),
    StageInfo#stage_details{notable_events = [{Time, Msg} | NotableEvents]}.

update_stage_info(Stage, StageInfoUpdate,
                  #stage_info{per_stage_info = PerStageInfo} = StageInfo) ->
    NewPerStageInfo = update_stage_info_rec(Stage, StageInfoUpdate,
                                            PerStageInfo),
    StageInfo#stage_info{per_stage_info = NewPerStageInfo}.

update_stage_info_rec([Stage | SubStages], StageInfoUpdate, AllStageInfo) ->
    case lists:keysearch(Stage, 1, AllStageInfo) of
        false ->
            AllStageInfo;
        {value, {Stage, OldStageInfo}} ->
            NewStageInfo =
                case SubStages of
                    [] ->
                        update_stage_info(StageInfoUpdate, OldStageInfo);
                    _ ->
                        NewSubStages = update_stage_info_rec(
                                         SubStages,
                                         StageInfoUpdate,
                                         OldStageInfo#stage_details.sub_stages),

                        OldStageInfo#stage_details{sub_stages = NewSubStages}
                end,
            lists:keyreplace(Stage, 1, AllStageInfo, {Stage, NewStageInfo})
    end.
