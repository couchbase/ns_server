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

-export([init/2, get_progress/1, update_progress/3]).
-export_type([stage_info/0]).

-record(stage_info, {
          per_stage_progress :: dict:dict(),
          aggregated  :: dict:dict()
         }).

-type stage_info() :: #stage_info{}.

init(LiveNodes, Stages) ->
    do_init([{S, ns_cluster_membership:service_nodes(LiveNodes, S)} ||
             S <- Stages]).

do_init(Stages) ->
    aggregate(init_per_stage(Stages)).

init_per_stage(Stages) ->
    dict:from_list([{Stage, init_stage(Nodes)} ||
                    {Stage, Nodes} <- Stages]).

init_stage(Nodes) ->
    dict:from_list([{N, 0} || N <- Nodes]).

get_progress(#stage_info{aggregated = Aggregated}) ->
    Aggregated.

update_progress(Stage, StageProgress,
                #stage_info{per_stage_progress = PerStage}) ->
    aggregate(do_update_progress(Stage, StageProgress, PerStage)).

do_update_progress(Stage, StageProgress, PerStage) ->
    dict:update(Stage,
                fun (OldStageProgress) ->
                        dict:merge(fun (_, _, New) ->
                                           New
                                   end, OldStageProgress, StageProgress)
                end, PerStage).

aggregate(PerStage) ->
    Aggregated0 =
        dict:fold(
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

    Aggregated =
        dict:map(fun (_, {Count, Sum}) ->
                         Sum / Count
                 end, Aggregated0),

    #stage_info{per_stage_progress = PerStage,
                aggregated = Aggregated}.
