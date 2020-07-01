%% @author Couchbase <info@couchbase.com>
%% @copyright 2020 Couchbase, Inc.
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

%% @doc rest api for stats
-module(menelaus_web_stats).

-export([handle_range_post/1]).

-include("ns_common.hrl").
-include("cut.hrl").

-define(MAX_TS, 9999999999999).
-define(MIN_TS, -?MAX_TS).
-define(DEFAULT_PROMETHEUS_QUERY_TIMEOUT, 60000).

handle_range_post(Req) ->
    Now = os:system_time(millisecond),
    validator:handle(
      fun (List) ->
          Monitors = start_node_extractors_monitoring(List),
          Requests = lists:map(send_metrics_request(_), List),
          ResList = lists:map(
                      fun ({Ref, Props}) ->
                          read_metrics_response(Ref, Props, Now)
                      end, lists:zip(Requests, List)),
          stop_node_extractors_monitoring(Monitors),
          menelaus_util:reply_json(Req, ResList)
      end, Req, json_array, post_validators(Now, Req)).

post_validators(Now, Req) ->
    NowSec = Now div 1000,
    [validate_metric_json(metric, _),
     validator:required(metric, _),
     validator:string_array(applyFunctions, _),
     validate_functions(applyFunctions, _),
     validate_interval(timeWindow, _),
     validator:default(timeWindow, "1m", _),
     validator:string_array(nodes, _),
     menelaus_web_ui_stats:validate_nodes_v2(nodes, _, Req),
     validator:default(nodes, ?cut(default_nodes(Req)), _),
     validator:one_of(aggregationFunction, [max, min, avg, sum, none], _),
     validator:convert(aggregationFunction,
                       fun (L) -> binary_to_atom(L, latin1) end, _),
     validate_interval(step, _),
     validator:default(step, "10s", _),
     validator:integer(start, ?MIN_TS, ?MAX_TS, _),
     validator:integer('end', ?MIN_TS, ?MAX_TS, _),
     menelaus_web_ui_stats:validate_negative_ts(start, NowSec, _),
     menelaus_web_ui_stats:validate_negative_ts('end', NowSec, _),
     validator:default(start, NowSec - 60, _),
     validator:default('end', NowSec, _),
     validator:greater_or_equal('end', start, _),
     validator:integer(timeout, 1, 60*5*1000, _),
     validator:default(timeout, ?DEFAULT_PROMETHEUS_QUERY_TIMEOUT, _),
     validator:unsupported(_)].

start_node_extractors_monitoring(List) ->
    AllNodes = lists:foldl(
                 fun (Props, Acc) ->
                     Nodes = [N || {N, _} <- proplists:get_value(nodes, Props)],
                     lists:umerge(lists:sort(Nodes), Acc)
                 end, [], List),
    lists:map(fun (N) -> erlang:monitor(process, {ns_server_stats, N}) end,
              AllNodes).

stop_node_extractors_monitoring(Refs) ->
    lists:map(
      fun (Ref) ->
          erlang:demonitor(Ref, [flush])
      end, Refs).

send_metrics_request(Props) ->
    Functions = proplists:get_value(applyFunctions, Props, []),
    Window = proplists:get_value(timeWindow, Props),
    Metric = proplists:get_value(metric, Props),
    Name = proplists:get_value(<<"name">>, Metric),
    Labels = proplists:delete(<<"name">>, Metric),
    Query = construct_promql_query(Name, Labels, Functions, Window),
    Start = proplists:get_value(start, Props),
    End = proplists:get_value('end', Props),
    Step = proplists:get_value(step, Props),
    Timeout = proplists:get_value(timeout, Props),
    Nodes = proplists:get_value(nodes, Props),
    NodesToPoll = lists:usort([N || {N, _} <- Nodes]),
    Ref = make_ref(),
    lists:foreach(
      fun (N) ->
          Req = {extract, {self(), {Ref, N}}, Query, Start, End, Step, Timeout},
          gen_server:cast({ns_server_stats, N}, Req)
      end, NodesToPoll),
    Ref.

read_metrics_response(Ref, Props, StartTimestampMs) ->
    Nodes = proplists:get_value(nodes, Props),
    Timeout = proplists:get_value(timeout, Props),
    {BadRes, GoodRes} =
        misc:partitionmap(
          fun ({Node, HostPort}) ->
              TimeLeft = max(StartTimestampMs + Timeout -
                             os:system_time(millisecond), 0),
              receive
                  {{Ref, Node}, {ok, R}} -> {right, {HostPort, R}};
                  {{Ref, Node}, {error, R}} -> {left, {HostPort, R}};
                  {'DOWN', _, _, {ns_server_stats, Node}, _} ->
                      {left, {HostPort, <<"Node is not available">>}}
              after TimeLeft ->
                  {left, {HostPort, timeout}}
              end
          end, Nodes),
    AggFunction = proplists:get_value(aggregationFunction, Props, none),
    Data = prepare_metric_props(merge_metrics(GoodRes, AggFunction)),
    Errors = [{[{node, N},
                {error, menelaus_web_ui_stats:format_error(R)}]}
                 || {N, R} <- BadRes],
    {[{data, Data}, {errors, Errors}]}.

default_nodes(Req) ->
    AllNodes = ns_cluster_membership:actual_active_nodes(),
    LocalAddr = menelaus_util:local_addr(Req),
    HostPort = menelaus_web_node:build_node_hostname(ns_config:latest(), _,
                                                     LocalAddr),
    [{N, iolist_to_binary(HostPort(N))} || N <- AllNodes].

validate_metric_json(Name, State) ->
    validator:validate(
      fun ({[]}) ->
              {error, "must be not empty"};
          ({Props}) when is_list(Props) ->
              case lists:all(?cut(is_binary(element(2, _))), Props) of
                  true -> {value, Props};
                  false -> {error, "metric labels must be strings"}
              end;
          (_) ->
              {error, "must be a json object"}
      end, Name, State).

validate_functions(Name, State) ->
    validator:validate(
      fun (L) ->
          try
              {value, validate_functions(L)}
          catch
              error:invalid_function ->
                  {error, "invalid list of functions"}
          end
      end, Name, State).

prepare_metric_props(Metrics) ->
    lists:map(
      fun ({MetricProps}) ->
          {misc:key_update(<<"metric">>, MetricProps,
                           fun ({P}) ->
                               {functools:chain(
                                  P, [proplists:delete(<<"job">>, _),
                                      proplists:delete(<<"__name__">>, _)])}
                           end)}
      end, Metrics).

merge_metrics(NodesResults, none) ->
    lists:flatmap(
      fun ({Node, NodeRes}) ->
          lists:map(
            fun ({MetricProps}) ->
                {misc:key_update(<<"metric">>, MetricProps,
                                 fun ({P}) -> {[{nodes, [Node]} | P]} end)}
            end, NodeRes)
      end, NodesResults);
merge_metrics(NodesResults, AggFunction) ->
    Nodes = [N || {N, _} <- NodesResults],
    FlatList = [{maps:from_list(Metric), Values} ||
                    {_, Metrics} <- NodesResults,
                    {Props} <- Metrics,
                    [{<<"metric">>, {Metric}},
                     {<<"values">>, Values}] <- [lists:sort(Props)]],
    lists:map(
      fun ({NamePropsMap, ListOfValueLists}) ->
          NameProps = maps:to_list(NamePropsMap),
          NameProps2 = {[{nodes, Nodes},
                         {aggregationFunction, AggFunction} | NameProps]},
          Timestamps = lists:umerge(lists:map(?cut([TS || [TS, _V] <- _1]),
                                              ListOfValueLists)),
          Normalize =
              menelaus_web_ui_stats:normalize_datapoints(Timestamps, _, []),
          ListOfValueLists2 = lists:map(Normalize, ListOfValueLists),
          Aggregated = aggregate_datapoints(AggFunction, ListOfValueLists2),
          Values = lists:zipwith(?cut([_1, _2]), Timestamps, Aggregated),
          {[{<<"metric">>, NameProps2},
            {<<"values">>, Values}]}
      end, misc:groupby_map(fun functools:id/1, FlatList)).

aggregate_datapoints(F, Datapoints) ->
    Fun = fun (L) ->
              Res = menelaus_web_ui_stats:aggregate(
                      F, [prometheus:parse_value(E) || E <- L]),
              prometheus:format_value(Res)
          end,
    misc:zipwithN(Fun, Datapoints).

construct_promql_query(Metric, Labels, Functions, Window) ->
    NeedTimeWindow = lists:any(fun is_range_vector_function/1, Functions),
    functools:chain(
      Labels,
      [?cut({[{eq, "__name__", Metric}] ++ [{eq, K, V} || {K, V} <- _]}),
       case NeedTimeWindow of
           true -> range_vector(_, Window);
           false -> fun functools:id/1
       end,
       apply_functions(_, Functions),
       prometheus:format_promql(_)]).

range_vector(Ast, TimeWindow) -> {range_vector, Ast, TimeWindow}.

apply_functions(Ast, Functions) ->
    lists:foldl(
      fun ({histogram_quantile, Q}, AccAst) ->
              {call, histogram_quantile, none, [Q, AccAst]};
          ({F, by, Labels}, AccAst) ->
              {call, F, {by, Labels}, [AccAst]};
          (F, AccAst) ->
              {call, F, none, [AccAst]}
      end, Ast, Functions).

is_range_vector_function(Function) ->
    lists:member(Function, [rate, irate, increase, avg_over_time, min_over_time,
                            max_over_time, deriv, delta, idelta]).

validate_functions(Functions) ->
    Parsed =
        lists:map(
          fun ("rate") -> rate;
              ("irate") -> irate;
              ("increase") -> increase;
              ("avg_over_time") -> avg_over_time;
              ("min_over_time") -> min_over_time;
              ("max_over_time") -> max_over_time;
              ("deriv") -> deriv;
              ("delta") -> delta;
              ("idelta") -> idelta;
              ("sum") -> sum;
              ("min") -> min;
              ("max") -> max;
              ("avg") -> avg;
              ("p" ++ PStr) ->
                  try list_to_integer(PStr) of
                      P when 0 < P; P =< 100  -> {histogram_quantile, P/100};
                      _ -> error(invalid_function)
                  catch
                      _:_ -> error(invalid_function)
                  end;
              (_) -> error(invalid_function)
          end, Functions),

    %% If sum is used inside quantile, we should sum by le. The reason is
    %% because the histogram_quantile function needs 'le' label to present.
    %% The same logic works for other aggregative functions, like min, max, etc.
    %% For example:
    %% "http_request_duration_bucket/sum/p90" should be converted
    %%   histogram_quantile(0.9, sum by (le) (http_request_duration_bucket))
    %% instead of
    %%   histogram_quantile(0.9, sum(http_request_duration_bucket))
    %% which will not work
    Reversed =
        lists:foldl(
          fun ({histogram_quantile, _} = F, Acc) ->
                  case Acc of
                      [] -> [F];
                      [PrevF | T] ->
                          case lists:member(PrevF, [sum, min, max, avg]) of
                              true -> [F, {PrevF, by, ["le"]} | T];
                              false -> [F | Acc]
                          end
                  end;
              (F, Acc) ->
                  [F | Acc]
          end, [], Parsed),
    lists:reverse(Reversed).

validate_interval(Name, State) ->
    validator:validate(
      fun (Interval) when is_integer(Interval) ->
              {value, integer_to_list(Interval)};
          (Interval) ->
              IntervalStr = case is_binary(Interval) of
                                true -> binary_to_list(Interval);
                                false -> Interval
                            end,
              try string:list_to_integer(IntervalStr) of
                  {error, _} -> {error, "invalid interval"};
                  {_, ""} -> {value, IntervalStr};
                  {_, [Unit]} ->
                      case lists:member(Unit, "smhdwy") of
                          true -> {value, IntervalStr};
                          false -> {error, "invalid duration unit"}
                      end;
                  {_, _} -> {error, "invalid duration unit"}
              catch
                  _:_ -> {error, "invalid interval"}
              end
      end, Name, State).
