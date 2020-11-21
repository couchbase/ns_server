%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2020 Couchbase, Inc.
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

-module(menelaus_web_ui_stats).

-export([handle_ui_stats_post_v2/1,
         validate_negative_ts/3,
         validate_nodes_v2/3,
         format_error/1,
         normalize_datapoints/3,
         aggregate/2]).

-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(MAX_TS, 9999999999999).
-define(MIN_TS, -?MAX_TS).

handle_ui_stats_post_v2(Req) ->
    Now = os:system_time(second),
    validator:handle(
      fun (List) ->
              Res = [extract_uistats(Now, V, Req) || V <- List],
              menelaus_util:reply_json(Req, Res)
      end, Req, json_array, ui_stats_post_validators_v2(Now, Req)).

ui_stats_post_validators_v2(Now, Req) ->
    [validator:required(queries, _),
     validate_queries(queries, _),
     validator:one_of(aggregate, [max, min, avg, sum, none], _),
     validator:convert(aggregate, fun (L) -> binary_to_atom(L, latin1) end, _),
     validator:integer(start, ?MIN_TS, ?MAX_TS, _),
     validator:required(start, _),
     validator:integer('end', ?MIN_TS, ?MAX_TS, _),
     validate_negative_ts(start, Now, _),
     validate_negative_ts('end', Now, _),
     validator:greater_or_equal('end', start, _),
     validator:integer(step, 1, 60 * 60 * 24 * 366, _),
     validator:required(step, _),
     validator:string_array(nodes, _),
     validate_nodes_v2(nodes, _, Req),
     validator:integer(timeout, 1, 60*5*1000, _),
     validator:unsupported(_)].

validate_queries(Name, State) ->
    validator:validate(
      fun (JSONList) when is_list(JSONList) ->
              validate_query_list(JSONList, []);
          (_) ->
              {error, "Must be a json array"}
      end, Name, State).

validate_query_list([], Acc) -> {value, Acc};
validate_query_list([{Props} | Tail], Acc) ->
    Name = proplists:get_value(<<"name">>, Props),
    case menelaus_stats_queries:find_query(Name) of
        undefined when is_binary(Name) ->
            {error, io_lib:format("Unknown query \"~s\"", [Name])};
        undefined ->
            {error, "Query name is not a string"};
        #{args := Args} = Q ->
            ArgValues = [{A, proplists:get_value(A, Props)} || A <- Args],
            {Bad, Good} = misc:partitionmap(
                            fun ({A, undefined}) -> {left, A};
                                ({A, V}) when is_binary(V) -> {right, {A, V}};
                                ({A, _}) -> {left, A}
                            end, ArgValues),
            case Bad of
                [] ->
                    GoodSafe = [{A, sanitize_query_arg(G)} || {A, G} <- Good],
                    validate_query_list(Tail,
                                        [{Name, Q#{args => GoodSafe}} | Acc]);
                _ ->
                    MissingStr = lists:join(", ", Bad),
                    {error, io_lib:format("Invalid arguments for query \"~s\": "
                                          "~s", [Name, MissingStr])}
            end
    end;
validate_query_list([_ | _], _Acc) ->
    {error, "Every query must be a json object"}.

format_queries(Queries) ->
    iolist_to_binary(
      lists:join(<<" or ">>, [format_query(N, Q) || {N, Q} <- Queries])).

format_query(Name, #{format := P, args := Args}) ->
    Query = misc:format_bin(P, [Value || {_Name, Value} <- Args]),
    lists:foldl(
        fun ({N, V}, Acc) ->
            misc:format_bin("label_replace(~s, \"~s\",\"~s\", \"\", \"\")",
                            [Acc, N, V])
        end, Query, [{<<"query">>, Name}|Args]).

sanitize_query_arg(Bin) ->
    binary:replace(Bin, [<<"\"">>, <<"'">>, <<"{">>, <<"}">>,<<"=">>], <<>>,
                   [global]).

validate_nodes_v2(Name, State, Req) ->
    validator:validate(
      fun (Nodes) ->
              {Right, Wrong} =
                  misc:partitionmap(
                    fun (HostName) ->
                            case menelaus_web_node:find_node_hostname(
                                   HostName, Req, any) of
                                {error, _} ->
                                    {right, HostName};
                                {ok, Node} ->
                                    {left, {Node, list_to_binary(HostName)}}
                            end
                    end, Nodes),
              case Wrong of
                  [] ->
                      {value, Right};
                  _ ->
                      {error, io_lib:format("Unknown hostnames: ~p", [Wrong])}
              end
      end, Name, State).

extract_uistats(Now, Params, Req) ->
    Queries = proplists:get_value(queries, Params),
    QueryStr = format_queries(Queries),
    Aggregate = proplists:get_value(aggregate, Params, none),
    Start = proplists:get_value(start, Params),
    End = proplists:get_value('end', Params, Now),
    Step = proplists:get_value(step, Params),
    Nodes = proplists:get_value(nodes, Params, all),
    Timeout = proplists:get_value(timeout, Params, 60000),
    NodesToPoll = case Nodes of
                      all -> ns_cluster_membership:actual_active_nodes();
                      _ -> lists:usort([N || {N, _} <- Nodes])
                  end,

    {GoodRes, BadRes} = misc:multi_call(NodesToPoll, ns_server_stats,
                                        {extract, QueryStr, Start, End,
                                         Step, Timeout}, 2 * Timeout,
                                        fun ({ok, R}) -> {true, R};
                                            ({error, Reason}) -> {false, Reason}
                                        end),

    MapNode =
        fun (N) when Nodes == all ->
                LocalAddr = menelaus_util:local_addr(Req),
                menelaus_web_node:build_node_hostname(ns_config:latest(),
                                                      N, LocalAddr);
            (N) ->
                proplists:get_value(N, Nodes)
        end,

    Errors = [{[{node, MapNode(N)},
                {error, format_error(R)}]} || {N, R} <- BadRes],
    NodeStats = [{MapNode(N), R} || {N, R} <- GoodRes],
    {Timestamps, Stats} = merge_metrics(NodeStats, Aggregate),
    {[{timestamps, Timestamps},
      {stats, Stats},
      {errors, Errors}]}.

format_error(Bin) when is_binary(Bin) -> Bin;
format_error(timeout) -> <<"Request timed out">>;
format_error({exit, {{nodedown, _}, _}}) -> <<"Node is down">>;
format_error({exit, _}) -> <<"Unexpected server error">>;
format_error({failed_connect, _}) -> <<"Connect to stats backend failed">>;
format_error(Unknown) -> misc:format_bin("Unexpected error - ~10000p",
                                         [Unknown]).

merge_metrics(Res, Aggregate) ->
    FlatList = [{maps:from_list(Metric), Node, Values} ||
                    {Node, Metrics} <- Res,
                    {Props} <- Metrics,
                    [{<<"metric">>, {Metric}},
                     {<<"values">>, Values}] <- [lists:sort(Props)]],

    Timestamps =
        lists:umerge([[TS || [TS, _] <- Values] || {_, _, Values} <- FlatList]),

    Stats = lists:map(
              fun ({M, L}) ->
                  Values = [{N, normalize_datapoints(Timestamps, V, [])}
                                 || {_, N, V} <- L],
                  {[{<<"metric">>, {maps:to_list(M)}} |
                    aggregate_datapoints(Aggregate, Values)]}
              end, misc:keygroup(1, lists:sort(FlatList))),
    {Timestamps, Stats}.

-ifdef(TEST).

merge_metrics_test() ->
    Merge = fun (Data) -> merge_metrics(Data, none) end,
    ?assertEqual({[], []}, Merge([])),
    ?assertEqual({[], []}, Merge([{node1, []}])),
    ?assertEqual({[], [{[{<<"metric">>, {[{name, m1}]}},
                         {<<"values">>, {[{node1, []}]}}]}]},
                 Merge([{node1, [{[{<<"metric">>, {[{name, m1}]}},
                                   {<<"values">>, []}]}]}])),
    ?assertEqual({[10,20], [{[{<<"metric">>, {[{name, m1}]}},
                              {<<"values">>, {[{node1, [v1, v2]}]}}]}]},
                 Merge([{node1, [{[{<<"metric">>, {[{name, m1}]}},
                                   {<<"values">>, [[10,v1],
                                                   [20,v2]]}]}]}])),
    ?assertEqual(
        {[10,15,20,25,35,40],
         [
          {[{<<"metric">>, {[{name, m1}]}},
            {<<"values">>, {[{node1, [n1m1v1, <<"NaN">>, n1m1v2, <<"NaN">>,
                                      <<"NaN">>, <<"NaN">>]}]}}]},
          {[{<<"metric">>, {[{name, m2}]}},
            {<<"values">>, {[{node1, [<<"NaN">>, n1m2v1, <<"NaN">>, n1m2v2,
                                      n1m2v3, <<"NaN">>]},
                             {node2, [<<"NaN">>, n2m2v1, n2m2v2, <<"NaN">>,
                                      n2m2v3, n2m2v4]}]}}]},
          {[{<<"metric">>, {[{name, m3}]}},
            {<<"values">>, {[{node2, [n2m3v1, <<"NaN">>, n2m3v2, <<"NaN">>,
                                      <<"NaN">>, <<"NaN">>]}]}}]}
         ]},
         Merge([{node1, [{[{<<"metric">>, {[{name, m1}]}},
                           {<<"values">>, [[10,n1m1v1],
                                           [20,n1m1v2]]}]},
                         {[{<<"metric">>, {[{name, m2}]}},
                           {<<"values">>, [[15,n1m2v1],
                                           [25,n1m2v2],
                                           [35,n1m2v3]]}]}]},
                {node2, [{[{<<"metric">>, {[{name, m2}]}},
                           {<<"values">>, [[15,n2m2v1],
                                           [20,n2m2v2],
                                           [35,n2m2v3],
                                           [40,n2m2v4]]}]},
                         {[{<<"metric">>, {[{name, m3}]}},
                           {<<"values">>, [[10,n2m3v1],
                                           [20,n2m3v2]]}]}]}])).
-endif.

normalize_datapoints([], [], Acc) ->
    lists:reverse(Acc);
normalize_datapoints([T | Tail1], [[T, V] | Tail2], Acc) ->
    normalize_datapoints(Tail1, Tail2, [V | Acc]);
normalize_datapoints([_ | Tail1], Values, Acc) ->
    normalize_datapoints(Tail1, Values, [<<"NaN">> | Acc]).

aggregate_datapoints(none, Datapoints) -> [{<<"values">>, {Datapoints}}];
aggregate_datapoints(F, Datapoints) ->
    {Nodes, DatapointsWithoutNodes} = lists:unzip(Datapoints),
    Fun = fun (L) ->
              Res = aggregate(F, [prometheus:parse_value(E) || E <- L]),
              prometheus:format_value(Res)
          end,
    [{<<"values">>, misc:zipwithN(Fun, DatapointsWithoutNodes)},
     {<<"nodes">>, Nodes}].

aggregate(sum, List) -> foldl2(fun prometheus_sum/2, undefined, List);
aggregate(max, List) -> foldl2(fun prometheus_max/2, undefined, List);
aggregate(min, List) -> foldl2(fun prometheus_min/2, undefined, List);
aggregate(avg, List) ->
    case aggregate(sum, List) of
        undefined -> undefined;
        infinity -> infinity;
        neg_infinity -> neg_infinity;
        N -> N / length(List)
    end.

foldl2(_, Acc, []) -> Acc;
foldl2(F, Acc, [E | Tail]) ->
    case F(E, Acc) of
        {stop, Res} -> Res;
        {ok, NewAcc} -> foldl2(F, NewAcc, Tail)
    end.

-ifdef(TEST).

aggregate_test() ->
    ?assertEqual(undefined, aggregate(sum, [])),
    ?assertEqual(undefined, aggregate(max, [])),
    ?assertEqual(undefined, aggregate(min, [])),
    ?assertEqual(undefined, aggregate(avg, [])).

aggregate_randomized_test() ->
    RandomList = fun (N, K, Extra) ->
            L = lists:seq(1,N),
            Undefined = lists:duplicate(K, undefined),
            {lists:sum(L), misc:shuffle(L ++ Undefined ++ Extra)}
        end,
    lists:foreach(
      fun (_) ->
              N = rand:uniform(30),
              K = rand:uniform(20),
              {Sum, List} = RandomList(N, K, []),
              ?assertEqual(Sum, aggregate(sum, List)),
              ?assertEqual(N, aggregate(max, List)),
              ?assertEqual(1, aggregate(min, List)),
              ?assertEqual(Sum / length(List), aggregate(avg, List)),

              {_, List2} = RandomList(N, K, [infinity]),
              ?assertEqual(infinity, aggregate(sum, List2)),
              ?assertEqual(infinity, aggregate(max, List2)),
              ?assertEqual(1, aggregate(min, List2)),
              ?assertEqual(infinity, aggregate(avg, List2)),

              {_, List3} = RandomList(N, K, [neg_infinity]),
              ?assertEqual(neg_infinity, aggregate(sum, List3)),
              ?assertEqual(N, aggregate(max, List3)),
              ?assertEqual(neg_infinity, aggregate(min, List3)),
              ?assertEqual(neg_infinity, aggregate(avg, List3)),

              {_, List4} = RandomList(N, K, lists:duplicate(3, neg_infinity) ++
                                            lists:duplicate(3, infinity)),
              ?assertEqual(undefined, aggregate(sum, List4)),
              ?assertEqual(infinity, aggregate(max, List4)),
              ?assertEqual(neg_infinity, aggregate(min, List4)),
              ?assertEqual(undefined, aggregate(avg, List4))
      end, lists:seq(1,1000)).
-endif.

prometheus_sum(undefined, V) -> {ok, V};
prometheus_sum(V, undefined) -> {ok, V};
prometheus_sum(infinity, neg_infinity) -> {stop, undefined};
prometheus_sum(neg_infinity, infinity) -> {stop, undefined};
prometheus_sum(infinity, _) -> {ok, infinity};
prometheus_sum(_, infinity) -> {ok, infinity};
prometheus_sum(neg_infinity, _) -> {ok, neg_infinity};
prometheus_sum(_, neg_infinity) -> {ok, neg_infinity};
prometheus_sum(V1, V2) -> {ok, V1 + V2}.

prometheus_max(undefined, V) -> {ok, V};
prometheus_max(V, undefined) -> {ok, V};
prometheus_max(infinity, _) -> {stop, infinity};
prometheus_max(_, infinity) -> {stop, infinity};
prometheus_max(V, neg_infinity) -> {ok, V};
prometheus_max(neg_infinity, V) -> {ok, V};
prometheus_max(V1, V2) when V1 >= V2 -> {ok, V1};
prometheus_max(_V1, V2) -> {ok, V2}.

prometheus_min(undefined, V) -> {ok, V};
prometheus_min(V, undefined) -> {ok, V};
prometheus_min(neg_infinity, _) -> {stop, neg_infinity};
prometheus_min(_, neg_infinity) -> {stop, neg_infinity};
prometheus_min(V, infinity) -> {ok, V};
prometheus_min(infinity, V) -> {ok, V};
prometheus_min(V1, V2) when V1 >= V2 -> {ok, V2};
prometheus_min(V1, _V2) -> {ok, V1}.

validate_negative_ts(Name, Now, State) ->
    validator:validate(
      fun (TS) when TS < 0 ->
              {value, Now + TS};
          (_) ->
              ok
      end, Name, State).
