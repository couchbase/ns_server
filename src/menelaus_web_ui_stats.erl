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

-export([handle_ui_stats_post_v2/1]).

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
    [validator:required(query, _),
     validator:string(query, _),
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

validate_nodes_v2(Name, State, Req) ->
    validator:validate(
      fun (Nodes) ->
              {Right, Wrong} =
                  misc:partitionmap(
                    fun (HostName) ->
                            case menelaus_web_node:find_node_hostname(
                                   HostName, Req) of
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
    Query = proplists:get_value(query, Params),
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
                                        {extract, Query, Start, End, Step,
                                         Timeout}, 2 * Timeout,
                                        fun ({ok, R}) -> {true, R};
                                            ({error, Reason}) -> {false, Reason}
                                        end),

    MapNode =
        fun (N) when Nodes == all ->
                LocalAddr = menelaus_util:local_addr(Req),
                Node = menelaus_web_node:build_node_hostname(ns_config:latest(),
                                                             N, LocalAddr),
                iolist_to_binary(Node);
            (N) ->
                proplists:get_value(N, Nodes)
        end,

    Errors = [{[{node, MapNode(N)},
                {error, format_error(R)}]} || {N, R} <- BadRes],
    NodeStats = [{MapNode(N), R} || {N, R} <- GoodRes],
    {Timestamps, Stats} = merge_metrics(NodeStats),
    {[{timestamps, Timestamps},
      {stats, Stats},
      {errors, Errors}]}.

format_error(Bin) when is_binary(Bin) -> Bin;
format_error({exit, {{nodedown, _}, _}}) -> <<"Node is down">>;
format_error({exit, _}) -> <<"Unexpected server error">>.

merge_metrics(Res) ->
    FlatList = [{maps:from_list(Metric), Node, Values} ||
                    {Node, Metrics} <- Res,
                    {Props} <- Metrics,
                    [{<<"metric">>, {Metric}},
                     {<<"values">>, Values}] <- [lists:sort(Props)]],

    Timestamps =
        lists:umerge([[TS || [TS, _] <- Values] || {_, _, Values} <- FlatList]),

    Stats = lists:map(
              fun ({M, L}) ->
                  Values = {[{N, normalize_datapoints(Timestamps, V, [])}
                                 || {_, N, V} <- L]},
                  {[{<<"metric">>, {maps:to_list(M)}},
                    {<<"values">>, Values}]}
              end, misc:keygroup(1, lists:sort(FlatList))),
    {Timestamps, Stats}.

-ifdef(TEST).

merge_metrics_test() ->
    ?assertEqual({[], []}, merge_metrics([])),
    ?assertEqual({[], []}, merge_metrics([{node1, []}])),
    ?assertEqual({[], [{[{<<"metric">>, {[{name, m1}]}},
                         {<<"values">>, {[{node1, []}]}}]}]},
                 merge_metrics([{node1, [{[{<<"metric">>, {[{name, m1}]}},
                                           {<<"values">>, []}]}]}])),
    ?assertEqual({[10,20], [{[{<<"metric">>, {[{name, m1}]}},
                              {<<"values">>, {[{node1, [v1, v2]}]}}]}]},
                 merge_metrics([{node1, [{[{<<"metric">>, {[{name, m1}]}},
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
         merge_metrics([{node1, [{[{<<"metric">>, {[{name, m1}]}},
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

validate_negative_ts(Name, Now, State) ->
    validator:validate(
      fun (TS) when TS < 0 ->
              {value, Now + TS};
          (_) ->
              ok
      end, Name, State).
