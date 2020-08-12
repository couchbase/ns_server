%% @author Couchbase <info@couchbase.com>
%% @copyright 2018-2019 Couchbase, Inc.
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
-module(stat_names_mappings).

-export([pre_70_stats_to_prom_query/2, prom_name_to_pre_70_name/2]).

-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(IRATE_INTERVAL, "1m").

pre_70_stats_to_prom_query("@system", all) ->
    <<"{category=`system`}">>;
pre_70_stats_to_prom_query("@system-processes", all) ->
    <<"{category=`system-processes`}">>;
pre_70_stats_to_prom_query("@global", all) ->
    <<"{category=`audit`}">>;
pre_70_stats_to_prom_query(StatSection, all) ->
    pre_70_stats_to_prom_query(StatSection, default_stat_list(StatSection));
pre_70_stats_to_prom_query(StatSection, List) ->
    AstList = lists:filtermap(
                fun (S) ->
                    case pre_70_stat_to_prom_query(StatSection, S) of
                        {ok, R} -> {true, R};
                        {error, not_found} -> false
                    end
                end, [bin(S) || S <- List]),
    prometheus:format_promql({'or', AstList}).

pre_70_stat_to_prom_query("@system", Stat) ->
    {ok, {[{eq, <<"name">>, <<"sys_", Stat/binary>>}]}};

pre_70_stat_to_prom_query("@system-processes", Stat) ->
    case binary:split(Stat, <<"/">>) of
        [ProcName, MetricName] ->
            {ok, {[{eq, <<"name">>, <<"sysproc_", MetricName/binary>>},
                   {eq, <<"proc">>, ProcName}]}};
        _ ->
            {error, not_found}
    end;

pre_70_stat_to_prom_query("@global", Stat) ->
    {ok, {[{eq, <<"name">>, Stat}]}};

pre_70_stat_to_prom_query("@query", <<"query_", Stat/binary>>) ->
    Gauges = [<<"active_requests">>, <<"queued_requests">>],
    case lists:member(Stat, Gauges) of
        true -> {ok, {[{eq, <<"name">>, <<"n1ql_", Stat/binary>>}]}};
        false -> {ok, rate({[{eq, <<"name">>, <<"n1ql_", Stat/binary>>}]})}
    end;

pre_70_stat_to_prom_query("@fts", Stat) ->
    {ok, {[{eq, <<"name">>, Stat}]}};

pre_70_stat_to_prom_query("@fts-" ++ Bucket, <<"fts/", Stat/binary>>) ->
    Counters = service_fts:get_counters(),
    IsCounter =
        fun (N) ->
            try
                lists:member(binary_to_existing_atom(N, latin1), Counters)
            catch
                _:_ -> false
            end
        end,
    case binary:split(Stat, <<"/">>, [global]) of
        [N] ->
            Name = <<"fts_", N/binary>>,
            case IsCounter(N) of
                true ->
                    {ok, sumby([<<"name">>],
                               rate(bucket_metric(Name, Bucket)))};
                false ->
                    {ok, sumby([<<"name">>], bucket_metric(Name, Bucket))}
            end;
        [Index, N] ->
            Name = <<"fts_", N/binary>>,
            case IsCounter(N) of
                true ->
                    {ok, sumby([<<"name">>, <<"index">>],
                               rate(index_metric(Name, Bucket, Index)))};
                false ->
                    {ok, sumby([<<"name">>, <<"index">>],
                               index_metric(Name, Bucket, Index))}
            end;
        _ ->
            {error, not_found}
    end;

pre_70_stat_to_prom_query(_, _) ->
    {error, not_found}.

rate(Ast) -> {call, irate, none, [{range_vector, Ast, ?IRATE_INTERVAL}]}.
sumby(ByFields, Ast) -> {call, sum, {by, ByFields}, [Ast]}.
bucket_metric(Name, Bucket) ->
    {[{eq, <<"name">>, Name}, {eq, <<"bucket">>, Bucket}]}.
index_metric(Name, Bucket, Index) ->
    {[{eq, <<"name">>, Name}, {eq, <<"bucket">>, Bucket}] ++
     [{eq, <<"index">>, Index} || Index =/= <<"*">>]}.

bin(A) when is_atom(A) -> atom_to_binary(A, latin1);
bin(B) when is_binary(B) -> B.

prom_name_to_pre_70_name(Bucket, {JSONProps}) ->
    Res =
        case proplists:get_value(<<"name">>, JSONProps) of
            <<"n1ql_", Name/binary>> ->
                {ok, <<"query_", Name/binary>>};
            <<"sys_", Name/binary>> -> {ok, Name};
            <<"sysproc_", Name/binary>> ->
                Proc = proplists:get_value(<<"proc">>, JSONProps, <<>>),
                {ok, <<Proc/binary, "/", Name/binary>>};
            <<"audit_", _/binary>> = Name -> {ok, Name};
            <<"fts_", _/binary>> = Name when Bucket == "@fts" ->
                {ok, Name};
            <<"fts_", Name/binary>> -> %% for @fts-<bucket>
                case proplists:get_value(<<"index">>, JSONProps, <<>>) of
                    <<>> -> {ok, <<"fts/", Name/binary>>};
                    Index -> {ok, <<"fts/", Index/binary, "/", Name/binary>>}
                end;
            _ -> {error, not_found}
        end,
    case Res of
        {ok, BinName} ->
            %% Since pre-7.0 stats don't care much about stats name type,
            %% 7.0 stats have to convert names to correct types based on stat
            %% section.
            case key_type_by_stat_type(Bucket) of
                atom -> {ok, binary_to_atom(BinName, latin1)};
                binary -> {ok, BinName}
            end;
        {error, _} = Error ->
            Error
    end.

key_type_by_stat_type("@query") -> atom;
key_type_by_stat_type("@global") -> atom;
key_type_by_stat_type("@system") -> atom;
key_type_by_stat_type("@system-processes") -> binary;
key_type_by_stat_type("@fts") -> binary;
key_type_by_stat_type("@fts-" ++ _) -> binary.

%% For system stats it's simple, we can get all of them with a simple query
%% {category="system"}. For most of other stats it's not always the case.
%% For example, for query we need to request rates for some stats, so we have
%% to know which stats should be rates and which stats should be plain. This
%% leads to the fact that when we need to get all of them we have to know
%% the real list of stats being requested. It can be achieved by various
%% means. I chose to just hardcode it (should be fine as it's for backward
%% compat only).
default_stat_list("@query") ->
    [query_active_requests, query_queued_requests, query_errors,
     query_invalid_requests, query_request_time, query_requests,
     query_requests_500ms, query_requests_250ms, query_requests_1000ms,
     query_requests_5000ms, query_result_count, query_result_size,
     query_selects, query_service_time, query_warnings];
default_stat_list("@fts") ->
    Stats = service_fts:get_service_gauges() ++
            service_fts:get_service_counters(),
    [<<"fts_", (bin(S))/binary>> || S <- Stats];
default_stat_list("@fts-" ++ _) ->
    Stats = service_fts:get_gauges() ++
            service_fts:get_counters(),
    [<<"fts/", (bin(S))/binary>> || S <- Stats] ++
    [<<"fts/*/", (bin(S))/binary>> || S <- Stats].

-ifdef(TEST).
pre_70_to_prom_query_test_() ->
    Test = fun (Section, Stats, ExpectedQuery) ->
               Name = lists:flatten(io_lib:format("~s: ~p", [Section, Stats])),
               {Name,
                fun () ->
                    ?assertEqual(pre_70_stats_to_prom_query(Section, Stats),
                                 list_to_binary(ExpectedQuery))
                end}
           end,
    [Test("@system", all, "{category=`system`}"),
     Test("@system", [], ""),
     Test("@system-processes", all, "{category=`system-processes`}"),
     Test("@system-processes", [], ""),
     Test("@system-processes", [<<"ns_server/cpu_utilization">>,
                                <<"ns_server/mem_resident">>,
                                <<"couchdb/cpu_utilization">>],
          "{name=`sysproc_cpu_utilization`,proc=`couchdb`} or "
          "{name=~`sysproc_cpu_utilization|sysproc_mem_resident`,"
           "proc=`ns_server`}"),
     Test("@query", all,
          "{name=~`n1ql_active_requests|n1ql_queued_requests`} or "
          "irate({name=~`n1ql_errors|n1ql_invalid_requests|n1ql_request_time|"
                        "n1ql_requests|n1ql_requests_1000ms|"
                        "n1ql_requests_250ms|n1ql_requests_5000ms|"
                        "n1ql_requests_500ms|n1ql_result_count|"
                        "n1ql_result_size|n1ql_selects|n1ql_service_time|"
                        "n1ql_warnings`}["?IRATE_INTERVAL"])"),
     Test("@query", [], ""),
     Test("@query", [query_errors, query_active_requests, query_request_time],
          "{name=`n1ql_active_requests`} or "
          "irate({name=~`n1ql_errors|n1ql_request_time`}["?IRATE_INTERVAL"])")].

prom_name_to_pre_70_name_test_() ->
    Test = fun (Section, Json, ExpectedRes) ->
               Name = lists:flatten(io_lib:format("~s: ~s", [Section, Json])),
               Props = ejson:decode(Json),
               {Name,
                fun () ->
                    ?assertEqual(prom_name_to_pre_70_name(Section, Props),
                                 ExpectedRes)
                end}
           end,
    [Test("@system", "{\"name\": \"sys_cpu_user_rate\"}",
          {ok, cpu_user_rate}),
     Test("@system-processes",
          "{\"name\": \"sysproc_cpu_utilization\",\"proc\": \"ns_server\"}",
          {ok, <<"ns_server/cpu_utilization">>}),
     Test("@query", "{\"name\": \"n1ql_active_requests\"}",
          {ok, query_active_requests}),
     Test("@query", "{}",
          {error, not_found}),
     Test("@query", "{\"name\": \"unknown\"}",
          {error, not_found}),
     Test("@query", "{\"proc\": \"ns_server\"}",
          {error, not_found})].

-endif.
