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

-define(IRATE_INTERVAL, "1m").

pre_70_stats_to_prom_query(StatSection, StatList) ->
    {Instance, Type} =
        case StatSection of
            "@query" -> {"n1ql", "n1ql"};
            "@global" -> {"ns_server", "audit"};
            "@system" -> {"ns_server", "system"};
            "@system-processes" -> {"ns_server", "system-processes"}
        end,

    CommonLabels = [{<<"instance">>, Instance}, {<<"type">>, Type}],

    StatList2 = case StatList of
                    all -> default_stat_list(StatSection);
                    _ -> StatList
                end,

    Metrics = case StatList2 of
                  all -> [{{gauge, []}, []}];
                  L ->
                      Convert = pre_70_name_to_prom_name(StatSection, _),
                      misc:groupby_map(
                        fun ({MetricType, {Name, Params}}) ->
                            {{MetricType, lists:usort(Params)}, Name}
                        end, [M || S <- L, {ok, M} <- [Convert(S)]])
              end,

    Asts =
        lists:map(
          fun ({{MetricType, Labels}, Names}) ->
                  NamesStr = lists:join("|", lists:usort(Names)),
                  LabelsAst =
                      {[{re, <<"name">>, NamesStr} || NamesStr =/= ""] ++
                       [{eq, K, V} || {K, V} <- Labels ++ CommonLabels]},
                  case MetricType of
                      gauge -> LabelsAst;
                      counter -> {call, <<"irate">>, none,
                                  [{range_vector, LabelsAst, ?IRATE_INTERVAL}]}
                  end
          end, Metrics),
    prometheus:format_promql({'or', Asts}).

pre_70_name_to_prom_name(Section, Name) when is_atom(Name) ->
    pre_70_name_to_prom_name(Section, atom_to_binary(Name, latin1));
pre_70_name_to_prom_name("@system", Name) ->
    {ok, {gauge, {<<"sys_", Name/binary>>, []}}};
pre_70_name_to_prom_name("@system-processes", Name) ->
    case binary:split(Name, <<"/">>) of
        [ProcName, MetricName] ->
            {ok, {gauge, {MetricName, [{proc, ProcName}]}}};
        _ ->
            {ok, {gauge, {Name, []}}}
    end;
pre_70_name_to_prom_name("@query", <<"query_", Name/binary>>)
                                        when Name == <<"active_requests">>;
                                             Name == <<"queued_requests">> ->
    {ok, {gauge, {<<"n1ql_", Name/binary>>, []}}};
pre_70_name_to_prom_name("@query", <<"query_", Name/binary>>) ->
    {ok, {counter, {<<"n1ql_", Name/binary>>, []}}};
pre_70_name_to_prom_name("@global", Name) -> {ok, {gauge, {Name, []}}};
pre_70_name_to_prom_name(_, _) ->
    {error, not_found}.

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
key_type_by_stat_type("@system-processes") -> binary.

%% For system stats it's simple, we can get all of them with a simple query
%% {type="system"}. For most of other stats it's not always the case.
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
default_stat_list(_) -> all.
