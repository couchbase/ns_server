%% @author Couchbase <info@couchbase.com>
%% @copyright 2020-2021 Couchbase, Inc.
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

-export([handle_range_post/1, handle_range_get/2,
         handle_get_settings/2, handle_post_settings/2]).

-include("ns_common.hrl").
-include("rbac.hrl").
-include("cut.hrl").

-define(MAX_TS, 9999999999999).
-define(MIN_TS, -?MAX_TS).
-define(DEFAULT_PROMETHEUS_QUERY_TIMEOUT, 60000).


params() ->
    Services = all_services(),

    [{"enabled",
      #{type => bool}},
     {"scrapeInterval",
      #{cfg_key => scrape_interval, type => pos_int}},
     {"scrapeTimeout",
      #{cfg_key => scrape_timeout, type => pos_int}},
     {"snapshotCreationTimeout",
      #{cfg_key => snapshot_timeout_msecs, type => pos_int}},
     {"scrapeIntervalsCalculationPeriod",
      #{cfg_key => intervals_calculation_period, type => int}},
     {"cbcollect.statsMaxSize",
      #{cfg_key => cbcollect_stats_dump_max_size, type => pos_int}},
     {"cbcollect.statsMinPeriod",
      #{cfg_key => cbcollect_stats_min_period, type => pos_int}},
     {"expectedAvgSampleSize",
      #{cfg => average_sample_size, type => pos_int}},
     {"logExecutedQueries",
      #{cfg_key => log_queries, type => bool}},
     {"derivedMetricsFilter",
      #{cfg_key => derived_metrics_filter, type => derived_metrics_filter}},
     {"derivedMetricsCalculationInterval",
      #{cfg_key => derived_metrics_interval, type => int}},

     {"prometheus.retentionSize",
      #{cfg_key => retention_size, type => pos_int}},
     {"prometheus.retentionTime",
      #{cfg_key => retention_time, type => pos_int}},
     {"prometheus.walCompression",
      #{cfg_key => wal_compression, type => bool}},
     {"prometheus.authEnabled",
      #{cfg_key => prometheus_auth_enabled, type => bool}},
     {"prometheus.logLevel",
      #{cfg_key => log_level,
        type => {one_of, string, ["debug", "info", "warn", "error"]}}},
     {"prometheus.maxBlockDuration",
      #{cfg_key => max_block_duration, type => pos_int}},
     {"prometheus.queryMaxSamples",
      #{cfg_key => query_max_samples, type => pos_int}},
     {"prometheus.reportMetrics",
      #{cfg_key => prometheus_metrics_enabled, type => bool}},
     {"prometheus.reportMetricsInterval",
      #{cfg_key => prometheus_metrics_scrape_interval, type => pos_int}},
     {"prometheus.listenAddr",
      #{cfg_key => listen_addr_type,
        type => {one_of, existing_atom, [loopback, any]}}}] ++
    [{"services." ++ N ++ ".highCardEnabled",
      #{cfg_key => [services, S, high_cardinality_enabled], type => bool}}
     || {S, N} <- Services] ++
    [{"statsExport." ++ N ++ ".highCardEnabled",
      #{cfg_key => [external_prometheus_services, S, high_cardinality_enabled],
        type => bool}}
     || {S, N} <- Services].

type_spec(derived_metrics_filter) ->
    #{validators => [fun derived_metrics_filter/2],
      formatter => fun format_derived_metrics_filter/1}.

format_derived_metrics_filter(all) -> {value, <<"all">>};
format_derived_metrics_filter(L) -> {value, [list_to_binary(M) || M <- L]}.

derived_metrics_filter(Name, State) ->
    Err = "must be either \"all\" or list of strings",
    validator:validate(
        case validator:is_json(State) of
            true ->
                fun (<<"all">>) -> {value, all};
                    (List) when is_list(List) ->
                        case lists:all(fun is_binary/1, List) of
                            true ->
                                Metrics = [binary_to_list(B) || B <- List],
                                verify_derived_metrics(Metrics);
                            false -> {error, Err}
                        end;
                    (_NotList) ->
                        {error, Err}
                end;
            false ->
                fun ("all") -> {value, all};
                    (Str) ->
                        Tokens = string:lexemes(Str, ","),
                        Metrics = [string:trim(T) || T <- Tokens],
                        verify_derived_metrics(Metrics)
                end
        end, Name, State).

handle_get_settings(Path, Req) ->
    Settings = misc:update_proplist(
                 prometheus_cfg:default_settings(),
                 ns_config:read_key_fast(stats_settings, [])),
    menelaus_web_settings2:handle_get(Path, params(), fun type_spec/1,
                                      Settings, Req).

handle_post_settings(Path, Req) ->
    menelaus_web_settings2:handle_post(
      apply_props(Path, _, _), Path, params(), fun type_spec/1, Req).

apply_props(Path, PropList, Req) ->
    OldProps = ns_config:read_key_fast(stats_settings, []),
    NewProps = lists:foldl(
                 fun ({KeyTokens, Value}, Acc) ->
                     apply_value(KeyTokens, Value, Acc)
                 end, OldProps, PropList),
    ns_config:set(stats_settings, NewProps),
    handle_get_settings(Path, Req).

apply_value([], Value, _PropList) -> Value;
apply_value([Key | Tail], Value, PropList) ->
    Res = misc:key_update(Key, PropList,
                          fun (SubProplist) ->
                              apply_value(Tail, Value, SubProplist)
                          end),
    case Res of
        false -> [{Key, apply_value(Tail, Value, [])} | PropList];
        _ -> Res
    end.

handle_range_post(Req) ->
    PermFilters =
        case promql_filters_for_identity(menelaus_auth:get_identity(Req)) of
            [] -> menelaus_util:web_exception(403, "Forbidden");
            F -> F
        end,
    Now = os:system_time(millisecond),
    validator:handle(
      fun (List) ->
          %% New process is needed to avoid leaving response messages in
          %% mochiweb handler process's mailbox in case of timeout or other
          %% problems
          misc:executing_on_new_process(
            fun () ->
                Monitors = start_node_extractors_monitoring(List),
                Requests = lists:map(send_metrics_request(_, PermFilters),
                                     List),
                reply_with_chunked_json_array(
                  fun ({Ref, Props}) ->
                      read_metrics_response(Ref, Props, Now)
                  end, lists:zip(Requests, List), Req),
                stop_node_extractors_monitoring(Monitors)
            end)
      end, Req, json_array, post_validators(Now, Req)).

reply_with_chunked_json_array(Fun, List, Req) ->
    HTTPResp = menelaus_util:reply_ok(
                 Req, "application/json; charset=utf-8", chunked),
    Write = mochiweb_response:write_chunk(_, HTTPResp),
    Write(<<"[">>),
    _ = lists:foldl(
          fun (E, IsFirst) ->
              case IsFirst of
                  true -> ok;
                  false -> Write(<<",">>)
              end,
              Write(ejson:encode(Fun(E))),
              false
          end, true, List),
    Write(<<"]">>),
    Write(<<>>).

handle_range_get([], _Req) ->
    menelaus_util:web_exception(404, "not found");
handle_range_get([MetricName | NotvalidatedFunctions], Req) ->
    PermFilters =
        case promql_filters_for_identity(menelaus_auth:get_identity(Req)) of
            [] -> menelaus_util:web_exception(403, "Forbidden");
            F -> F
        end,
    Functions = try validate_functions(NotvalidatedFunctions)
                catch
                    error:invalid_function ->
                        menelaus_util:web_exception(404, "not found")
                end,
    Now = os:system_time(millisecond),
    validator:handle(
      fun (Props) ->
          Labels = lists:filter(fun ({K, _V}) ->
                                     not lists:member(K, [timeWindow, step,
                                                          start, 'end', nodes,
                                                          aggregationFunction,
                                                          timeout])
                                end, Props),
          Metric = [{<<"name">>, iolist_to_binary(MetricName)}|Labels],
          NewProps = [{metric, Metric}, {applyFunctions, Functions} | Props],
          %% New process is needed to avoid leaving response messages in
          %% mochiweb handler process's mailbox in case of timeout or other
          %% problems
          misc:executing_on_new_process(
            fun () ->
                Monitors = start_node_extractors_monitoring([Props]),
                Ref = send_metrics_request(NewProps, PermFilters),
                Res = read_metrics_response(Ref, Props, Now),
                stop_node_extractors_monitoring(Monitors),
                menelaus_util:reply_json(Req, Res)
            end)
      end, Req, qs, get_validators(Now, Req)).

post_validators(Now, Req) ->
    [validate_metric_json(metric, _),
     validator:required(metric, _),
     validator:string_array(applyFunctions, _),
     validate_functions(applyFunctions, _),
     validator:string_array(nodes, _) | validators(Now, Req)] ++
    [validator:unsupported(_)].

get_validators(Now, Req) ->
    [validator:token_list(nodes, ", ", _) | validators(Now, Req)].

validators(Now, Req) ->
    NowSec = Now div 1000,
    [validate_interval(timeWindow, _),
     validator:default(timeWindow, "1m", _),
     menelaus_web_ui_stats:validate_nodes_v2(nodes, _, Req),
     validator:default(nodes,
                       ?cut(menelaus_web_node:get_hostnames(Req, any)), _),
     validator:one_of(aggregationFunction, [max, min, avg, sum, none], _),
     validator:convert(aggregationFunction,
                       fun (L) when is_binary(L) -> binary_to_atom(L, latin1);
                           (L) -> list_to_atom(L)
                       end, _),
     validate_interval(step, _),
     validator:default(step, "10s", _),
     validator:integer(start, ?MIN_TS, ?MAX_TS, _),
     validator:integer('end', ?MIN_TS, ?MAX_TS, _),
     menelaus_web_ui_stats:validate_negative_ts(start, NowSec, _),
     menelaus_web_ui_stats:validate_negative_ts('end', NowSec, _),
     validator:greater_or_equal('end', start, _),
     validator:default(start, NowSec - 60, _),
     validator:default('end', NowSec, _),
     validator:integer(timeout, 1, 60*5*1000, _),
     validator:default(timeout, ?DEFAULT_PROMETHEUS_QUERY_TIMEOUT, _)].

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

send_metrics_request(Props, PermFilters) ->
    Functions = proplists:get_value(applyFunctions, Props, []),
    Window = proplists:get_value(timeWindow, Props),
    Metric = proplists:get_value(metric, Props),
    Name = proplists:get_value(<<"name">>, Metric),
    Labels = proplists:delete(<<"name">>, Metric),
    Query = construct_promql_query(Name, Labels, Functions,
                                   Window, PermFilters),
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

construct_promql_query(Metric, Labels, Functions, Window, PermFilters) ->
    {RangeVFunctions, InstantVFunctions} =
        lists:splitwith(fun is_range_vector_function/1, Functions),
    functools:chain(
      Labels,
      [?cut(lists:map(fun ({PermFilter}) ->
                          {[{eq, "__name__", Metric} || Metric =/= undefined] ++
                           [{re, K, V} || {K, V} <- _] ++
                           PermFilter}
                      end, PermFilters)),
       case RangeVFunctions of
           [] -> fun functools:id/1;
           _ -> lists:map(fun (Ast) -> range_vector(Ast, Window) end, _)
       end,
       lists:map(fun (Ast) -> apply_functions(Ast, RangeVFunctions) end, _),
       {'or', _},
       apply_functions(_, InstantVFunctions),
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

promql_filters_for_identity(Identity) ->
    CompiledRoles = menelaus_roles:get_compiled_roles(Identity),
    PermCheck =
        fun (Obj) ->
            menelaus_roles:is_allowed(collection_perm(Obj), CompiledRoles)
        end,
    case PermCheck([all, all, all]) of
        true -> [{[]}]; %% one empty filter
        false ->
            Roles = menelaus_roles:get_roles(Identity),
            Definitions = menelaus_roles:get_definitions(all),
            PermMap = build_stats_perm_map(Roles, PermCheck, Definitions),
            convert_perm_map_to_promql_ast(PermMap)
    end.

collection_perm([B, S, C]) -> {[{collection, [B, S, C]}, stats], read};
collection_perm([B, S]) ->    {[{collection, [B, S, all]}, stats], read};
collection_perm([B]) ->       {[{collection, [B, all, all]}, stats], read}.

build_stats_perm_map(UserRoles, PermCheckFun, RolesDefinitions) ->
    ParamDefs = menelaus_roles:get_param_defs(_, RolesDefinitions),
    StrippedParams =
        [{Defs, menelaus_roles:strip_ids(Defs, P)} || {R, P} <- UserRoles,
                                                      Defs <- [ParamDefs(R)]],
    Params =
        misc:groupby_map(
          fun ({[bucket_name], B}) -> {buckets, B};
              ({?RBAC_SCOPE_PARAMS, [B, any]}) -> {buckets, [B]};
              ({?RBAC_COLLECTION_PARAMS, [B, any, any]}) -> {buckets, [B]};
              ({?RBAC_SCOPE_PARAMS, S}) -> {scopes, S};
              ({?RBAC_COLLECTION_PARAMS, [B, S, any]}) -> {scopes, [B, S]};
              ({?RBAC_COLLECTION_PARAMS, P}) -> {collections, P}
          end, StrippedParams),

    CheckParam =
        fun F([Obj], CheckPerm, Acc) ->
                case CheckPerm([Obj]) of
                    true -> Acc#{Obj => true};
                    false -> Acc
                end;
            F([Obj | T], CheckPerm, Acc) ->
                case maps:get(Obj, Acc, #{}) of
                    true -> Acc;
                    Map ->
                        NewCheckPerm = fun (E) -> CheckPerm([Obj | E]) end,
                        SubAcc = F(T, NewCheckPerm, Map),
                        Acc#{Obj => SubAcc}
                end
        end,

    CheckParamPerm = ?cut(CheckParam(_1, PermCheckFun, _2)),

    functools:chain(
      #{},
      [lists:foldl(CheckParamPerm, _,
                   proplists:get_value(buckets, Params, [])),
       lists:foldl(CheckParamPerm, _,
                   proplists:get_value(scopes, Params, [])),
       lists:foldl(CheckParamPerm, _,
                   proplists:get_value(collections, Params, []))]).

convert_perm_map_to_promql_ast(PermMap) ->
    AllowedBuckets = maps:keys(maps:filter(fun (_, V) -> V =:= true end,
                                           PermMap)),
    AllowedBucketsRe = [escape_re_chars(B) || B <- AllowedBuckets],
    Filters =
        [{[{re, "bucket", lists:join("|", AllowedBucketsRe)}]}
                || AllowedBucketsRe =/= []] ++
        maps:fold(
          fun (_Bucket, true, Acc) -> Acc;
              (Bucket, ScopePermMap, Acc) ->
                  AllowedScopes = maps:keys(
                                    maps:filter(fun (_, V) -> V =:= true end,
                                                ScopePermMap)),
                  [{[{eq, "bucket", Bucket},
                     {re, "scope", lists:join("|", AllowedScopes)}]}
                        || AllowedScopes =/= []] ++
                  maps:fold(
                    fun (_Scope, true, Acc2) -> Acc2;
                        (Scope, CollectionsPermMap, Acc2) ->
                            AllowedCols = maps:keys(
                                            maps:filter(
                                              fun (_, V) -> V =:= true end,
                                              CollectionsPermMap)),
                            [{[{eq, "bucket", Bucket},
                               {eq, "scope", Scope},
                               {re, "collection", lists:join("|", AllowedCols)}]}
                                    || AllowedCols =/= []] ++ Acc2
                    end, Acc, ScopePermMap)
          end, [], PermMap),
    case Filters of
        [] -> [];
        _ -> [{[{not_re, "bucket", ".+"}]} | Filters]
    end.

escape_re_chars(Str) ->
    re:replace(Str, "[\\[\\].\\\\^$|()?*+{}]", "\\\\&",
               [{return,list}, global]).

verify_derived_metrics(Metrics) ->
    AllDerivedMetrics = all_derived_metrics(),
    case [M || M <- Metrics, not lists:member(M, AllDerivedMetrics)] of
        [] -> {value, Metrics};
        InvalidMetrics ->
            {error, io_lib:format("Invalid derived metrics: ~p",
                                  [InvalidMetrics])}
    end.

all_derived_metrics() ->
    Services = [S || {S, _} <- all_services()],
    [N || S <- Services, {N, _} <- prometheus_cfg:derived_metrics(S)].

all_services() ->
    InstallType = case cluster_compat_mode:is_enterprise() of
                      true -> enterprise;
                      false -> community
                  end,
    [{S, atom_to_list(ns_cluster_membership:json_service_name(S))}
        || S <- [ns_server, xdcr |
                 ns_cluster_membership:allowed_services(InstallType)]].
