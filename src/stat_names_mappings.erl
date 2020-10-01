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

-export([pre_70_stats_to_prom_query/2, prom_name_to_pre_70_name/2,
         handle_stats_mapping_get/3]).

-include("ns_test.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(IRATE_INTERVAL, "1m").

handle_stats_mapping_get(Section, StatTokens, Req) ->
    StatName = lists:flatten(lists:join("/", StatTokens)),
    Stats = case StatName of
                "all" -> all;
                S -> [list_to_binary(S)]
            end,
    Query = pre_70_stats_to_prom_query(Section, Stats),
    menelaus_util:reply_text(Req, Query, 200).

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
    map_index_stats(<<"fts">>, service_fts:get_counters(), Bucket, Stat);

pre_70_stat_to_prom_query("@index", <<"index_ram_percent">>) ->
    {ok, named(<<"index_ram_percent">>,
               {'*', [{'/', [{ignoring, [<<"name">>]}],
                       [metric(<<"index_memory_used_total">>),
                        metric(<<"index_memory_quota">>)]}, 100]})};
pre_70_stat_to_prom_query("@index", <<"index_remaining_ram">>) ->
    {ok, named(<<"index_remaining_ram">>,
               {'-', [{ignoring, [<<"name">>]}],
                [metric(<<"index_memory_quota">>),
                 metric(<<"index_memory_used_total">>)]})};
pre_70_stat_to_prom_query("@index", <<"index_memory_used">>) ->
    {ok, metric(<<"index_memory_used_total">>)};
pre_70_stat_to_prom_query("@index", Stat) ->
    {ok, metric(Stat)};

pre_70_stat_to_prom_query("@index-" ++ Bucket, <<"index/", Stat/binary>>) ->
    map_index_stats(<<"index">>, service_index:get_counters(), Bucket, Stat);

pre_70_stat_to_prom_query("@cbas", <<"cbas_disk_used">>) ->
    {ok, metric(<<"cbas_disk_used_bytes_total">>)};
pre_70_stat_to_prom_query("@cbas", <<"cbas_gc_count">>) ->
    {ok, rate(metric(<<"cbas_gc_count_total">>))};
pre_70_stat_to_prom_query("@cbas", <<"cbas_gc_time">>) ->
    {ok, rate(metric(<<"cbas_gc_time_milliseconds_total">>))};
pre_70_stat_to_prom_query("@cbas", <<"cbas_heap_used">>) ->
    {ok, metric(<<"cbas_heap_memory_used_bytes">>)};
pre_70_stat_to_prom_query("@cbas", <<"cbas_system_load_average">>) ->
    {ok, metric(<<"cbas_system_load_average">>)};
pre_70_stat_to_prom_query("@cbas", <<"cbas_thread_count">>) ->
    {ok, metric(<<"cbas_thread_count">>)};
pre_70_stat_to_prom_query("@cbas", <<"cbas_io_reads">>) ->
    {ok, rate(metric(<<"cbas_io_reads_total">>))};
pre_70_stat_to_prom_query("@cbas", <<"cbas_io_writes">>) ->
    {ok, rate(metric(<<"cbas_io_writes_total">>))};

pre_70_stat_to_prom_query("@cbas-" ++ Bucket, <<"cbas/", Stat/binary>>) ->
    Incoming = {[{eq, <<"name">>, <<"cbas_incoming_records_count">>},
                 {eq, <<"bucket">>, Bucket},
                 {eq, <<"link">>, <<"Local">>}]},
    Failed = {[{eq, <<"name">>, <<"cbas_failed_to_parse_records_count">>},
               {eq, <<"bucket">>, Bucket},
               {eq, <<"link">>, <<"Local">>}]},
    case Stat of
        <<"incoming_records_count_total">> ->
            {ok, named(<<"cbas_incoming_records_count_total">>,
                       sumby([], Incoming))};
        <<"all/incoming_records_count_total">> ->
            {ok, named(<<"cbas_all_incoming_records_count_total">>,
                       sumby([], Incoming))};
        <<"failed_at_parser_records_count_total">> ->
            {ok, named(<<"cbas_failed_at_parser_records_count_total">>,
                       sumby([], Failed))};
        <<"all/failed_at_parser_records_count_total">> ->
            {ok, named(<<"cbas_all_failed_at_parser_records_count_total">>,
                       sumby([], Failed))};
        <<"incoming_records_count">> ->
            {ok, named(<<"cbas_incoming_records_count">>,
                       sumby([], rate(Incoming)))};
        <<"all/incoming_records_count">> ->
            {ok, named(<<"cbas_all_incoming_records_count">>,
                       sumby([], rate(Incoming)))};
        <<"failed_at_parser_records_count">> ->
            {ok, named(<<"cbas_failed_at_parser_records_count">>,
                       sumby([], rate(Failed)))};
        <<"all/failed_at_parser_records_count">> ->
            {ok, named(<<"cbas_all_failed_at_parser_records_count">>,
                       sumby([], rate(Failed)))};
        _ ->
            {error, not_found}
    end;

pre_70_stat_to_prom_query("@xdcr-" ++ Bucket, <<"replication_changes_left">>) ->
    M = {[{eq, <<"name">>, <<"xdcr_changes_left_total">>},
          {eq, <<"sourceBucketName">>, Bucket}]},
    {ok, sumby([<<"name">>], M)};
pre_70_stat_to_prom_query("@xdcr-" ++ Bucket,
                          <<"replication_docs_rep_queue">>) ->
    M = {[{eq, <<"name">>, <<"xdcr_docs_rep_queue_total">>},
          {eq, <<"sourceBucketName">>, Bucket}]},
    {ok, sumby([<<"name">>], M)};
pre_70_stat_to_prom_query("@xdcr-" ++ Bucket,
                          <<"replications/", Stat/binary>>) ->
    BucketBin = list_to_binary(Bucket),
    [ReplId, Source, Target, Name] = binary:split(Stat, <<"/">>, [global]),
    Metric = fun (N) ->
                 {RId, Type} =
                    case ReplId of
                        <<"*">> -> {<<"*">>, <<"*">>};
                        <<"backfill_", Id/binary>> -> {Id, <<"Backfill">>};
                        Id -> {Id, <<"Main">>}
                    end,
                 {[{eq, <<"name">>, N}, {eq, <<"sourceBucketName">>, Bucket}] ++
                  [{eq, <<"pipelineType">>, Type} || Type =/= <<"*">>] ++
                  [{eq, <<"targetClusterUUID">>, RId} || RId =/= <<"*">>] ++
                  [{eq, <<"targetBucketName">>, Target} || Target =/= <<"*">>]}
             end,
    case Name of
        _ when Source =/= BucketBin ->
            {error, not_found};
        N when N =:= <<"time_committing">>;
               N =:= <<"wtavg_docs_latency">>;
               N =:= <<"wtavg_get_latency">>;
               N =:= <<"wtavg_meta_latency">>;
               N =:= <<"throughput_throttle_latency">>;
               N =:= <<"resp_wait_time">>;
               N =:= <<"throttle_latency">> ->
            M = Metric(<<"xdcr_", N/binary, "_seconds">>),
            {ok, multiply_by_scalar(M, 1000)};
        <<"dcp_dispatch_time">> ->
            M = Metric(<<"xdcr_dcp_dispatch_time_seconds">>),
            {ok, multiply_by_scalar(M, 1000000000)};
        <<"bandwidth_usage">> ->
            M = rate(Metric(<<"xdcr_data_replicated_bytes">>)),
            {ok, named(<<"xdcr_bandwidth_usage_bytes_per_second">>, M)};
        <<"rate_doc_checks">> ->
            {ok, named(<<"xdcr_rate_doc_checks_docs_per_second">>,
                       {call, idelta, none,
                        [{range_vector, Metric(<<"xdcr_docs_checked_total">>),
                          ?IRATE_INTERVAL}]})};
        <<"rate_received_from_dcp">> ->
            {ok, named(<<"xdcr_rate_received_from_dcp_docs_per_second">>,
                       rate(Metric(<<"xdcr_docs_received_from_dcp_total">>)))};
        <<"rate_doc_opt_repd">> ->
            {ok, named(<<"xdcr_rate_doc_opt_repd_docs_per_second">>,
                       rate(Metric(<<"xdcr_docs_opt_repd_total">>)))};
        <<"rate_replicated">> ->
            {ok, named(<<"xdcr_rate_replicated_docs_per_second">>,
                       rate(Metric(<<"xdcr_docs_written_total">>)))};
        N when N =:= <<"deletion_filtered">>;
               N =:= <<"expiry_received_from_dcp">>;
               N =:= <<"docs_opt_repd">>;
               N =:= <<"deletion_failed_cr_source">>;
               N =:= <<"set_filtered">>;
               N =:= <<"datapool_failed_gets">>;
               N =:= <<"dcp_datach_length">>;
               N =:= <<"docs_filtered">>;
               N =:= <<"docs_checked">>;
               N =:= <<"set_received_from_dcp">>;
               N =:= <<"docs_unable_to_filter">>;
               N =:= <<"set_failed_cr_source">>;
               N =:= <<"set_docs_written">>;
               N =:= <<"docs_written">>;
               N =:= <<"deletion_docs_written">>;
               N =:= <<"expiry_docs_written">>;
               N =:= <<"num_failedckpts">>;
               N =:= <<"add_docs_written">>;
               N =:= <<"docs_rep_queue">>;
               N =:= <<"docs_failed_cr_source">>;
               N =:= <<"deletion_received_from_dcp">>;
               N =:= <<"num_checkpoints">>;
               N =:= <<"expiry_filtered">>;
               N =:= <<"expiry_stripped">>;
               N =:= <<"changes_left">>;
               N =:= <<"docs_processed">>;
               N =:= <<"docs_received_from_dcp">>;
               N =:= <<"expiry_failed_cr_source">> ->
            {ok, Metric(<<"xdcr_", N/binary, "_total">>)};
        N when N =:= <<"size_rep_queue">>;
               N =:= <<"data_replicated">> ->
            {ok, Metric(<<"xdcr_", N/binary, "_bytes">>)}
    end;

pre_70_stat_to_prom_query(_, _) ->
    {error, not_found}.

%% Works for fts and index, Prefix is the only difference
map_index_stats(Prefix, Counters, Bucket, Stat) ->
    IsCounter =
        fun (N) ->
            try
                lists:member(binary_to_existing_atom(N, latin1), Counters)
            catch
                _:_ -> false
            end
        end,
    case binary:split(Stat, <<"/">>, [global]) of
        [<<"disk_overhead_estimate">> = N] ->
              DiskSize = sumby([<<"name">>],
                               bucket_metric(<<Prefix/binary, "_disk_size">>,
                                             Bucket)),
              FragPerc = sumby([<<"name">>],
                               bucket_metric(<<Prefix/binary, "_frag_percent">>,
                                             Bucket)),
              Name = <<Prefix/binary, "_", N/binary>>,
              {ok, named(Name, {'/', [{'*', [{ignoring, [<<"name">>]}],
                                       [DiskSize, FragPerc]}, 100]})};
        [Index,  <<"disk_overhead_estimate">> = N] ->
              DiskSize = sumby([<<"name">>, <<"index">>],
                               index_metric(<<Prefix/binary, "_disk_size">>,
                                             Bucket, Index)),
              FragPerc = sumby([<<"name">>, <<"index">>],
                               index_metric(<<Prefix/binary, "_frag_percent">>,
                                             Bucket, Index)),
              Name = <<Prefix/binary, "_", N/binary>>,
              {ok, named(Name, {'/', [{'*', [{ignoring, [<<"name">>]}],
                                       [DiskSize, FragPerc]}, 100]})};
        [N] ->
            Name = <<Prefix/binary, "_", N/binary>>,
            case IsCounter(N) of
                true ->
                    {ok, sumby([<<"name">>],
                               rate(bucket_metric(Name, Bucket)))};
                false ->
                    {ok, sumby([<<"name">>], bucket_metric(Name, Bucket))}
            end;
        [Index, N] ->
            Name = <<Prefix/binary, "_", N/binary>>,
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
    end.

rate(Ast) -> {call, irate, none, [{range_vector, Ast, ?IRATE_INTERVAL}]}.
sumby(ByFields, Ast) -> {call, sum, {by, ByFields}, [Ast]}.
metric(Name) -> {[{eq, <<"name">>, Name}]}.
bucket_metric(Name, Bucket) ->
    {[{eq, <<"name">>, Name}, {eq, <<"bucket">>, Bucket}]}.
index_metric(Name, Bucket, Index) ->
    {[{eq, <<"name">>, Name}, {eq, <<"bucket">>, Bucket}] ++
     [{eq, <<"index">>, Index} || Index =/= <<"*">>]}.
named(Name, Ast) ->
    {call, label_replace, none, [Ast, <<"name">>, Name, <<>>, <<>>]}.
multiply_by_scalar(Ast, Scalar) ->
    {'*', [Ast, Scalar]}.

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
            <<"index_memory_used_total">> when Bucket == "@index" ->
                {ok, <<"index_memory_used">>};
            <<"index_", _/binary>> = Name when Bucket == "@index" ->
                {ok, Name};
            <<"index_", Name/binary>> -> %% for @index-<bucket>
                case proplists:get_value(<<"index">>, JSONProps, <<>>) of
                    <<>> -> {ok, <<"index/", Name/binary>>};
                    Index -> {ok, <<"index/", Index/binary, "/", Name/binary>>}
                end;
            <<"cbas_disk_used_bytes_total">> ->
                {ok, <<"cbas_disk_used">>};
            <<"cbas_gc_count_total">> ->
                {ok, <<"cbas_gc_count">>};
            <<"cbas_gc_time_milliseconds_total">> ->
                {ok, <<"cbas_gc_time">>};
            <<"cbas_heap_memory_used_bytes">> ->
                {ok, <<"cbas_heap_used">>};
            <<"cbas_system_load_average">> ->
                {ok, <<"cbas_system_load_average">>};
            <<"cbas_thread_count">> ->
                {ok, <<"cbas_thread_count">>};
            <<"cbas_io_reads_total">> ->
                {ok, <<"cbas_io_reads">>};
            <<"cbas_io_writes_total">> ->
                {ok, <<"cbas_io_writes">>};
            <<"cbas_all_", Name/binary>> ->
                {ok, <<"cbas/all/", Name/binary>>};
            <<"cbas_", Name/binary>> ->
                {ok, <<"cbas/", Name/binary>>};
            <<"xdcr_", Name/binary>> ->
                build_pre_70_xdcr_name(Name, JSONProps);
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

build_pre_70_xdcr_name(Name, Props) ->
    Suffixes = [<<"_total">>, <<"_seconds">>,
                <<"_bytes_per_second">>, <<"_docs_per_second">>,
                <<"_bytes">>],
    case drop_suffixes(Name, Suffixes) of
        {ok, Stripped} ->
            Id = proplists:get_value(<<"targetClusterUUID">>, Props),
            Source = proplists:get_value(<<"sourceBucketName">>, Props),
            Target = proplists:get_value(<<"targetBucketName">>, Props),
            Type = proplists:get_value(<<"pipelineType">>, Props),
            if
                Type   =:= <<"Backfill">>,
                Id     =/= undefined,
                Source =/= undefined,
                Target =/= undefined ->
                    {ok, <<"replications/backfill_", Id/binary, "/",
                           Source/binary, "/", Target/binary,"/",
                           Stripped/binary>>};
                Type   =:= <<"Main">>,
                Id     =/= undefined,
                Source =/= undefined,
                Target =/= undefined ->
                    {ok, <<"replications/", Id/binary, "/",
                           Source/binary, "/", Target/binary,"/",
                           Stripped/binary>>};
                (Stripped =:= <<"docs_rep_queue">>) or
                (Stripped =:= <<"changes_left">>),
                Id       =:= undefined,
                Source   =:= undefined,
                Target   =:= undefined ->
                    {ok, <<"replication_", Stripped/binary>>};
                true ->
                    {error, not_found}
            end;
        false ->
            {error, not_found}
    end.

drop_suffixes(Bin, Suffixes) ->
    Check = fun (Suffix) ->
                fun (NameToParse) ->
                    case misc:is_binary_ends_with(NameToParse, Suffix) of
                        true ->
                            L = byte_size(NameToParse) - byte_size(Suffix),
                            {ok, binary:part(NameToParse, {0, L})};
                        false ->
                            false
                    end
                end
            end,
    functools:alternative(Bin,[Check(S) || S <- Suffixes]).

key_type_by_stat_type("@query") -> atom;
key_type_by_stat_type("@global") -> atom;
key_type_by_stat_type("@system") -> atom;
key_type_by_stat_type("@system-processes") -> binary;
key_type_by_stat_type("@fts") -> binary;
key_type_by_stat_type("@fts-" ++ _) -> binary;
key_type_by_stat_type("@index") -> binary;
key_type_by_stat_type("@index-" ++ _) -> binary;
key_type_by_stat_type("@cbas") -> binary;
key_type_by_stat_type("@cbas-" ++ _) -> binary;
key_type_by_stat_type("@xdcr-" ++ _) -> binary.



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
    [<<"fts/*/", (bin(S))/binary>> || S <- Stats];
default_stat_list("@index") ->
    Stats = service_index:get_service_gauges() ++
            service_index:get_service_counters() ++
            [ram_percent, remaining_ram],
    [<<"index_", (bin(S))/binary>> || S <- Stats];
default_stat_list("@index-" ++ _) ->
    Stats = service_index:get_gauges() ++
            service_index:get_counters() ++
            service_index:get_computed(),
    [<<"index/", (bin(S))/binary>> || S <- Stats] ++
    [<<"index/*/", (bin(S))/binary>> || S <- Stats];
default_stat_list("@cbas") ->
    Stats = service_cbas:get_service_gauges() ++
            service_cbas:get_service_counters(),
    [<<"cbas_", (bin(S))/binary>> || S <- Stats];
default_stat_list("@cbas-" ++ _) ->
    Stats = service_cbas:get_gauges() ++
            service_cbas:get_counters(),
    [<<"cbas/", (bin(S))/binary>> || S <- Stats] ++
    [<<"cbas/all/", (bin(S))/binary>> || S <- Stats];
default_stat_list("@xdcr-" ++ B) ->
    Bucket = list_to_binary(B),
    Stats = [
        <<"add_docs_written">>, <<"bandwidth_usage">>, <<"changes_left">>,
        <<"data_replicated">>, <<"datapool_failed_gets">>,
        <<"dcp_datach_length">>, <<"dcp_dispatch_time">>,
        <<"deletion_docs_written">>, <<"deletion_failed_cr_source">>,
        <<"deletion_filtered">>, <<"deletion_received_from_dcp">>,
        <<"docs_checked">>, <<"docs_failed_cr_source">>, <<"docs_filtered">>,
        <<"docs_opt_repd">>, <<"docs_processed">>, <<"docs_received_from_dcp">>,
        <<"docs_rep_queue">>, <<"docs_unable_to_filter">>, <<"docs_written">>,
        <<"expiry_docs_written">>, <<"expiry_failed_cr_source">>,
        <<"expiry_filtered">>, <<"expiry_received_from_dcp">>,
        <<"expiry_stripped">>, <<"num_checkpoints">>, <<"num_failedckpts">>,
        <<"rate_doc_checks">>, <<"rate_doc_opt_repd">>,
        <<"rate_received_from_dcp">>, <<"rate_replicated">>,
        <<"resp_wait_time">>, <<"set_docs_written">>,
        <<"set_failed_cr_source">>, <<"set_filtered">>,
        <<"set_received_from_dcp">>, <<"size_rep_queue">>,
        <<"throttle_latency">>, <<"throughput_throttle_latency">>,
        <<"time_committing">>, <<"wtavg_docs_latency">>,
        <<"wtavg_get_latency">>, <<"wtavg_meta_latency">>
    ],
    [<<"replication_changes_left">>, <<"replication_docs_rep_queue">>] ++
    [<<"replications/*/", Bucket/binary, "/*/", S/binary>> || S <- Stats].

-ifdef(TEST).
pre_70_to_prom_query_test_() ->
    Test = fun (Section, Stats, ExpectedQuery) ->
               Name = lists:flatten(io_lib:format("~s: ~p", [Section, Stats])),
               {Name, ?_assertBinStringsEqual(
                         list_to_binary(ExpectedQuery),
                         pre_70_stats_to_prom_query(Section, Stats))}
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
          "irate({name=~`n1ql_errors|n1ql_request_time`}["?IRATE_INTERVAL"])"),
     Test("@fts", all, "{name=~`fts_curr_batches_blocked_by_herder|"
                               "fts_num_bytes_used_ram|"
                               "fts_total_queries_rejected_by_herder`}"),
     Test("@fts", [], ""),
     Test("@fts", [<<"fts_num_bytes_used_ram">>,
                   <<"fts_curr_batches_blocked_by_herder">>],
          "{name=~`fts_curr_batches_blocked_by_herder|"
                  "fts_num_bytes_used_ram`}"),
     Test("@fts-test", all,
          "sum by (name) ({name=~`fts_doc_count|"
                                 "fts_num_bytes_used_disk|"
                                 "fts_num_files_on_disk|"
                                 "fts_num_mutations_to_index|"
                                 "fts_num_pindexes_actual|"
                                 "fts_num_pindexes_target|"
                                 "fts_num_recs_to_persist|"
                                 "fts_num_root_filesegments|"
                                 "fts_num_root_memorysegments`,"
                          "bucket=`test`}) or "
          "sum by (name) (irate({name=~`fts_total_bytes_indexed|"
                                       "fts_total_bytes_query_results|"
                                       "fts_total_compaction_written_bytes|"
                                       "fts_total_queries|"
                                       "fts_total_queries_error|"
                                       "fts_total_queries_slow|"
                                       "fts_total_queries_timeout|"
                                       "fts_total_request_time|"
                                       "fts_total_term_searchers`,"
                                "bucket=`test`}[1m])) or "
          "sum by (name,index) ({name=~`fts_doc_count|"
                                       "fts_num_bytes_used_disk|"
                                       "fts_num_files_on_disk|"
                                       "fts_num_mutations_to_index|"
                                       "fts_num_pindexes_actual|"
                                       "fts_num_pindexes_target|"
                                       "fts_num_recs_to_persist|"
                                       "fts_num_root_filesegments|"
                                       "fts_num_root_memorysegments`,"
                                "bucket=`test`}) or "
          "sum by (name,index) (irate({name=~`fts_total_bytes_indexed|"
                                             "fts_total_bytes_query_results|"
                                             "fts_total_compaction_written_bytes|"
                                             "fts_total_queries|"
                                             "fts_total_queries_error|"
                                             "fts_total_queries_slow|"
                                             "fts_total_queries_timeout|"
                                             "fts_total_request_time|"
                                             "fts_total_term_searchers`,"
                                      "bucket=`test`}[1m]))"),
     Test("@fts-test", [], ""),
     Test("@fts-test", [<<"fts/num_files_on_disk">>,
                        <<"fts/num_pindexes_target">>,
                        <<"fts/doc_count">>,
                        <<"fts/ind1/doc_count">>,
                        <<"fts/ind1/num_pindexes_target">>,
                        <<"fts/ind2/num_files_on_disk">>,
                        <<"fts/ind2/total_queries">>],
          "sum by (name) ({name=~`fts_doc_count|"
                                 "fts_num_files_on_disk|"
                                 "fts_num_pindexes_target`,bucket=`test`}) or "
          "sum by (name,index) ({name=~`fts_doc_count|"
                                       "fts_num_pindexes_target`,"
                                "bucket=`test`,index=`ind1`}) or "
          "sum by (name,index) ({name=`fts_num_files_on_disk`,"
                                "bucket=`test`,index=`ind2`}) or "
          "sum by (name,index) (irate({name=`fts_total_queries`,"
                                      "bucket=`test`,index=`ind2`}[1m]))"),
     Test("@index", all,
          "{name=~`index_memory_quota|index_memory_used_total`} or "
          "label_replace(({name=`index_memory_used_total`} / ignoring(name)"
                        " {name=`index_memory_quota`}) * 100,"
                        "`name`,`index_ram_percent`,``,``) or "
          "label_replace({name=`index_memory_quota`} - ignoring(name) "
                        "{name=`index_memory_used_total`},"
                        "`name`,`index_remaining_ram`,``,``)"),
     Test("@index", [], ""),
     Test("@index", [<<"index_memory_quota">>, <<"index_remaining_ram">>],
          "{name=`index_memory_quota`} or "
          "label_replace({name=`index_memory_quota`} - ignoring(name) "
                        "{name=`index_memory_used_total`},"
                        "`name`,`index_remaining_ram`,``,``)"),
     Test("@index-test", all,
          "label_replace((sum by (name) ({name=`index_disk_size`,"
                                         "bucket=`test`})"
                           " * ignoring(name) "
                         "sum by (name) ({name=`index_frag_percent`,"
                                         "bucket=`test`})) / 100,"
                         "`name`,`index_disk_overhead_estimate`,``,``) or "
          "label_replace((sum by (name,index) ({name=`index_disk_size`,"
                                               "bucket=`test`})"
                           " * ignoring(name) "
                         "sum by (name,index) ({name=`index_frag_percent`,"
                                               "bucket=`test`})) / 100,"
                        "`name`,`index_disk_overhead_estimate`,``,``) or "
          "sum by (name) ({name=~`index_data_size|index_data_size_on_disk|"
                                 "index_disk_size|index_frag_percent|"
                                 "index_items_count|index_log_space_on_disk|"
                                 "index_memory_used|index_num_docs_pending|"
                                 "index_num_docs_queued|index_raw_data_size|"
                                 "index_recs_in_mem|index_recs_on_disk`,"
                          "bucket=`test`}) or "
          "sum by (name) (irate({name=~`index_cache_hits|index_cache_misses|"
                                       "index_num_docs_indexed|"
                                       "index_num_requests|"
                                       "index_num_rows_returned|"
                                       "index_scan_bytes_read|"
                                       "index_total_scan_duration`,"
                                "bucket=`test`}[1m])) or "
          "sum by (name,index) ({name=~`index_data_size|"
                                       "index_data_size_on_disk|"
                                       "index_disk_size|"
                                       "index_frag_percent|"
                                       "index_items_count|"
                                       "index_log_space_on_disk|"
                                       "index_memory_used|"
                                       "index_num_docs_pending|"
                                       "index_num_docs_queued|"
                                       "index_raw_data_size|"
                                       "index_recs_in_mem|"
                                       "index_recs_on_disk`,bucket=`test`}) or "
          "sum by (name,index) (irate({name=~`index_cache_hits|"
                                             "index_cache_misses|"
                                             "index_num_docs_indexed|"
                                             "index_num_requests|"
                                             "index_num_rows_returned|"
                                             "index_scan_bytes_read|"
                                             "index_total_scan_duration`,"
                                      "bucket=`test`}[1m]))"),
     Test("@index-test", [], ""),
     Test("@index-test", [<<"index/cache_hits">>,
                          <<"index/i1/num_requests">>,
                          <<"index/i1/disk_overhead_estimate">>],
          "label_replace((sum by (name,index) ({name=`index_disk_size`,"
                                               "bucket=`test`,"
                                               "index=`i1`}) * ignoring(name) "
                         "sum by (name,index) ({name=`index_frag_percent`,"
                                               "bucket=`test`,"
                                               "index=`i1`})) / 100,"
                        "`name`,`index_disk_overhead_estimate`,``,``) or "
          "sum by (name) (irate({name=`index_cache_hits`,"
                                 "bucket=`test`}[1m])) or "
          "sum by (name,index) (irate({name=`index_num_requests`,"
                                      "bucket=`test`,"
                                      "index=`i1`}[1m]))"),
     Test("@cbas", all, "{name=~`cbas_disk_used_bytes_total|"
                                "cbas_heap_memory_used_bytes|"
                                "cbas_system_load_average|"
                                "cbas_thread_count`} or "
                        "irate({name=~`cbas_gc_count_total|"
                                      "cbas_gc_time_milliseconds_total|"
                                      "cbas_io_reads_total|"
                                      "cbas_io_writes_total`}[1m])"),
     Test("@cbas", [], ""),
     Test("@cbas", [<<"cbas_disk_used">>, <<"cbas_gc_count">>],
          "{name=`cbas_disk_used_bytes_total`} or "
          "irate({name=`cbas_gc_count_total`}[1m])"),
     Test("@cbas-test", all,
          "label_replace(sum by () ({name=`cbas_failed_to_parse_records_count`,"
                                    "bucket=`test`,link=`Local`}),"
                        "`name`,`cbas_all_failed_at_parser_records_count_total`"
                        ",``,``) or "
          "label_replace(sum by () ({name=`cbas_incoming_records_count`,"
                                    "bucket=`test`,link=`Local`}),"
                        "`name`,`cbas_all_incoming_records_count_total`,"
                        "``,``) or "
          "label_replace(sum by () ({name=`cbas_failed_to_parse_records_count`,"
                                    "bucket=`test`,link=`Local`}),"
                        "`name`,`cbas_failed_at_parser_records_count_total`,"
                        "``,``) or "
          "label_replace(sum by () ({name=`cbas_incoming_records_count`,"
                                    "bucket=`test`,link=`Local`}),"
                        "`name`,`cbas_incoming_records_count_total`,``,``) or "
          "label_replace(sum by () (irate({name=`cbas_failed_to_parse_records_"
                                          "count`,"
                                          "bucket=`test`,link=`Local`}[1m])),"
                        "`name`,`cbas_all_failed_at_parser_records_count`,"
                        "``,``) or "
          "label_replace(sum by () (irate({name=`cbas_incoming_records_count`,"
                                          "bucket=`test`,link=`Local`}[1m])),"
                        "`name`,`cbas_all_incoming_records_count`,``,``) or "
          "label_replace(sum by () (irate({name=`cbas_failed_to_parse_records_"
                                          "count`,"
                                          "bucket=`test`,link=`Local`}[1m])),"
                        "`name`,`cbas_failed_at_parser_records_count`,"
                        "``,``) or "
          "label_replace(sum by () (irate({name=`cbas_incoming_records_count`,"
                                          "bucket=`test`,link=`Local`}[1m])),"
                        "`name`,`cbas_incoming_records_count`,``,``)"),
     Test("@cbas-test", [], ""),
     Test("@xdcr-test", all,
          "{name=~`xdcr_add_docs_written_total|xdcr_changes_left_total|"
                  "xdcr_data_replicated_bytes|xdcr_datapool_failed_gets_total|"
                  "xdcr_dcp_datach_length_total|"
                  "xdcr_deletion_docs_written_total|"
                  "xdcr_deletion_failed_cr_source_total|"
                  "xdcr_deletion_filtered_total|"
                  "xdcr_deletion_received_from_dcp_total|"
                  "xdcr_docs_checked_total|xdcr_docs_failed_cr_source_total|"
                  "xdcr_docs_filtered_total|xdcr_docs_opt_repd_total|"
                  "xdcr_docs_processed_total|xdcr_docs_received_from_dcp_total|"
                  "xdcr_docs_rep_queue_total|xdcr_docs_unable_to_filter_total|"
                  "xdcr_docs_written_total|xdcr_expiry_docs_written_total|"
                  "xdcr_expiry_failed_cr_source_total|"
                  "xdcr_expiry_filtered_total|"
                  "xdcr_expiry_received_from_dcp_total|"
                  "xdcr_expiry_stripped_total|xdcr_num_checkpoints_total|"
                  "xdcr_num_failedckpts_total|xdcr_set_docs_written_total|"
                  "xdcr_set_failed_cr_source_total|xdcr_set_filtered_total|"
                  "xdcr_set_received_from_dcp_total|xdcr_size_rep_queue_bytes`,"
           "sourceBucketName=`test`} or "
          "({name=~`xdcr_resp_wait_time_seconds|xdcr_throttle_latency_seconds|"
                   "xdcr_throughput_throttle_latency_seconds|"
                   "xdcr_time_committing_seconds|"
                   "xdcr_wtavg_docs_latency_seconds|"
                   "xdcr_wtavg_get_latency_seconds|"
                   "xdcr_wtavg_meta_latency_seconds`,"
            "sourceBucketName=`test`} * 1000) or "
          "({name=`xdcr_dcp_dispatch_time_seconds`,"
            "sourceBucketName=`test`} * 1000000000) or "
          "label_replace(idelta({name=`xdcr_docs_checked_total`,"
                                "sourceBucketName=`test`}[1m]),`name`,"
                        "`xdcr_rate_doc_checks_docs_per_second`,``,``) or "
          "label_replace(irate({name=`xdcr_data_replicated_bytes`,"
                               "sourceBucketName=`test`}[1m]),`name`,"
                        "`xdcr_bandwidth_usage_bytes_per_second`,``,``) or "
          "label_replace(irate({name=`xdcr_docs_opt_repd_total`,"
                               "sourceBucketName=`test`}[1m]),`name`,"
                        "`xdcr_rate_doc_opt_repd_docs_per_second`,``,``) or "
          "label_replace(irate({name=`xdcr_docs_received_from_dcp_total`,"
                               "sourceBucketName=`test`}[1m]),`name`,"
                        "`xdcr_rate_received_from_dcp_docs_per_second`,``,``)"
          " or "
          "label_replace(irate({name=`xdcr_docs_written_total`,"
                               "sourceBucketName=`test`}[1m]),`name`,"
                        "`xdcr_rate_replicated_docs_per_second`,``,``) or "
          "sum by (name) ({name=~`xdcr_changes_left_total|"
                                 "xdcr_docs_rep_queue_total`,"
                          "sourceBucketName=`test`})"),
     Test("@xdcr-test", [], ""),
     Test("@xdcr-test",
          [<<"replications/id1/test/test2/changes_left">>,
           <<"replications/backfill_id1/test/test2/changes_left">>,
           <<"replications/id1/test/test2/docs_processed">>,
           <<"replications/backfill_id1/test/test2/docs_processed">>,
           <<"replications/id1/test/test2/bandwidth_usage">>,
           <<"replications/backfill_id1/test/test2/bandwidth_usage">>,
           <<"replications/id1/test/test2/time_committing">>,
           <<"replications/backfill_id1/test/test2/time_committing">>],
          "{name=~`xdcr_changes_left_total|xdcr_docs_processed_total`,"
           "sourceBucketName=`test`,pipelineType=`Backfill`,"
           "targetClusterUUID=`id1`,targetBucketName=`test2`} or "
          "{name=~`xdcr_changes_left_total|xdcr_docs_processed_total`,"
           "sourceBucketName=`test`,pipelineType=`Main`,"
           "targetClusterUUID=`id1`,targetBucketName=`test2`} or "
          "({name=`xdcr_time_committing_seconds`,sourceBucketName=`test`,"
            "pipelineType=`Backfill`,targetClusterUUID=`id1`,"
            "targetBucketName=`test2`} * 1000) or "
          "({name=`xdcr_time_committing_seconds`,sourceBucketName=`test`,"
            "pipelineType=`Main`,targetClusterUUID=`id1`,"
            "targetBucketName=`test2`} * 1000) or "
          "label_replace(irate({name=`xdcr_data_replicated_bytes`,"
                               "sourceBucketName=`test`,"
                               "pipelineType=`Backfill`,"
                               "targetClusterUUID=`id1`,"
                               "targetBucketName=`test2`}[1m]),`name`,"
                        "`xdcr_bandwidth_usage_bytes_per_second`,``,``) or "
          "label_replace(irate({name=`xdcr_data_replicated_bytes`,"
                               "sourceBucketName=`test`,"
                               "pipelineType=`Main`,"
                               "targetClusterUUID=`id1`,"
                               "targetBucketName=`test2`}[1m]),`name`,"
                        "`xdcr_bandwidth_usage_bytes_per_second`,``,``)")].

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
          {error, not_found}),
     Test("@fts", "{\"name\": \"fts_num_bytes_used_ram\"}",
          {ok, <<"fts_num_bytes_used_ram">>}),
     Test("@fts-test", "{\"name\": \"fts_doc_count\"}",
          {ok, <<"fts/doc_count">>}),
     Test("@fts-test", "{\"name\": \"fts_doc_count\", \"index\": \"ind1\"}",
          {ok, <<"fts/ind1/doc_count">>}),
     Test("@index", "{\"name\": \"index_memory_used_total\"}",
          {ok, <<"index_memory_used">>}),
     Test("@index", "{\"name\": \"index_remaining_ram\"}",
          {ok, <<"index_remaining_ram">>}),
     Test("@index-test", "{\"name\": \"index_disk_size\"}",
          {ok, <<"index/disk_size">>}),
     Test("@index-test", "{\"name\": \"index_disk_size\", \"index\": \"ind1\"}",
          {ok, <<"index/ind1/disk_size">>}),
     Test("@cbas", "{\"name\": \"cbas_gc_time_milliseconds_total\"}",
          {ok, <<"cbas_gc_time">>}),
     Test("@cbas-test",
          "{\"name\": \"cbas_failed_at_parser_records_count_total\"}",
          {ok, <<"cbas/failed_at_parser_records_count_total">>}),
     Test("@cbas-test",
          "{\"name\": \"cbas_all_failed_at_parser_records_count_total\"}",
          {ok, <<"cbas/all/failed_at_parser_records_count_total">>}),
     Test("@xdcr-test",
          "{\"name\": \"xdcr_docs_processed_total\","
           "\"sourceBucketName\": \"b1\","
           "\"pipelineType\": \"Backfill\","
           "\"targetClusterUUID\": \"id1\","
           "\"targetBucketName\":\"b2\"}",
          {ok, <<"replications/backfill_id1/b1/b2/docs_processed">>}),
     Test("@xdcr-test",
          "{\"name\": \"xdcr_bandwidth_usage_bytes_per_second\","
           "\"sourceBucketName\": \"b1\","
           "\"pipelineType\": \"Main\","
           "\"targetClusterUUID\": \"id1\","
           "\"targetBucketName\":\"b2\"}",
          {ok, <<"replications/id1/b1/b2/bandwidth_usage">>}),
     Test("@xdcr-test",
          "{\"name\": \"xdcr_changes_left_total\"}",
          {ok, <<"replication_changes_left">>})].

-endif.
