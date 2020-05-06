%% @author Couchbase <info@couchbase.com>
%% @copyright 2018-2020 Couchbase, Inc.
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
-module(stats_interface).

-export([system_stats/0,
         sysproc_stats/0,
         buckets_interesting_stats/0,
         latest/2]).

-define(DEFAULT_TIMEOUT, 5000).
-define(IRATE_INTERVAL, "1m").

system_stats() ->
    latest(<<"{type=\"system\", __name__=~\"sys_cpu_utilization_rate|"
             "sys_cpu_stolen_rate|sys_swap_total|sys_swap_used|"
             "sys_mem_total|sys_mem_free|sys_mem_limit|"
             "sys_cpu_cores_available|sys_allocstall\"}">>,
           fun (Props) ->
               <<"sys_", N/binary>> = proplists:get_value(<<"name">>, Props),
               {true, binary_to_atom(N, latin1)}
           end).

sysproc_stats() ->
    Res = latest(
            <<"{type=\"system-processes\", __name__=~\""
              "sysproc_mem_resident|sysproc_mem_size|"
              "sysproc_cpu_utilization|sysproc_major_faults_raw\"}">>,
            fun (Props) ->
                <<"sysproc_", N/binary>> = proplists:get_value(<<"name">>,
                                                               Props),
                P = proplists:get_value(<<"proc">>, Props),
                {true, {binary_to_atom(P, latin1), binary_to_atom(N, latin1)}}
            end),
    misc:groupby_map(fun ({{Proc, Name}, Value}) ->
                         {Proc, {Name, Value}}
                     end, Res).

buckets_interesting_stats() ->
    Q = <<"kv_curr_items or "
          "kv_curr_items_tot or "
          "kv_vb_replica_curr_items or "
          "kv_mem_used_bytes or "
          "couch_docs_actual_disk_size or "
          "couch_views_actual_disk_size or "
          "couch_spatial_disk_size or "
          "kv_ep_db_data_size_bytes or "
          "couch_views_data_size or "
          "couch_spatial_data_size or "
          "kv_vb_active_num_non_resident or "
          "irate(kv_operations{op=\"get\"}["?IRATE_INTERVAL"]) or "
          "irate(kv_get_hits["?IRATE_INTERVAL"]) or "
          "kv_ep_bg_fetched or "
          "label_replace("
            "sum by (bucket) ("
              "irate(kv_num_ops["?IRATE_INTERVAL"]) or "
              "irate(kv_cmd_lookup["?IRATE_INTERVAL"]) or "
              "irate(kv_operations{op=\"set\"}["?IRATE_INTERVAL"]) or "
              "irate(kv_incr_misses["?IRATE_INTERVAL"]) or "
              "irate(kv_incr_hits["?IRATE_INTERVAL"]) or "
              "irate(kv_decr_misses["?IRATE_INTERVAL"]) or "
              "irate(kv_decr_hits["?IRATE_INTERVAL"]) or "
              "irate(kv_delete_misses["?IRATE_INTERVAL"]) or "
              "irate(kv_delete_hits["?IRATE_INTERVAL"])), "
            "\"name\", \"kv_ops\", \"\", \"\") or "
          "sum by (bucket, name) (index_data_size or index_disk_size)">>,
    Res = latest(Q, fun (Props) ->
                        N = proplists:get_value(<<"name">>, Props),
                        B = proplists:get_value(<<"bucket">>, Props),
                        {true, {binary_to_list(B), binary_to_atom(N, latin1)}}
                    end),
    misc:groupby_map(fun ({{Bucket, Name}, Value}) ->
                         {Bucket, {Name, Value}}
                     end, Res).

latest(Query, NameParser) ->
    latest(Query, NameParser, ?DEFAULT_TIMEOUT).
latest(Query, NameParser, Timeout) ->
    Settings = prometheus_cfg:settings(),
    case prometheus:query(Query, undefined, Timeout, Settings) of
        {ok, JsonArray} ->
            lists:filtermap(
              fun ({Props}) ->
                  {MetricProps} = proplists:get_value(<<"metric">>, Props),
                  [_, Val] = proplists:get_value(<<"value">>, Props),
                  case NameParser(MetricProps) of
                      {true, Name} ->
                          {true, {Name, prometheus:parse_value(Val)}};
                      false ->
                          false
                  end
              end, JsonArray);
        {error, _} -> []
    end.
