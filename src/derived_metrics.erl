%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included
%% in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
%% in that file, in accordance with the Business Source License, use of this
%% software will be governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.
%%
-module(derived_metrics).

-export([is_metric/1, get_metric/2]).

-include("cut.hrl").

is_metric(Name) ->
    get_metric(Name) =/= [].

get_metric(Name, Key) ->
    proplists:get_value(Key, get_metric(Name)).

get_metric(<<"kv_vb_resident_items_ratio">>) ->
    [{params, [<<"Resident">>, <<"Total">>]},
     {aggregation_fun, aggregated_ratio(_, _, 100)},
     {query,
      fun (M) ->
          CI = M(<<"kv_vb_curr_items">>),
          NR = M(<<"kv_vb_num_non_resident">>),
          [promQL:multiply_by_scalar(promQL:op('-', [CI, NR]), 100), CI]
      end}];
get_metric(<<"index_resident_percent">>) ->
    [{params, [<<"in_memory">>, <<"total">>]},
     {aggregation_fun, aggregated_ratio(_, _, 100)},
     {query,
      fun (M) ->
          RP = M(<<"index_resident_percent">>),
          DS = M(<<"index_data_size">>),
          [promQL:op('*', [RP, DS]), DS]
      end}];
get_metric(<<"xdcr_percent_completeness">>) ->
    [{params, [<<"total_processed">>, <<"left_and_processed">>]},
     {aggregation_fun, aggregated_ratio(_, _, 100)},
     {query,
      fun (M) ->
          Processed = M(<<"xdcr_docs_processed_total">>),
          Left = M(<<"xdcr_changes_left_total">>),
          [promQL:multiply_by_scalar(Processed, 100),
           promQL:sum_without([<<"name">>], {'or', [Processed, Left]})]
      end}];
get_metric(<<"index_fragmentation">>) ->
    [{params, [<<"fragmented_size">>, <<"total_size">>]},
     {aggregation_fun, aggregated_ratio(_, _, 100)},
     {query,
      fun (M) ->
          DiskSize = M(<<"index_disk_size">>),
          FragPercent = M(<<"index_frag_percent">>),
          FragmentedSize =
            promQL:sum_without([<<"index">>, <<"collection">>, <<"scope">>],
                               promQL:op('*', [DiskSize, FragPercent])),
          TotalSize =
            promQL:sum_without([<<"index">>, <<"collection">>, <<"scope">>],
                               DiskSize),
          [FragmentedSize, TotalSize]
      end}];
%% Used by unit tests:
get_metric(<<"test_derived_metric">>) ->
    [{params, [<<"p1">>, <<"p2">>]},
     {aggregation_fun,
      fun (P1, P2) ->
          menelaus_web_stats:aggregate(sum, P1) *
          (menelaus_web_stats:aggregate(sum, P2) + 1)
      end},
     {query, fun (M) -> [M(<<"m1">>), M(<<"m2">>)] end}];
get_metric(_) -> [].

aggregated_ratio(Values1, Values2, DivisionByZeroDefault) ->
    case menelaus_web_stats:aggregate(sum, Values2) of
        0 -> DivisionByZeroDefault;
        Total ->
            menelaus_web_stats:aggregate(
              'div', [menelaus_web_stats:aggregate(sum, Values1), Total])
    end.

