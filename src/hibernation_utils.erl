%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

-module(hibernation_utils).

-include("cut.hrl").

-export([run_hibernation_op/3,
         set_hibernation_status/2,
         update_hibernation_status/1,
         build_hibernation_task/0]).

run_hibernation_op(Body, Args, Timeout) ->
    case async:run_with_timeout(
           fun () ->
                   async:foreach(
                     Body, Args, [exit_on_first_error])
           end, Timeout) of
        {ok, Result} ->
            Result;
        {error, timeout} ->
            exit(timeout)
    end.

get_hibernation_status(Snapshot) ->
    chronicle_compat:get(Snapshot, hibernation_status, #{default => undefined}).

set_hibernation_status(Bucket, Status) ->
    chronicle_compat:set_multiple(
      [{hibernation_status, Status},
       {hibernation_uuid, couch_uuids:random()},
       {hibernation_bucket, Bucket}]).

update_hibernation_status(Status) ->
    chronicle_kv:transaction(
      kv, [hibernation_status],
      fun (Snapshot) ->
              case get_hibernation_status(Snapshot) of
                  {Op, running} ->
                      {commit, [{set, hibernation_status, {Op, Status}}]};
                  _ ->
                      {abort, ok}
              end
      end),
    ok.

keys() ->
    [hibernation_status, hibernation_uuid, hibernation_bucket].

fetch_snapshot(Txn) ->
    chronicle_compat:txn_get_many(keys(), Txn).

build_task_prop(_, undefined) ->
    [];
build_task_prop(hibernation_status, {Op, Status}) when is_atom(Status) ->
    [{op, Op}, {status, Status}];
build_task_prop(hibernation_bucket, Bucket) when is_list(Bucket) ->
    [{bucket, list_to_binary(Bucket)}];
build_task_prop(hibernation_uuid, UUID) when is_binary(UUID) ->
    [{id, UUID}].

build_hibernation_task() ->
    Snapshot = chronicle_compat:get_snapshot([fetch_snapshot(_)]),
    TaskProps = [begin
                     Val = chronicle_compat:get(Snapshot, Key,
                                                #{default => undefined}),
                     build_task_prop(Key, Val)
                 end
                 || Key <- keys()],
    Task = lists:flatten(TaskProps),
    case Task of
        [] ->
            [];
        _ ->
            [[{type, hibernation} | Task] ++
             [{isStale,
               leader_registry:whereis_name(ns_orchestrator) =:= undefined}]]

    end.
