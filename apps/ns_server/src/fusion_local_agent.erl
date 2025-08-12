%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% local server that is responsible for janitoring fusion namespaces on the
%% node if the bucket is deleted or fusion on the bucket is disabled
-module(fusion_local_agent).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-record(state, {state :: fusion_uploaders:state(),
                queue :: pid(),
                deleting :: [binary()]}).

-export([start_link/0]).
-export([init/1, handle_info/2]).

-define(UPLOADERS_STOP_TIMEOUT, ?get_timeout(uploaders_stop, 60000)).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Self = self(),
    FusionSettingsKey = fusion_uploaders:config_key(),
    chronicle_compat_events:subscribe(
      fun (Key) when Key =:= FusionSettingsKey ->
              Self ! check_state_and_buckets;
          (Key) ->
              case ns_bucket:buckets_change(Key) of
                  false ->
                      ok;
                  true ->
                      Self ! check_state_and_buckets
              end
      end),

    Self ! check_state_and_buckets,
    {ok, Pid} = work_queue:start_link(),
    {ok, #state{state = disabled,
                queue = Pid,
                deleting = []}}.

handle_info({deleted, Namespace}, State = #state{deleting = Deleting}) ->
    {noreply, State#state{deleting = Deleting -- [Namespace]}};
handle_info(check_state_and_buckets, State) ->
    misc:flush(check_state_and_buckets),
    FusionState = fusion_uploaders:get_state(),
    NewState = State#state{state = FusionState},
    NewState1 =
        case FusionState of
            disabled ->
                NewState;
            _ ->
                maybe_schedule_deletes(NewState)
        end,
    {noreply, NewState1}.

maybe_schedule_deletes(#state{queue = Queue,
                              deleting = Deleting} = State) ->
    Snapshot = ns_bucket:get_snapshot(all, [props, uuid]),

    {ok, Json} =
        ns_memcached:get_fusion_namespaces(
          fusion_uploaders:get_metadata_store_uri()),
    {Parsed} = ejson:decode(Json),
    Namespaces = proplists:get_value(<<"namespaces">>, Parsed),
    BucketsThatNeedData = [N || {N, C} <- ns_bucket:get_buckets(Snapshot),
                                lists:member(ns_bucket:get_fusion_state(C),
                                             [enabled, stopped, stopping])],

    NeededNamespaces = [iolist_to_binary(
                          ["kv/", BucketName, "/",
                           ns_bucket:uuid(BucketName, Snapshot)]) ||
                           BucketName <- BucketsThatNeedData],
    ToDelete = (Namespaces -- NeededNamespaces) -- Deleting,
    Self = self(),
    case ToDelete of
        [] ->
            State;
        _ ->
            ?log_debug("Schedule the following namespaces for deletion: ~p",
                       [ToDelete]),
            [work_queue:submit_sync_work(
               Queue, ?cut(delete_data(Self, NS))) || NS <- ToDelete],
            State#state{deleting = Deleting ++ ToDelete}
    end.

wait_for_uploaders_to_stop(_BucketName, 0) ->
    {error, timeout};
wait_for_uploaders_to_stop(BucketName, Tries) ->
    case ns_memcached:get_fusion_uploaders_state(BucketName) of
        {ok, {[]}} ->
            ok;
        {ok, {VBucketsInfo}} ->
            case lists:any(
                   fun ({_VBName, {VBStats}}) ->
                           proplists:get_value(<<"state">>, VBStats) =/=
                               <<"disabled">>
                   end, VBucketsInfo) of
                true ->
                    timer:sleep(1000),
                    wait_for_uploaders_to_stop(BucketName, Tries - 1);
                false ->
                    ok
            end;
        bucket_not_found ->
            ok;
        Error ->
            {error, Error}
    end.

delete_data(Parent, Namespace) ->
    ?log_info("Delete namespace ~p. Wait for uploaders to stop", [Namespace]),
    [_, BucketName, _] = string:tokens(binary_to_list(Namespace), "/"),
    case wait_for_uploaders_to_stop(BucketName,
                                    ?UPLOADERS_STOP_TIMEOUT div 1000) of
        {error, Error} ->
            ?log_error("Error waiting for uploaders for bucket ~p to stop: ~p",
                       [BucketName, Error]),
            delete_data(Parent, Namespace);
        ok ->
            ?log_info("Start deleting namespace ~p", [Namespace]),
            case ns_memcached:delete_fusion_namespace(
                   fusion_uploaders:get_log_store_uri(),
                   fusion_uploaders:get_metadata_store_uri(), Namespace) of
                ok ->
                    ?log_info("Namespace ~p deleted succesfully", [Namespace]),
                    ok;
                Error ->
                    ?log_error("Error deleting namespace ~p: ~p",
                               [Namespace, Error])
            end
    end,
    Parent ! {deleted, Namespace}.
