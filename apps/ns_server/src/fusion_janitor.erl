%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% server that is responsible for janitoring fusion namespaces on the
%% cluster
-module(fusion_janitor).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-record(state, {state :: fusion_uploaders:state(),
                queue :: pid(),
                deleting :: [binary()],
                failed :: [binary()],
                to_reply :: [{binary(), {pid(), gen_server:reply_tag()}}]}).

-define(GET_STATE_TIMEOUT, ?get_timeout(get_state, 10000)).
-define(GET_NAMESPACES_TIMEOUT, ?get_timeout(get_namespaces, 10000)).
-define(DELETE_NAMESPACE_TIMEOUT, ?get_timeout(delete_namespace, 60000)).
-define(RETRY_INTERVAL, ?get_timeout(retry_interval, 30000)).

-export([start_link/0, get_state/0, delete_namespace/1]).
-export([init/1, handle_info/2, handle_call/3]).

%% RPC calls
-export([do_delete_namespace/1, do_get_namespaces/0,
         do_get_active_bucket_uuids/0]).

-type state() :: {fusion_uploaders:state(), [binary()]}.

-define(UPLOADERS_STOP_TIMEOUT, ?get_timeout(uploaders_stop, 60000)).
-define(WAIT_FOR_UPLOADERS_INTERVAL, ?get_param(wait_for_uploaders_interval,
                                                1000)).
-define(BUCKET_SHUTDOWN_TIMEOUT, ?get_timeout(bucket_shutdown, 60000)).
-define(WAIT_FOR_BUCKET_SHUTDOWN_INTERVAL,
        ?get_param(wait_for_bucket_shutdown_interval, 1000)).
-define(GET_ACTIVE_BUCKET_UUIDS_TIMEOUT,
        ?get_timeout(get_active_bucket_uuids, 10000)).

start_link() ->
    gen_server2:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec get_state() -> state().
get_state() ->
    gen_server2:call(?MODULE, get_state, ?GET_STATE_TIMEOUT).

-spec delete_namespace(ns_bucket:name()) -> ok | error.
delete_namespace(BucketName) ->
    {ok, BucketConfig} = ns_bucket:get_bucket(BucketName),
    case should_have_namespace(BucketConfig) of
        true ->
            ?log_info("Deleting fusion namespace for ~p", [BucketName]),
            gen_server2:call(?MODULE, {delete, BucketName},
                             ?DELETE_NAMESPACE_TIMEOUT);
        false ->
            ok
    end.

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
                deleting = [],
                failed = [],
                to_reply = []}}.

handle_call(get_state, _From, State = #state{state = FusionState,
                                             deleting = Deleting,
                                             failed = Failed}) ->
    {reply, {FusionState, Deleting ++ Failed}, State};
handle_call({delete, BucketName}, From,
            State = #state{deleting = Deleting, to_reply = ToReply}) ->
    Namespace = namespace(BucketName, direct),
    ?log_debug("Requesting to delete namespace ~p", [Namespace]),
    case lists:member(Namespace, Deleting) of
        true ->
            {noreply, State#state{to_reply = [{Namespace, From} | ToReply]}};
        false ->
            case lists:member(Namespace, get_namespaces()) of
                true ->
                    NewState = schedule_deletes([Namespace], State),
                    {noreply,
                     NewState#state{to_reply = [{Namespace, From} | ToReply]}};
                false ->
                    ?log_debug("Request to delete non-existent namespace ~p",
                               [Namespace]),
                    {reply, ok, State}
            end
    end.

handle_info({delete_finished, Namespace, Result},
            State = #state{deleting = Deleting, to_reply = ToReply,
                           failed = Failed}) ->
    [gen_server2:reply(From, Result) || {NS, From} <- ToReply,
                                        NS =:= Namespace],

    NewState =
        case Result of
            ok ->
                State;
            error ->
                erlang:send_after(?RETRY_INTERVAL, self(),
                                  check_state_and_buckets),
                State#state{failed = [Namespace | Failed]}
        end,
    {noreply,
     NewState#state{
       deleting = Deleting -- [Namespace],
       to_reply = [{NS, From} || {NS, From} <- ToReply, NS =/= Namespace]}};

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
    {noreply, NewState1#state{failed = []}}.

get_namespaces() ->
    {ok, Namespaces} = ns_cluster_membership:execute_on_kv_node(
                         ?MODULE, do_get_namespaces, [],
                         ?GET_NAMESPACES_TIMEOUT,
                         "get namespaces", do_get_namespaces_failed),
    Namespaces.

-spec do_get_namespaces() -> [binary()].
do_get_namespaces() ->
    chronicle_compat:pull(),
    {ok, Json} =
        ns_memcached:get_fusion_namespaces(
          fusion_uploaders:get_metadata_store_uri()),
    {Parsed} = ejson:decode(Json),
    proplists:get_value(<<"namespaces">>, Parsed).

should_have_namespace(BucketConfig) ->
    lists:member(ns_bucket:get_fusion_state(BucketConfig),
                 [enabled, enabling, stopped, stopping]).

namespace(BucketName, Snapshot) ->
    iolist_to_binary(["kv/", ns_bucket:uuid(BucketName, Snapshot)]).

maybe_schedule_deletes(#state{deleting = Deleting} = State) ->
    Snapshot = ns_bucket:get_snapshot(all, [props, uuid]),
    Namespaces = get_namespaces(),

    BucketsThatNeedData =
        [BucketName || {BucketName, BucketConfig} <-
                           ns_bucket:get_buckets(Snapshot),
                       should_have_namespace(BucketConfig)],

    NamespacesToKeep = [namespace(BucketName, Snapshot) ||
                           BucketName <- BucketsThatNeedData],
    ToDelete = (Namespaces -- NamespacesToKeep) -- Deleting,
    schedule_deletes(ToDelete, State).

schedule_deletes([], State) ->
    State;
schedule_deletes(ToDelete, #state{queue = Queue,
                                  deleting = Deleting} = State) ->
    Self = self(),
    ?log_debug("Schedule the following namespaces for deletion: ~p",
               [ToDelete]),
    [work_queue:submit_work(
       Queue, ?cut(delete_data(Self, NS))) || NS <- ToDelete],
    State#state{deleting = Deleting ++ ToDelete}.

wait_for_uploaders_to_stop(BucketName) ->
    case ns_bucket:get_bucket(BucketName) of
        {ok, BucketConfig} ->
            case misc:poll_for_condition(
                   ?cut(uploaders_stopped(BucketName, BucketConfig)),
                   ?UPLOADERS_STOP_TIMEOUT, ?WAIT_FOR_UPLOADERS_INTERVAL) of
                timeout ->
                    {error, timeout};
                Other ->
                    Other
            end;
        not_present ->
            {error, bucket_not_found}
    end.

uploaders_stopped(BucketName, BucketConfig) ->
    case janitor_agent:get_fusion_uploaders_state(BucketName, BucketConfig) of
        {ok, PerNodeInfos} ->
            AllStopped =
                lists:all(
                  fun ({_Node, {VBucketsInfo}}) ->
                          lists:all(
                            fun ({_VBName, {VBStats}}) ->
                                    proplists:get_value(<<"state">>, VBStats)
                                        =:= <<"disabled">>
                            end, VBucketsInfo)
                  end, PerNodeInfos),
            case AllStopped of
                true ->
                    ok;
                false ->
                    false
            end;
        {error, _} = Error ->
            Error
    end.

%% The bucket is already gone from the chronicle, but memcached might still
%% have it open on some of the nodes, so we cannot touch the namespace until
%% every active kv node has shut the bucket down.
wait_for_bucket_shutdown(BucketUUID) ->
    case misc:poll_for_condition(
           ?cut(bucket_is_shut_down(BucketUUID)),
           ?BUCKET_SHUTDOWN_TIMEOUT, ?WAIT_FOR_BUCKET_SHUTDOWN_INTERVAL) of
        timeout ->
            {error, timeout};
        Other ->
            Other
    end.

bucket_is_shut_down(BucketUUID) ->
    KVNodes = ns_cluster_membership:service_active_nodes(kv),
    case misc:rpc_multicall_with_plist_result(
           KVNodes, ?MODULE, do_get_active_bucket_uuids, [],
           ?GET_ACTIVE_BUCKET_UUIDS_TIMEOUT) of
        {Good, [], []} ->
            case [N || {N, UUIDs} <- Good, lists:member(BucketUUID, UUIDs)] of
                [] ->
                    ok;
                NodesWithBucket ->
                    ?log_debug("Bucket with uuid = ~p is still active on ~p",
                               [BucketUUID, NodesWithBucket]),
                    false
            end;
        {_, BadResults, FailedNodes} ->
            %% We cannot tell if the bucket is still open on the nodes we
            %% failed to reach, so give up and let the janitor retry.
            {error, {failed_nodes,
                     BadResults ++ [{N, node_was_down} || N <- FailedNodes]}}
    end.

-spec do_get_active_bucket_uuids() -> [binary()].
do_get_active_bucket_uuids() ->
    [UUID || {_BucketName, UUID} <-
                 ns_memcached:get_active_buckets_with_uuids()].

pre_delete_data(Namespace) ->
    [_, BucketUUID] = binary:split(Namespace, [<<"/">>]),
    case ns_bucket:uuid2bucket(BucketUUID) of
        {ok, BucketName} ->
            ?log_info("Waiting for bucket ~p uploaders to stop",
                      [BucketName]),
            case wait_for_uploaders_to_stop(BucketName) of
                {error, Err} ->
                    ?log_error("Error waiting for uploaders for bucket "
                               "~p to stop: ~p", [BucketName, Err]),
                    error;
                ok ->
                    {ok, lists:flatten(io_lib:format("~p for bucket ~p",
                                                     [Namespace, BucketName]))}
            end;
        {error, not_found} ->
            ?log_info("Bucket with uuid = ~p is not found. Waiting for it to "
                      "be shut down on all kv nodes.", [BucketUUID]),
            case wait_for_bucket_shutdown(BucketUUID) of
                {error, Err} ->
                    ?log_error("Error waiting for bucket with uuid = ~p to be "
                               "shut down: ~p", [BucketUUID, Err]),
                    error;
                ok ->
                    {ok, lists:flatten(io_lib:format("~p", [Namespace]))}
            end
    end.

delete_data(Parent, Namespace) ->
    ?log_info("Attempt to delete namespace ~p.", [Namespace]),
    RV =
        case pre_delete_data(Namespace) of
            {ok, NamespaceString} ->
                ?log_info("Start deleting namespace ~s", [NamespaceString]),
                case ns_cluster_membership:execute_on_kv_node(
                       ?MODULE, do_delete_namespace, [Namespace],
                       ?DELETE_NAMESPACE_TIMEOUT,
                       "delete namespace", delete_namespace_failed) of
                    {ok, ok} ->
                        ?log_info("Namespace ~s deleted succesfully",
                                  [NamespaceString]),
                        ok;
                    Error ->
                        ?log_error("Error deleting namespace ~s: ~p",
                                   [NamespaceString, Error]),
                        error
                end;
            error ->
                error
        end,
    Parent ! {delete_finished, Namespace, RV}.

-spec do_delete_namespace(binary()) -> ok | mc_error().
do_delete_namespace(Namespace) ->
    chronicle_compat:pull(),
    ns_memcached:delete_fusion_namespace(
      fusion_uploaders:get_log_store_uri(),
      fusion_uploaders:get_metadata_store_uri(), Namespace).
