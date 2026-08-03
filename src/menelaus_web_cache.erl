%% @author Couchbase <info@couchbase.com>
%% @copyright 2013-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc This service maintains public ETS table that's caching various
%% somewhat expensive to compute stuff used by menelaus_web*
%%
-module(menelaus_web_cache).
-include("ns_common.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0,
         get_static_value/1,
         lookup_or_compute_with_expiration/3]).

-define(CLEANUP_INTERVAL, ?get_timeout(cleanup, 600000)).

start_link() ->
    work_queue:start_link(?MODULE, fun cache_init/0).

cache_init() ->
    ets:new(?MODULE, [set, named_table]),
    VersionsPList = build_versions(),
    ets:insert(?MODULE, {versions, VersionsPList}),
    PackageVariant = read_package_variant(),
    ets:insert(?MODULE, {package_variant, PackageVariant}),
    schedule_cleanup().

implementation_version(Versions) ->
    list_to_binary(proplists:get_value(ns_server, Versions, "unknown")).

build_versions() ->
    Versions = ns_info:version(),
    [{implementationVersion, implementation_version(Versions)},
     {componentsVersion, {lists:map(fun ({K,V}) ->
                                            {K, list_to_binary(V)}
                                    end,
                                    Versions)}}].

read_package_variant() ->
    Filename = filename:join(path_config:component_path(bin, ".."),
                             "VARIANT.txt"),
    case file:read_file(Filename) of
        {ok, C} ->
            string:trim(C);
        Err ->
            ?log_error("Failed to read '~p': ~p", [Filename, Err]),
            <<"">>
    end.

get_static_value(Key) ->
    [{Key, Value}] = ets:lookup(?MODULE, Key),
    Value.

lookup_value_with_expiration(Key, InvalidPred) ->
    lookup_value_with_expiration(Key, InvalidPred,
                                 erlang:monotonic_time(millisecond)).
lookup_value_with_expiration(Key, InvalidPred, Time) ->
    case ets:lookup(?MODULE, Key) of
        [] ->
            {not_found, Time};
        [{_, Value, Expiration, InvalidationState}] ->
            case Time =< Expiration of
                true ->
                    case InvalidPred(Key, Value, InvalidationState) of
                        true ->
                            {not_found, Time};
                        _ ->
                            {ok, Value}
                    end;
                _ ->
                    {not_found, Time}
            end
    end.

lookup_or_compute_with_expiration(Key, ComputeBody, InvalidPred) ->
    case lookup_value_with_expiration(Key, InvalidPred) of
        {not_found, AsOf} ->
            compute_with_expiration(Key, ComputeBody, InvalidPred, AsOf);
        {ok, Value} ->
            ns_server_stats:notify_counter(<<"web_cache_hits">>),
            Value
    end.

compute_with_expiration(Key, ComputeBody, InvalidPred, AsOf) ->
    work_queue:submit_sync_work(
      ?MODULE,
      ?cut(do_compute_with_expiration(Key, ComputeBody, InvalidPred, AsOf))).

do_compute_with_expiration(Key, ComputeBody, InvalidPred, AsOf) ->
    case lookup_value_with_expiration(Key, InvalidPred, AsOf) of
        {not_found, _} ->
            Now = erlang:monotonic_time(millisecond),
            case ComputeBody() of
                {error, _} = Error ->
                    Error;
                {Value, Age, InvalidationState} ->
                    Expiration = Now + Age,
                    ns_server_stats:notify_counter(<<"web_cache_updates">>),
                    ets:insert(?MODULE, {Key,
                                         Value, Expiration, InvalidationState}),
                    Value
            end;
        {ok, Value} ->
            ns_server_stats:notify_counter(<<"web_cache_inner_hits">>),
            Value
    end.

schedule_cleanup() ->
    {ok, _} = timer:apply_after(?CLEANUP_INTERVAL, work_queue, submit_work,
                                [self(), fun cleanup/0]).

cleanup() ->
    Now = erlang:monotonic_time(millisecond),
    ToDelete = ets:foldl(
                 fun ({Key, _, Expiration, _}, Acc) when Now > Expiration ->
                         [Key | Acc];
                     (_, Acc) ->
                         Acc
                 end, [], ?MODULE),
    [ets:delete(?MODULE, K) || K <- ToDelete],
    schedule_cleanup().

-ifdef(TEST).

-define(TEST_KEY, test_key).

setup() ->
    fake_ns_config:setup(),

    %% This lets ns_server_stats run (minimally). It's not general purpose so
    %% doesn't belong in mock_helpers, and will be removed on merge forwards
    meck:new(mb_master, []),
    meck:expect(mb_master, master_node, fun() -> another_node end),

    PidMap = mock_helpers:setup_mocks([ns_server_stats]),

    {ok, CachePid} = start_link(),
    {CachePid, PidMap}.

teardown({CachePid, PidMap}) ->
    gen_server:stop(CachePid),
    mock_helpers:teardown(PidMap),
    meck:unload(),
    fake_ns_config:teardown().

count(Counter) ->
    case ets:lookup(ns_server_stats,
                    {c, ns_server_stats:normalized_metric(Counter)}) of
        [] -> 0;
        [{_, N}] -> N
    end.

%% Records how many times it ran under Tag and returns a fixed
%% {Value, Age, InvalidationState} triple
compute_body(Value, Age) ->
    fun () ->
            {Value, Age, undefined}
    end.

never_invalid() ->
    fun (_Key, _Value, _State) -> false end.

web_cache_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{"cold compute test", fun cold_compute_and_warm_hit_t/0},
      {"stale value test", fun stale_value_recomputed_t/0},
      {"invalid pref test", fun invalid_pred_forces_recompute_t/0},
      {"compute error test", fun compute_error_not_cached_t/0},
      {"valid as of arrival test", fun valid_as_of_arrival_is_served_t/0}
     ]}.

%% A cold read computes and stores the value, an immediate warm read reuses
%% it without recomputing.
cold_compute_and_warm_hit_t() ->
    IP = never_invalid(),
    CB = compute_body(value_v1, 60000),
    ?assertEqual(value_v1,
                 lookup_or_compute_with_expiration(?TEST_KEY, CB, IP)),
    ?assertEqual(1, count(<<"web_cache_updates">>)),
    ?assertEqual(value_v1,
                 lookup_or_compute_with_expiration(?TEST_KEY, CB, IP)),
    ?assertEqual(0, count(<<"web_cache_inner_hits">>)),
    ?assertEqual(1, count(<<"web_cache_hits">>)).

%% A value whose validity window has closed by the time the next request
%% arrives is recomputed
stale_value_recomputed_t() ->
    IP = never_invalid(),
    %% 0 => immediately expired
    ?assertEqual(v1,
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, compute_body(v1, 0), IP)),
    ?assertEqual(1, count(<<"web_cache_updates">>)),
    %% We do need a 1ms sleep unfortunately to avoid the next lookup being on
    %% the same millisecond.
    timer:sleep(1),
    ?assertEqual(v2,
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, compute_body(v2, 0), IP)),
    ?assertEqual(2, count(<<"web_cache_updates">>)).

%% An invalidation predicate reporting the entry as invalid forces a
%% recompute even when the value has not expired
invalid_pred_forces_recompute_t() ->
    ?assertEqual(v1,
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, compute_body(v1, 60000),
                   never_invalid())),
    ?assertEqual(1, count(<<"web_cache_updates">>)),
    AlwaysInvalid = fun (_, _, _) -> true end,
    ?assertEqual(v2,
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, compute_body(v2, 60000),
                   AlwaysInvalid)),
    ?assertEqual(2, count(<<"web_cache_updates">>)).

%% A ComputeBody returning {error, _} propagates the error and is not cached.
%% A later successful compute populates the cache normally
compute_error_not_cached_t() ->
    IP = never_invalid(),
    ErrBody = fun () -> {error, boom} end,
    ?assertEqual({error, boom},
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, ErrBody, IP)),
    ?assertEqual([], ets:lookup(?MODULE, ?TEST_KEY)),
    ?assertEqual(v1,
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, compute_body(v1, 60000), IP)),
    ?assertEqual(1, count(<<"web_cache_updates">>)).

%% The crux of the change: a caller that arrived while the value was valid is
%% served it even though the value has expired by the time its queue-delayed
%% inner lookup runs, and its ComputeBody never runs. Under the old
%% "now"-based check this caller would have missed and recomputed
valid_as_of_arrival_is_served_t() ->
    IP = never_invalid(),
    Age = 500,
    Block = 1500,
    %% Populate the cache with a short-lived value
    ?assertEqual(v1,
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, compute_body(v1, Age), IP)),
    %% Occupy the work_queue past the value's wall-clock expiry so a
    %% later request's inner lookup runs only after it has expired
    Parent = self(),
    spawn_link(fun () ->
                       work_queue:submit_sync_work(
                         ?MODULE,
                         fun () ->
                                 Parent ! queue_blocked,
                                 timer:sleep(Block)
                         end)
               end),
    receive queue_blocked -> ok
    after 5000 -> erlang:error(queue_never_blocked)
    end,
    %% The reader's arrival time is captured before it enters the
    %% queue and lies within the validity window, but its inner
    %% lookup only runs once the blocker releases the queue
    spawn_link(fun () ->
                       R = lookup_or_compute_with_expiration(
                             ?TEST_KEY,
                             compute_body(v2, 60000),
                             IP),
                       Parent ! {reader_result, R}
               end),
    Result = receive {reader_result, R} -> R
             after 10000 -> erlang:error(reader_timeout)
             end,
    ?assertEqual(v1, Result).

-endif.
