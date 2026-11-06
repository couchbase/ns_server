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
-include_lib("ns_common/include/cut.hrl").

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
lookup_value_with_expiration(Key, InvalidPred, AsOf) ->
    case ets:lookup(?MODULE, Key) of
        [{_, Value, _, _, BuildStart}] when BuildStart > AsOf ->
            %% Built from inputs read after the caller arrived, so skip the
            %% predicate, as the payload is new enough to serve.
            %% N.B. This works under the assumption that the predicate is
            %% just trying to ensure freshness, and is not particularly robust.
            {ok, Value};
        [{_, Value, Expiration, InvalidationState, _}]
          when AsOf =< Expiration ->
            case InvalidPred(Key, Value, InvalidationState) of
                true ->
                    {not_found, AsOf};
                _ ->
                    {ok, Value}
            end;
        _ ->
            {not_found, AsOf}
    end.

%% InvalidPred must only judge freshness, as entries built after the caller
%% arrived are served without consulting it.
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
        {not_found, LookupTime} ->
            BuildStart = erlang:monotonic_time(millisecond),
            case ComputeBody() of
                {error, _} = Error ->
                    Error;
                {Value, Age, InvalidationState} ->
                    %% If this is already expired then set the expiry time to
                    %% now, rather than lookup + age. This means that anything
                    %% waiting for this payload (in the message queue) can
                    %% serve it instead of recomputing it.
                    Expiration =
                        case LookupTime + Age =< BuildStart of
                            true -> erlang:monotonic_time(millisecond);
                            false -> LookupTime + Age
                        end,

                    ns_server_stats:notify_counter(<<"web_cache_updates">>),
                    ets:insert(?MODULE, {Key, Value, Expiration,
                                         InvalidationState, BuildStart}),
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
                 fun ({Key, _, Expiration, _, _}, Acc) when Now > Expiration ->
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
      {"valid as of arrival test", fun valid_as_of_arrival_is_served_t/0},
      {"slow compute serve queue test",
       fun slow_compute_serves_queued_arrival_t/0},
      {"churn coalesce test",
       {timeout, 30, fun churn_queued_callers_share_build_t/0}},
      {"update id: later build served",
       {timeout, 30, fun update_id_later_build_served_t/0}},
      {"update id: earlier build rebuilt",
       {timeout, 30, fun update_id_earlier_build_rebuilt_t/0}}
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

%% When ComputeBody outlives the value's Age, the stored expiry is clamped to
%% the compute-finish time rather than LookupTime + Age. A request that queued
%% behind the slow compute is served the fresh value instead of recomputing.
%% An Age of 0 makes the value expired the instant it is computed, so the
%% clamp always applies and there is no timing to race on
slow_compute_serves_queued_arrival_t() ->
    IP = never_invalid(),
    Parent = self(),
    %% R1 blocks mid-compute until the test releases it, holding the
    %% work_queue so R2 must queue behind it. self() here is the
    %% work_queue process, which runs the ComputeBody
    SlowBody = fun () ->
                       Parent ! {computing, self()},
                       receive proceed -> ok end,
                       {v1, 0, undefined}
               end,
    spawn_link(fun () ->
                       R = lookup_or_compute_with_expiration(
                             ?TEST_KEY, SlowBody, IP),
                       Parent ! {r1, R}
               end),
    ComputePid = receive {computing, P} -> P
                 after 5000 -> erlang:error(compute_never_started)
                 end,
    %% R2 arrives while R1 is still computing, its request lands in
    %% the work_queue mailbox behind R1's in-flight work
    spawn_link(fun () ->
                       R = lookup_or_compute_with_expiration(
                             ?TEST_KEY, compute_body(v2, 60000),
                             IP),
                       Parent ! {r2, R}
               end),
    %% Release R1. Age 0 clamps the expiry to R1's compute-finish
    %% time, at or after R2's arrival, so R2 is served from cache
    ComputePid ! proceed,
    R1 = receive {r1, V1} -> V1
         after 10000 -> erlang:error(r1_timeout)
         end,
    R2 = receive {r2, V2} -> V2
         after 10000 -> erlang:error(r2_timeout)
         end,
    ?assertEqual(v1, R1),
    %% R2 is served R1's value, its ComputeBody never runs
    ?assertEqual(v1, R2),
    ?assertEqual(1, count(<<"web_cache_updates">>)).

%% Callers queued before a build started are served it, although the config
%% version moved during the build, so two queued callers cost one build
churn_queued_callers_share_build_t() ->
    Counter = counters:new(2, []),
    ConfigVersion = fun () -> counters:get(Counter, 1) end,
    %% Each build moves the config version, so its own result fails the
    %% predicate
    Body = fun () ->
                   counters:add(Counter, 2, 1),
                   Vsn = ConfigVersion(),
                   counters:add(Counter, 1, 1),
                   {v, 60000, Vsn}
           end,
    IP = fun (_, _, Vsn) -> Vsn =/= ConfigVersion() end,
    Parent = self(),
    spawn_link(fun () ->
                       work_queue:submit_sync_work(
                         ?MODULE,
                         fun () ->
                                 Parent ! {queue_blocked, self()},
                                 receive proceed -> ok end
                         end)
               end),
    CachePid = receive {queue_blocked, P} -> P
               after 5000 -> erlang:error(not_blocked)
               end,
    N = 2,
    lists:foreach(
      fun (_) ->
              spawn_link(fun () ->
                                 Parent ! {done,
                                           lookup_or_compute_with_expiration(
                                             ?TEST_KEY, Body, IP)}
                         end)
      end, lists:seq(1, N)),
    wait_for_queue_len(CachePid, N),
    %% Start the build after the callers' arrival millisecond, as a tie does
    %% not postdate them
    timer:sleep(1),
    CachePid ! proceed,
    lists:foreach(
      fun (_) ->
              receive {done, v} -> ok
              after 10000 -> erlang:error(timeout)
              end
      end, lists:seq(1, N)),
    ?assertEqual(1, counters:get(Counter, 2)).

wait_for_queue_len(Pid, N) ->
    case erlang:process_info(Pid, message_queue_len) of
        {message_queue_len, Len} when Len >= N ->
            ok;
        _ ->
            timer:sleep(1),
            wait_for_queue_len(Pid, N)
    end.

%% poolsStreaming tags each pool_details entry with the UpdateID of the caller
%% that built it, and a caller holding an UpdateID treats a differently tagged
%% entry as invalid. These two tests use
%% the same rule. State stands in for the config: event 2 sets it to 2 before
%% the caller holding UpdateID 2 arrives.
update_id_pred(CallerUpdateID) ->
    fun (_Key, _Value, {OldUpdateID}) ->
            CallerUpdateID =/= OldUpdateID andalso CallerUpdateID =/= undefined
    end.

update_id_body(Who, State, UpdateID) ->
    fun () -> {{Who, counters:get(State, 1)}, 60000, {UpdateID}} end.

%% A build that started after the caller arrived read State after event 2,
%% so the caller is served it although it carries another caller's UpdateID.
update_id_later_build_served_t() ->
    State = counters:new(1, []),
    counters:put(State, 1, 1),
    Parent = self(),
    spawn_link(fun () ->
                       work_queue:submit_sync_work(
                         ?MODULE,
                         fun () ->
                                 Parent ! {queue_blocked, self()},
                                 receive proceed -> ok end
                         end)
               end),
    CachePid = receive {queue_blocked, P} -> P
               after 5000 -> erlang:error(not_blocked)
               end,
    %% Y (UpdateID 1) queues first, its build will start after X arrives
    spawn_link(fun () ->
                       Parent ! {y, lookup_or_compute_with_expiration(
                                      ?TEST_KEY, update_id_body(y, State, 1),
                                      update_id_pred(1))}
               end),
    wait_for_queue_len(CachePid, 1),
    counters:put(State, 1, 2),
    spawn_link(fun () ->
                       Parent ! {x, lookup_or_compute_with_expiration(
                                      ?TEST_KEY, update_id_body(x, State, 2),
                                      update_id_pred(2))}
               end),
    wait_for_queue_len(CachePid, 2),
    %% Start the build after X's arrival millisecond, as above
    timer:sleep(1),
    CachePid ! proceed,
    ?assertEqual({y, 2}, receive {x, VX} -> VX after 5000 -> timeout end),
    ?assertEqual({y, 2}, receive {y, VY} -> VY after 5000 -> timeout end),
    ?assertEqual(1, count(<<"web_cache_updates">>)).

%% A build already under way when the caller arrived may have read State
%% before event 2: the caller must not be served it, and rebuilds.
update_id_earlier_build_rebuilt_t() ->
    State = counters:new(1, []),
    counters:put(State, 1, 1),
    Parent = self(),
    SlowY = fun () ->
                    V = counters:get(State, 1),
                    Parent ! y_read_state,
                    timer:sleep(300),
                    {{y, V}, 60000, {1}}
            end,
    spawn_link(fun () ->
                       Parent ! {y, lookup_or_compute_with_expiration(
                                      ?TEST_KEY, SlowY, update_id_pred(1))}
               end),
    receive y_read_state -> ok after 5000 -> erlang:error(no_build) end,
    counters:put(State, 1, 2),
    ?assertEqual({x, 2},
                 lookup_or_compute_with_expiration(
                   ?TEST_KEY, update_id_body(x, State, 2), update_id_pred(2))),
    ?assertEqual({y, 1}, receive {y, V} -> V after 5000 -> timeout end),
    ?assertEqual(2, count(<<"web_cache_updates">>)).

-endif.
