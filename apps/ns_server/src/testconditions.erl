%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

-module(testconditions).

-include("ns_common.hrl").

-define(TESTCONDITION_STORE, testconditions).

%% APIs
-export([get/1,
         set/2,
         delete/1,
         clear/0,
         list/0,
         check_test_condition/1,
         check_test_condition/2,
         check_test_condition/3,
         check_test_condition/4,
         check_test_condition/5,
         trigger_failure/3,
         trigger_delay/4]).

get(Key) ->
    simple_store:get(?TESTCONDITION_STORE, Key).

%% TODO: No need to persist the testconditions.
%% Add function for non-persistent set() in simple_store.
set(Key, Value) ->
    simple_store:set(?TESTCONDITION_STORE, Key, Value).

delete(Key) ->
    simple_store:delete(?TESTCONDITION_STORE, Key).

clear() ->
    simple_store:clear(?TESTCONDITION_STORE).

list() ->
    {ok, List} = simple_store:list(?TESTCONDITION_STORE),
    List.

%%
%% Generic test condition handling:
%%
%% There are 2 types of generically handled test conditions:
%%  1. Applicable to a specific "step"
%%  2. Applicable to a specific "kind" of "step". "Kind" can be used as a
%%     sub-tag for "step" for things like rebalance to inject a failure for a
%%     specific bucket.
%%
%% There are two types of generically handled failures:
%%  1. Fail
%%  2. Delay. A delay can be used to inject other failures. E.g. Introduce a
%%     delay of 60s during rebalance of a bucket. During those 60s, user can
%%     SIGSTOP memcached on a node.
%%
%% An ExtendedHandler can be passed to allow custom handling of additional
%% conditions or failure types.
-spec check_test_condition(term()) -> term().
check_test_condition(Step) ->
    check_test_condition(?NS_SERVER_LOGGER, Step, [], undefined).

-spec check_test_condition(atom(), term()) -> term().
check_test_condition(Logger, Step) ->
    check_test_condition(Logger, Step, [], undefined).

-spec check_test_condition(atom(), term(), term()) -> term().
check_test_condition(Logger, Step, Kind) ->
    check_test_condition(Logger, Step, Kind, undefined).

-spec check_test_condition(atom(), term(), term(),
                           undefined | fun((term()) -> term())) -> term().
check_test_condition(Logger, Step, Kind, ExtendedHandler) ->
    check_test_condition(Logger, Step, Kind, ExtendedHandler, [{once, true}]).

-spec check_test_condition(
        atom(), term(), term(),
        undefined | fun((term()) -> term()), list()) -> term().
check_test_condition(Logger, Step, Kind, ExtendedHandler, Options) ->
    case testconditions:get(Step) of
        fail ->
            %% E.g. fail rebalance at the start.
            %% Triggered by: testconditions:set(rebalance_start, fail)
            trigger_failure(Logger, Step, [], Options);
        {delay, Sleep} ->
            %% E.g. delay rebalance by 60s at the start.
            %% Triggered by:
            %%  testconditions:set(rebalance_start, {delay, 60000})
            trigger_delay(Logger, Step, [], Options, Sleep);
        {return, Value} ->
            %% E.g. return a timeout for bucket shutdown wait.
            %% Triggered by:
            %% testconditions:set(wait_for_bucket_shutdown,
            %%                    {return, {shutdown_failed, [foo]}})
            trigger_return(Logger, Step, [], Options, Value);
        {fail, Kind} ->
            %% E.g. fail verify_replication for bucket "test".
            %% Triggered by:
            %%  testconditions:set(verify_replication, {fail, “test”})
            trigger_failure(Logger, Step, Kind, Options);
        {delay, Kind, Sleep} ->
            %% E.g. delay service_rebalance_start by 1s for index service.
            %% Triggered by:
            %%  testconditions:set(service_rebalance_start,
            %%                     {delay, index, 1000})
            trigger_delay(Logger, Step, Kind, Options, Sleep);
        {return, Kind, Value} ->
            %% E.g. return a timeout for bucket shutdown wait.
            %% Triggered by:
            %% testconditions:set({wait_for_bucket_shutdown, \"bucket-1\"},
            %%                    {return, {shutdown_failed, [foo]}})
            trigger_return(Logger, Step, Kind, Options, Value);
        Condition ->
            case ExtendedHandler of
                undefined -> ok;
                _ -> ExtendedHandler(Condition)
            end
    end.

maybe_delete(Step, Options) ->
    case proplists:get_bool(once, Options) of
        true ->
            testconditions:delete(Step);
        false ->
            ok
    end.

trigger_failure(Logger, Step, Kind) ->
    trigger_failure(Logger, Step, Kind, [{once, true}]).

trigger_failure(Logger, Step, Kind, Options) ->
    Msg = case Kind of
              [] ->
                  io_lib:format("Failure triggered by test during ~p", [Step]);
              _ ->
                  io_lib:format("Failure triggered by test during ~p for ~p",
                      [Step, Kind])
          end,
    ale:error(Logger, "~s", [lists:flatten(Msg)]),
    maybe_delete(Step, Options),
    fail_by_test_condition.

trigger_delay(Logger, Step, Kind, Sleep) ->
    trigger_delay(Logger, Step, Kind, [{once, true}], Sleep).

trigger_delay(Logger, Step, Kind, Options, Sleep) ->
    Msg = case Kind of
              [] ->
                  io_lib:format("Delay triggered by test during ~p. "
                  "Sleeping for ~p ms", [Step, Sleep]);
              _ ->
                  io_lib:format("Delay triggered by test during ~p for ~p. "
                  "Sleeping for ~p ms", [Step, Kind, Sleep])
          end,
    ale:error(Logger, "~s", [lists:flatten(Msg)]),

    maybe_delete(Step, Options),
    timer:sleep(Sleep).

trigger_return(Logger, Step, Kind, Options, Value) ->
    Msg = case Kind of
              [] ->
                  io_lib:format("Returning value ~p during ~p", [Value, Step]);
              _ ->
                  io_lib:format("Returning value ~p during ~p for ~p",
                      [Value, Step, Kind])
          end,
    ale:error(Logger, "~s", [lists:flatten(Msg)]),
    maybe_delete(Step, Options),
    Value.
