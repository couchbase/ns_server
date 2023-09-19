%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(supervisor_tests).

-include("ns_common.hrl").

-include_lib("eunit/include/eunit.hrl").

-export([init/1]).
-export([crashing_child_link/0]).
-export([wait/0]).

-define(MAX_R, 2).
-define(MAX_T, 100).
-define(CRASHING_CHILD_NAME, crashing_child).
-define(MAX_R_RESTART_DELAY_SECONDS, 2).

supervisor_test_setup({Supervisor, ChildSpecs}) ->
    {ok, SupPid} = Supervisor:start_link(supervisor_tests, ChildSpecs),
    SupPid.

supervisor_test_teardown(_Test, SupervisorPid) ->
    erlang:process_flag(trap_exit, true),
    misc:terminate_and_wait(SupervisorPid, shutdown),
    erlang:process_flag(trap_exit, false).

%% In some cases we do not want to hit max_restart_intensity errors, we want
%% the supervisor to handle it. This test asserts that we do not crash the
%% supervisor
max_restart_intensity_t() ->
    TimeStart = erlang:monotonic_time(millisecond),

    lists:foreach(
      fun(_X) ->
              %% Make sure the process is up before we try to stop it
              ?assertEqual(ok, misc:wait_for_local_name(?CRASHING_CHILD_NAME,
                                                        10000)),

              ChildPid = erlang:whereis(?CRASHING_CHILD_NAME),
              ChildPid ! die,
              ?assertEqual(ok, misc:wait_for_process(ChildPid, infinity))

      end,
      %% Restart more than MAX_R times
      lists:seq(0, ?MAX_R)
     ),

    %% We should have restarted again.
    ?assertEqual(ok, misc:wait_for_local_name(?CRASHING_CHILD_NAME, 10000)),

    %% The test should have taken longer than the MaxR Restart delay too.
    %% Anecdotally with MaxR - 1 restarts this takes ~400ms (and fails) on my
    %% M1 Macbook Pro. With MaxR restarts this takes ~2.4seconds.
    TimeEnd = erlang:monotonic_time(millisecond),
    MinDuration = erlang:convert_time_unit(?MAX_R_RESTART_DELAY_SECONDS,
                                           second,
                                           millisecond),

    %% Eunit quite horribly expects the return of this function to be some
    %% sort of tuple (because we are calling from a test generator).
    %% The horrible part is the cryptic runtime error it returns, it's as below:
    %%        *** test module not found ***
    %%     **ok
    %%
    %% _assert macros are supposed to deal with this for us, but we can't use
    %% them everywhere otherwise we construct terms that we don't use and
    %% fail compilation, only if it's the return result of a test that has
    %% been generated.
    ?_assert(TimeEnd - TimeStart > MinDuration).

%% Used by max_restart_intensity_t to startup the supervisor under test
init(ChildSpecs) ->
    {ok,
     {{one_for_one, ?MAX_R, ?MAX_T},
      ChildSpecs}}.

wait() ->
    erlang:register(?CRASHING_CHILD_NAME, self()),
    receive
        X -> erlang:exit(X)
    end.

crashing_child_link() ->
    Pid = spawn_link(fun wait/0),
    {ok, Pid}.

supervisor2_crashing_child_spec() ->
    {?CRASHING_CHILD_NAME,
      {supervisor_tests, crashing_child_link, []},
      {permanent, ?MAX_R_RESTART_DELAY_SECONDS},
      infinity, worker, []}.

max_restart_intensity_test_() ->
    Tests =
        [{"supervisor2, supervisor2 spec",
          {supervisor2, [supervisor2_crashing_child_spec()]}}],

    {foreachx,
        fun supervisor_test_setup/1,
        fun supervisor_test_teardown/2,
        [{Test, fun (_T, _R) ->
                        {Name, timeout, 100, max_restart_intensity_t()}
                end} || {Name, Test} <- Tests]}.

restartable_spec() ->
    restartable:spec(
      {?CRASHING_CHILD_NAME,
       {supervisor_tests, crashing_child_link, []},
       permanent, infinity, worker, []}).

restartable_via_name_t({_Supervisor, _ChildSpec}, SupPid) ->
    ChildPid1 = whereis(?CRASHING_CHILD_NAME),

    {ok, _} = restartable:restart(SupPid, ?CRASHING_CHILD_NAME),

    ok = misc:wait_for_local_name(?CRASHING_CHILD_NAME, 10000),

    ChildPid2 = whereis(?CRASHING_CHILD_NAME),
    ?_assertNotEqual(ChildPid1, ChildPid2).

restartable_via_name_test_() ->
    Tests =
        [{"supervisor, restartable spec",
            {supervisor, [restartable_spec()]}}],

    {foreachx,
        fun supervisor_test_setup/1,
        fun supervisor_test_teardown/2,
        [{Test, fun (T, R) ->
            {Name, timeout, 100, restartable_via_name_t(T, R)}
                end} || {Name, Test} <- Tests]}.

restartable_via_pid_t({Supervisor, _ChildSpec}, SupPid) ->
    ChildPid1 = whereis(?CRASHING_CHILD_NAME),

    [{?CRASHING_CHILD_NAME, RestartablePid, _, _}] =
        Supervisor:which_children(SupPid),
    {ok, _} = restartable:restart(RestartablePid),

    ChildPid2 = whereis(?CRASHING_CHILD_NAME),
    ?_assertNotEqual(ChildPid1, ChildPid2).

restartable_via_pid_test_() ->
    Tests =
        [{"supervisor, restartable spec",
            {supervisor, [restartable_spec()]}}],

    {foreachx,
        fun supervisor_test_setup/1,
        fun supervisor_test_teardown/2,
        [{Test, fun (T, R) ->
            {Name, timeout, 100, restartable_via_pid_t(T, R)}
                end} || {Name, Test} <- Tests]}.
