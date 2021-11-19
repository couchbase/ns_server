%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included
%% in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
%% in that file, in accordance with the Business Source License, use of this
%% software will be governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.

-module(leader_registry_tests).

-include_lib("eunit/include/eunit.hrl").

setup() ->
    {ok, _} = gen_event:start_link({local, leader_events}),
    {ok, _} = leader_registry:start_link().

cleanup(_) ->
    misc:unlink_terminate_and_wait(whereis(leader_registry), shutdown),
    misc:unlink_terminate_and_wait(whereis(leader_events), shutdown).

basic_test_() ->
    {spawn,
     {setup, fun setup/0, fun cleanup/1, fun basic_test__/0}}.

basic_test__() ->
    Parent = self(),
    Wait = fun R() -> receive Msg -> Parent ! {self(), Msg}, R() end end,

    A = spawn_link(Wait),
    B = spawn_link(Wait),

    undefined = leader_registry:whereis_name(a),
    undefined = leader_registry:whereis_name(b),

    ?assertExit(not_a_leader, leader_registry:register_name(a, A)),

    gen_event:sync_notify(leader_events, {new_leader, node()}),

    yes = leader_registry:register_name(a, A),
    A = leader_registry:whereis_name(a),

    ?assertExit({duplicate_name, _, _, _}, leader_registry:register_name(a, B)),

    yes = leader_registry:register_name(b, B),
    B = leader_registry:whereis_name(b),

    leader_registry:send(a, test),
    receive
        {A, test} ->
            ok
    after
        1000 ->
            exit(no_message_received)
    end,

    ?assertExit({badarg, _}, leader_registry:send(c, test)),

    misc:unlink_terminate_and_wait(A, shutdown),
    wait_not_registered(a),

    gen_event:sync_notify(leader_events, {new_leader, undefined}),
    %% make sure leader_registry has processed the notification
    _ = sys:get_state(leader_registry),
    undefined = leader_registry:whereis_name(b),

    misc:unlink_terminate_and_wait(B, shutdown).

wait_not_registered(Name) ->
    wait_not_registered(Name, 1000).

wait_not_registered(Name, TimeLeft) ->
    case leader_registry:whereis_name(Name) of
        undefined ->
            ok;
        Pid when is_pid(Pid) andalso TimeLeft > 0 ->
            timer:sleep(1),
            wait_not_registered(Name, TimeLeft - 1);
        Pid when is_pid(Pid) ->
            exit({name_still_registered, Name, Pid})
    end.
