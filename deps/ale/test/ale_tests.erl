%% @author Couchbase <info@couchbase.com>
%% @copyright 2011-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(ale_tests).

-compile(nowarn_export_all).
-compile(export_all).
-compile({parse_transform, ale_transform}).

-include("ale.hrl").

-include_lib("eunit/include/eunit.hrl").

prepare() ->
    application:start(ale),

    ok = ale:start_sink(stderr, ale_stderr_sink, []),
    ok = ale:start_sink(disk, ale_disk_sink, ["/tmp/test_log"]),

    ok = ale:add_sink(?ERROR_LOGGER, disk, info),
    ok = ale:add_sink(?ALE_LOGGER, stderr, info),

    ok = ale:start_logger(info),
    ok = ale:start_logger(test),

    ok = ale:add_sink(info, stderr),
    ok = ale:add_sink(info, disk),
    ok = ale:add_sink(test, stderr).

test() ->
    Fn = fun () -> io:format("test local~n") end,
    RemoteSusp = ale:delay(io:format("test remote~n")),

    ale:debug(info,    "test message: ~p", [RemoteSusp]),
    ale:info(info,     "test message: ~p", [Fn()]),
    ale:warn(info,     "test message: ~p", [Fn()]),
    ale:error(info,    "test message: ~p", [RemoteSusp]),
    ale:critical(info, "test message: ~p", [test]),

    ale:xcritical(info, user_data_goes_here,
                  "test message (with user data): ~p", [test]),

    Error = error,
    Info = info,
    GetError = fun () -> error end,
    GetInfo = fun () -> info end,
    ale:log(Info, Error, "dynamic message test: ~p", [test]),
    ale:log(info, Error, "dynamic but known logger: ~p", [test]),
    ale:log(info, GetError(), "dynamic message (fn level): ~p", [test]),
    ale:log(Info, GetError(), "dynamic message (fn level) 2: ~p", [test]),
    ale:log(GetInfo(), GetError(),
            "dynamic message (fn both level and logger: ~p)", [test]),

    ale:xinfo(info, user_data, "test message: ~p", [Fn()]),
    ale:xerror(info, user_data, "test message: ~p", [Fn()]),

    ale:xlog(GetInfo(), error, user_data, "test message: ~p", [test]),
    ale:xlog(info, GetError(), user_data, "test message: ~p", [test]),
    ale:xlog(GetInfo(), GetError(), user_data, "test message: ~p", [test]),

    {error, {badarg, _}} = ale:start_logger(bad_logger, slkdfjlksdj),
    {error, badarg} = ale:set_loglevel(info, lsdkjflsdkj),
    {error, badarg} = ale:set_sync_loglevel(info, lksjdflkjs),
    {error, badarg} = ale:set_sink_loglevel(info, disk, lsdkjflksjd),
    {error, badarg} = ale:add_sink(?ALE_LOGGER, disk, lskdjflksdj),

    ok.

test_perf_loop(0) ->
    ok;
test_perf_loop(Times) ->
    ale:debug(ns_info, "test message: ~p", [test]),
    test_perf_loop(Times - 1).

test_perf() ->
    {Time, _} = timer:tc(fun test_perf_loop/1, [1000000]),
    io:format("Time spent: ~ps~n", [Time div 1000000]).

test_ale_codegen() ->
    ok = ale:start_sink(stderr_dummy, ale_stderr_sink, []),
    ok = ale:start_logger(info),
    ok = ale:add_sink(info, stderr_dummy),

    ale:warn(info, "test msg: ~p", ["hello"], [{chars_limit, 1000}]),
    ale:xwarn(info, user_data, "test msg: ~p", ["hello"], [{chars_limit, 1000}]),
    ok.

test_ale_codegen_test() ->
    ?assertEqual(ok, test_ale_codegen()).

%% ale_sup is one_for_all, so a crash of any of its children restarts ale.
%% ale used to be unable to survive that: init/1 removes the
%% ?ERROR_LOGGER/?TRACE_LOGGER handlers left behind by the previous
%% incarnation, which makes logger cast {removing_handler, _} back to ale, and
%% handling that cast after init/1 had already reinstalled the handlers killed
%% it with {error, {already_exist, _}}. ale_sup then exceeded its restart
%% intensity within milliseconds and took the whole ale application down.
%%
%% Runs on a peer node. It can't use the ale of the node running the tests:
%% under the ns_server suite that is the one t.erl:fake_loggers/0 sets up, and
%% restarting ale_sup takes its sinks down with it, leaving every logger
%% compiled against them failing with noproc for the rest of the run.
restart_test_() ->
    {setup, fun start_ale_peer/0, fun stop_ale_peer/1,
     fun (Peer) ->
             {"ale survives a restart",
              fun () ->
                      %% under eunit's default 5s per-test timeout, so that a
                      %% hung peer is reported as a failure
                      on_peer(Peer, assert_survives_restart, [], 4000)
              end}
     end}.

assert_survives_restart() ->
    OldPid = whereis(ale),
    exit(OldPid, kill),
    ?assert(wait_until(fun () -> is_pid(whereis(ale)) andalso
                                     whereis(ale) =/= OldPid end, 20)),

    %% The crash this guards against hits the new ale only once it gets round
    %% to the {removing_handler, _} casts, so give it time before checking
    %% that it is still the same process.
    NewPid = whereis(ale),
    timer:sleep(500),
    ?assertEqual(NewPid, whereis(ale)),
    assert_handlers_intact().

%% logger removes a handler whenever that handler's log/2 raises, from
%% whatever process happened to be logging, and anybody can call
%% logger:remove_handler/1. ale has to put the handler back, and do it only
%% by adding it: removing one of ours itself could race with logger removing
%% the other one, and logger's removals of different handlers aren't safe
%% against each other.
removed_handler_test_() ->
    {foreach, fun start_ale/0, fun stop_ale/1,
     [{"a removed " ++ atom_to_list(Logger) ++ " is put back",
       fun () -> assert_reinstalled(Logger) end}
      || Logger <- [?ERROR_LOGGER, ?TRACE_LOGGER]]}.

assert_reinstalled(Logger) ->
    Ale = whereis(ale),
    Watch = watch_handler_changes(),
    ok = logger:remove_handler(Logger),
    %% rather than wait for ale's next periodic check
    Ale ! periodic_check_logger_handlers,
    Reinstalled = wait_until(fun () -> handler_is_ale(Logger) end, 20),
    %% give ale time to do anything more it might do about it
    timer:sleep(300),
    Changes = handler_changes(Watch),

    ?assert(Reinstalled),
    ?assertEqual(Ale, whereis(ale)),
    ?assertEqual([{remove_handler, Logger}, {add_handler, Logger}], Changes),
    assert_handlers_intact().

%% Runs ?MODULE:Fun(Args...) on Peer, failing the test unless it returns ok.
on_peer(Peer, Fun, Args, Timeout) ->
    ?assertEqual(ok, peer:call(Peer, ?MODULE, Fun, Args, Timeout)).

start_ale_peer() ->
    %% standard_io rather than distribution: works whether or not the node
    %% running the tests is distributed, and needs no node name
    {ok, Peer, _Node} = peer:start_link(#{connection => standard_io,
                                          wait_boot => 30000}),
    true = peer:call(Peer, code, set_path, [code:get_path()]),
    {ok, _} = peer:call(Peer, application, ensure_all_started, [ale]),
    Peer.

stop_ale_peer(Peer) ->
    peer:stop(Peer).

start_ale() ->
    {ok, Started} = application:ensure_all_started(ale),
    Started.

stop_ale([]) ->
    %% ale was already running when we got here -- the test harness
    %% (t.erl:fake_loggers/0) starts it, with sinks the rest of the suite logs
    %% through. Not ours to tear down.
    ok;
stop_ale(Started) ->
    lists:foreach(fun application:stop/1, lists:reverse(Started)),
    _ = logger:remove_handler(?ERROR_LOGGER),
    _ = logger:remove_handler(?TRACE_LOGGER),
    ok.

%% Both of our handlers are installed, and each is listed once: logger calls a
%% handler once for every time it is listed.
assert_handlers_intact() ->
    lists:foreach(
      fun (Logger) ->
              ?assert(handler_is_ale(Logger)),
              ?assertEqual({Logger, 1}, {Logger, times_listed(Logger)})
      end, [?ERROR_LOGGER, ?TRACE_LOGGER]),
    ok.

times_listed(Logger) ->
    length([Id || Id <- logger:get_handler_ids(), Id =:= Logger]).

handler_is_ale(Logger) ->
    lists:member(Logger, logger:get_handler_ids()) andalso
        case logger:get_handler_config(Logger) of
            {ok, #{module := ale}} ->
                true;
            _ ->
                false
        end.

%% Starts collecting the requests logger_server gets to add or remove one of
%% our handlers, whoever they come from. handler_changes/1 stops it and
%% returns them.
watch_handler_changes() ->
    Self = self(),
    Ref = make_ref(),
    Watch = fun (FuncState, {in, {'$gen_call', _, Request}}, _)
                  when element(1, Request) =:= add_handler;
                       element(1, Request) =:= remove_handler ->
                    case lists:member(element(2, Request),
                                      [?ERROR_LOGGER, ?TRACE_LOGGER]) of
                        true ->
                            Self ! {Ref, {element(1, Request),
                                          element(2, Request)}};
                        false ->
                            ok
                    end,
                    FuncState;
                (FuncState, _Event, _) ->
                    FuncState
            end,
    ok = sys:install(logger, {Watch, ok}),
    {Ref, Watch}.

handler_changes({Ref, Watch}) ->
    ok = sys:remove(logger, Watch),
    collect_handler_changes(Ref, []).

collect_handler_changes(Ref, Acc) ->
    receive
        {Ref, Change} ->
            collect_handler_changes(Ref, [Change | Acc])
    after
        0 ->
            lists:reverse(Acc)
    end.

wait_until(_Pred, 0) ->
    false;
wait_until(Pred, TriesLeft) ->
    case Pred() of
        true ->
            true;
        false ->
            timer:sleep(100),
            wait_until(Pred, TriesLeft - 1)
    end.
