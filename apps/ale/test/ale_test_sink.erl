%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

%% A sink for ale_tests that supports encryption as far as ale can tell, like
%% ale_disk_sink, and answers the calls ale makes to such sinks either by
%% saying its files use InUseDeks, or, given die, by dying.
-module(ale_test_sink).

-behaviour(gen_server).

-export([start_link/2, meta/0]).

-export([init/1, handle_call/3, handle_cast/2]).

start_link(Name, Behaviour) ->
    gen_server:start_link({local, Name}, ?MODULE, Behaviour, []).

meta() ->
    [{async, true},
     {type, preformatted},
     {encryption_supported, true}].

init(Behaviour) ->
    {ok, Behaviour}.

handle_call(_Request, _From, die) ->
    {stop, died_on_call, die};
handle_call(get_in_use_deks, _From, {in_use, InUseDeks} = State) ->
    {reply, {ok, InUseDeks}, State};
handle_call(notify_active_key_updt, _From, State) ->
    {reply, ok, State};
handle_call({drop_log_deks, _DekIds, _WorkSzThresh}, _From, State) ->
    {reply, {ok, 0}, State};
handle_call(sync, _From, State) ->
    {reply, ok, State}.

handle_cast({log, _Msg}, State) ->
    {noreply, State}.
