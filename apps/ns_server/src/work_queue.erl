%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(work_queue).

-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1, start_link/2,
         submit_work/2, submit_sync_work/2, sync_work/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% A plain constant rather than ?get_param: cb_atomic_persistent_term is a
%% work_queue and starts before ns_config_sup, so reading config here would
%% crash on the missing ns_config_ets_dup table.
-define(HIBERNATE_AFTER, 10000).

start_link() ->
    start_link(fun nothing/0).

start_link(Name) when is_atom(Name) orelse is_tuple(Name) ->
    start_link(Name, fun nothing/0);
start_link(InitFun) when is_function(InitFun) ->
    gen_server:start_link(?MODULE, InitFun, opts()).

start_link(Name, InitFun) when is_atom(Name) ->
    start_link({local, Name}, InitFun);
start_link(Name, InitFun) when is_tuple(Name) ->
    gen_server:start_link(Name, ?MODULE, InitFun, opts()).

opts() ->
    [{hibernate_after, ?HIBERNATE_AFTER}].

submit_work(Name, Fun) ->
    gen_server:cast(Name, Fun).

submit_sync_work(Name, Fun) ->
    gen_server:call(Name, Fun, infinity).

sync_work(Name) ->
    gen_server:call(Name, fun nothing/0).

nothing() -> [].

init(InitFun) ->
    %% submit_work/2 is an unacknowledged cast of a closure, which can capture
    %% arbitrarily large terms, so the mailbox can both grow long and hold big
    %% messages. Keep it off the heap so GC doesn't have to walk it (MB-72708).
    process_flag(message_queue_data, off_heap),
    InitFun(),
    {ok, []}.

handle_call(Fun, _From, State) ->
    RV = Fun(),
    {reply, RV, State}.

handle_cast(Fun, State) ->
    Fun(),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
