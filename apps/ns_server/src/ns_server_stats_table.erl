%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% Owns the ETS table holding the metrics reported to prometheus.
%%
%% ns_server_stats itself cannot create it: it needs the couchdb node
%% (grab_pid_names/0 -> ns_couchdb_api:get_pid/0, which exits if that node is
%% not up), so it is started late, after wait_for_couchdb_node.  Anything that
%% notifies a counter before that - cb_crl_manager's initial CRL load,
%% chronicle_local, ns_gc_runner - would have it silently dropped, because
%% ns_server_stats:notify_counter/2 writes to a table that does not exist yet
%% and swallows the badarg.  This process is started first instead, so the
%% table is there from the beginning of the node's life.
%%
%% Only this one table is moved: the other two ns_server_stats creates have
%% no writers that run this early.
%%
-module(ns_server_stats_table).

-behaviour(gen_server).

-export([start_link/0]).

-export([init/1, handle_call/3, handle_cast/2]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    ns_server_stats:init_metrics_table(),
    {ok, []}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.
