%% @author Couchbase <info@couchbase.com>
%% @copyright 2020 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% @doc process responsible for maintaining the copy of chronicle_kv
%% on ns_couchdb node
%%

-module(ns_couchdb_chronicle_dup).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include("ns_config.hrl").

-export([start_link/0,
         init/1,
         handle_info/2,
         lookup/1]).


-record(state, {child, ref}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

lookup(Key) ->
    ets:lookup(?MODULE, Key).

init([]) ->
    ets:new(?MODULE, [public, set, named_table]),
    process_flag(trap_exit, true),
    State = subscribe_to_events(),
    pull(),
    {ok, State}.

subscribe_to_events() ->
    Self = self(),
    Ref = make_ref(),
    NsServer = ns_node_disco:ns_server_node(),
    ?log_debug("Subscribing to events from ~p with ref = ~p", [NsServer, Ref]),
    Child = ns_pubsub:subscribe_link(
              {chronicle_kv:event_manager(kv), NsServer},
              fun ({{key, Key}, _Rev, {updated, Value}}) ->
                      Self ! {insert, Ref, {Key, Value}};
                  ({{key, Key}, _Rev, deleted}) ->
                      Self ! {delete, Ref, Key};
                  (_) ->
                      ok
              end),
    #state{child = Child, ref = Ref}.

handle_info({'EXIT', Child, Reason}, #state{child = Child}) ->
    ?log_debug("Received exit ~p from event subscriber", [Reason]),
    erlang:send_after(200, self(), resubscribe),
    {noreply, #state{child = undefined, ref = undefined}};
handle_info({'EXIT', From, Reason}, State) ->
    ?log_debug("Received exit ~p from ~p", [Reason, From]),
    {stop, Reason, State};
handle_info({insert, Ref, KV}, State = #state{ref = Ref}) ->
    insert(KV),
    {noreply, State};
handle_info({delete, Ref, K}, State = #state{ref = Ref}) ->
    delete(K),
    {noreply, State};
handle_info(resubscribe, #state{child = undefined}) ->
    self() ! pull,
    {noreply, subscribe_to_events()};
handle_info(pull, State) ->
    misc:flush(pull),
    pull(),
    {noreply, State};
handle_info(Message, State) ->
    ?log_debug("Unexpected message ~p at state ~p", [Message, State]),
    {noreply, State}.

notify(Evt) ->
    gen_event:notify(chronicle_kv:event_manager(kv), Evt).

insert({K, V} = KV) ->
    ?log_debug("Set ~p", [KV]),
    ets:insert(?MODULE, KV),
    notify({{key, K}, no_rev, {updated, V}}).

delete(K) ->
    ?log_debug("Delete ~p", [K]),
    ets:delete(?MODULE, K),
    notify({{key, K}, no_rev, deleted}).

pull() ->
    NsServer = ns_node_disco:ns_server_node(),
    ?log_debug("Pulling everything from ~p", [NsServer]),
    Snapshot =
        try
            chronicle_local:get_snapshot(NsServer)
        catch
            Type:What ->
                ?log_debug("Config pull from ~p:~p failed due to ~p",
                           [NsServer, Type, What]),
                erlang:send_after(200, self(), pull),
                undefined
        end,
    apply_snapshot(Snapshot).

apply_snapshot(undefined) ->
    ok;
apply_snapshot(Snapshot) ->
    DeletedKeys = [K || {K, _} <- ets:tab2list(?MODULE)] --
        [K || {K, _} <- Snapshot],
    [delete(K) || K <- DeletedKeys],
    lists:foreach(
      fun ({K, _V} = KV) ->
              case ets:lookup(?MODULE, K) of
                  [KV] ->
                      ok;
                  _ ->
                      insert(KV)
              end
      end, Snapshot).
