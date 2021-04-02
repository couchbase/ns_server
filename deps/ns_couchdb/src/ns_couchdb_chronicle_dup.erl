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
         lookup/1,
         get_snapshot/0]).


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
              fun ({{key, Key}, Rev, {updated, Value}}) ->
                      Self ! {insert, Ref, Key, Value, Rev};
                  ({{key, Key}, Rev, deleted}) ->
                      Self ! {delete, Ref, Key, Rev};
                  (_) ->
                      ok
              end),
    #state{child = Child, ref = Ref}.

handle_info({'EXIT', Child, Reason}, #state{child = Child}) ->
    ?log_debug("Received exit ~p from event subscriber", [Reason]),
    resubscribe(),
    {noreply, #state{child = undefined, ref = undefined}};
handle_info({'EXIT', From, Reason}, State) ->
    ?log_debug("Received exit ~p from ~p", [Reason, From]),
    {stop, Reason, State};
handle_info({insert, Ref, K, V, Rev}, State = #state{ref = Ref}) ->
    insert(K, V, Rev),
    {noreply, State};
handle_info({delete, Ref, K, Rev}, State = #state{ref = Ref}) ->
    delete(K, Rev),
    {noreply, State};
handle_info(resubscribe, #state{child = undefined} = State) ->
    {noreply, try
                  NewState = subscribe_to_events(),
                  self() ! pull,
                  NewState
              catch error:Error ->
                      ?log_debug("Subscription failed with ~p", [Error]),
                      resubscribe(),
                      State
              end};
handle_info(pull, State) ->
    misc:flush(pull),
    pull(),
    {noreply, State};
handle_info(Message, State) ->
    ?log_debug("Unexpected message ~p at state ~p", [Message, State]),
    {noreply, State}.

resubscribe() ->
    erlang:send_after(200, self(), resubscribe).

notify(Evt) ->
    gen_event:notify(chronicle_kv:event_manager(kv), Evt).

insert(K, V, R) ->
    ?log_debug("Set ~p, rev = ~p", [K, R]),
    ets:insert(?MODULE, {K, {V, R}}),
    notify({{key, K}, R, {updated, V}}).

delete(K, R) ->
    ?log_debug("Delete ~p, rev = ~p", [K, R]),
    ets:delete(?MODULE, K),
    notify({{key, K}, R, deleted}).

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

get_snapshot() ->
    ets:tab2list(?MODULE).

apply_snapshot(undefined) ->
    ok;
apply_snapshot(Snapshot) ->
    lists:foreach(
      fun ({K, {_V, R}}) ->
              case maps:is_key(K, Snapshot) of
                  true ->
                      ok;
                  false ->
                      delete(K, R)
              end
      end, get_snapshot()),
    lists:foreach(
      fun ({K, {V, R}}) ->
              case ets:lookup(?MODULE, K) of
                  [{K, {V, R}}] ->
                      ok;
                  _ ->
                      insert(K, V, R)
              end
      end, maps:to_list(Snapshot)).
