%% @author Couchbase <info@couchbase.com>
%% @copyright 2021 Couchbase, Inc.
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
-module(chronicle_kv_log).

-behaviour(gen_server2).

-export([start_link/0, init/1, handle_info/2]).

-include("ns_common.hrl").

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Self = self(),
    ns_pubsub:subscribe_link(chronicle_kv:event_manager(kv),
                             fun ({_, _, _} = Evt) ->
                                     Self ! Evt;
                                 (_) ->
                                     ok
                             end),
    {ok, #{}}.

handle_info({{key, K}, R, {updated, V}}, State) ->
    NewState = log(K, V, R, State),
    {noreply, NewState, hibernate};
handle_info({{key, K}, R, deleted}, State) ->
    ?log_debug("delete (key: ~p, rev: ~p)", [K, R]),
    {noreply, maps:remove(K, State), hibernate};
handle_info(Info, State) ->
    ?log_warning("Unexpected message(~p, ~p)", [Info, State]),
    {noreply, State, hibernate}.

log(K, V, R, State) ->
    {NewV, NewState} =
        case ns_bucket:sub_key_match(K) of
            {true, _Bucket, props} ->
                {case maps:find(K, State) of
                     {ok, Old} ->
                         ns_config_log:compute_bucket_diff(V, Old);
                     error ->
                         V
                 end, maps:put(K, V, State)};
            _ ->
                {V, State}
        end,
    VB = list_to_binary(io_lib:print(NewV, 0, 80, 100)),
    ?log_debug("update (key: ~p, rev: ~p)~n~s", [K, R, VB]),
    NewState.
