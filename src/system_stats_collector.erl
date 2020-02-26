%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2011-2019 Couchbase, Inc.
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
%% @doc grabs system-level stats portsigar
%%
-module(system_stats_collector).

%% API
-export([start_link/0]).

%% callbacks
-export([init/1, grab_stats/1, process_stats/5]).

-export([increment_counter/1, increment_counter/2,
         get_ns_server_stats/0, set_counter/2,
         add_histo/2,
         cleanup_stale_epoch_histos/0, log_system_stats/1,
         stale_histo_epoch_cleaner/0]).


-record(state, {
          port :: port() | undefined
         }).

start_link() ->
    base_stats_collector:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, #state{port = ns_server_stats:spawn_sigar()}}.

log_system_stats(TS) ->
    ns_server_stats:log_system_stats(TS).

grab_stats(#state{port = Port}) ->
    ns_server_stats:grab_stats(Port).

process_stats(TS, Binary, PrevSample, _, State) ->
    {RetStats, NewPrevSample} =
        ns_server_stats:process_stats(TS, Binary, PrevSample),
    {RetStats, NewPrevSample, State}.

increment_counter(Name) ->
    ns_server_stats:increment_counter(Name).

increment_counter(Name, By) ->
    ns_server_stats:increment_counter(Name, By).

set_counter(Name, Value) ->
    ns_server_stats:set_counter(Name, Value).

get_ns_server_stats() ->
    ns_server_stats:get_ns_server_stats().

add_histo(Type, Value) ->
    ns_server_stats:add_histo(Type, Value).

cleanup_stale_epoch_histos() ->
    ns_server_stats:cleanup_stale_epoch_histos().

stale_histo_epoch_cleaner() ->
    ns_server_stats:stale_histo_epoch_cleaner().
