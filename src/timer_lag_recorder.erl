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
%% This process sends itself a message using send_after and then measures
%% the lag of when the message is received vs when it is expected.

-module(timer_lag_recorder).

-include("ns_common.hrl").

%% How often to send ourself a message in milliseconds.
-define(TIMER_INTERVAL, 1000).

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_info/2, handle_cast/2]).

-record(state, {time_expected}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    TimeExpected = send_check_time(),
    {ok, #state{time_expected = TimeExpected}}.

send_check_time() ->
    TimeExpected = erlang:monotonic_time(millisecond) + ?TIMER_INTERVAL,
    erlang:send_after(TimeExpected, self(), check_time, [{abs, true}]),
    TimeExpected.

handle_call(Msg, _From, _State) ->
    erlang:error({unknown_msg, Msg}).

handle_cast(Msg, _State) ->
    erlang:error({unknown_cast, Msg}).

handle_info(check_time, #state{time_expected = TimeExpected0} = State) ->
    TimeNow = erlang:monotonic_time(millisecond),
    Lag = TimeNow - TimeExpected0,
    system_stats_collector:add_histo(timer_lag, Lag * 1000),
    Skipped = Lag / ?TIMER_INTERVAL,

    case Skipped > 10 of
        true ->
            error_logger:error_msg("Detected time forward jump (or too large "
                                   "erlang scheduling latency).  Skipping ~w "
                                   "samples (or ~w milliseconds)",
                                   [Skipped, Lag]);
        false ->
            ok
    end,

    TimeExpected = send_check_time(),

    {noreply, State#state{time_expected = TimeExpected}}.
