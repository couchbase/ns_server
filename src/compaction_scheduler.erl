%% @author Couchbase <info@couchbase.com>
%% @copyright 2014-2015 Couchbase, Inc.
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
%% @doc scheduler for compaction daemon
%%

-module(compaction_scheduler).

-include("ns_common.hrl").

-record(state, {start_ts,
                timer,
                interval,
                message}).

-export([init/2, set_interval/2, schedule_next/1, start_now/1, cancel/1]).

-spec init(integer(), term()) -> #state{}.
init(Interval, Message) ->
    #state{start_ts = undefined,
           timer = misc:create_timer(Message),
           interval = Interval,
           message = Message}.

-spec set_interval(integer(), #state{}) -> #state{}.
set_interval(Interval, State) ->
    State#state{interval=Interval}.

-spec schedule_next(#state{}) -> #state{}.
schedule_next(#state{start_ts = StartTs0,
                     interval = CheckInterval,
                     timer = Timer,
                     message = Message} = State) ->
    Now = now_utc_seconds(),

    StartTs = case StartTs0 of
                  undefined ->
                      Now;
                  _ ->
                      StartTs0
              end,

    Diff = Now - StartTs,

    Timeout =
        case Diff < CheckInterval of
            true ->
                RepeatIn = (CheckInterval - Diff),
                ?log_debug("Finished compaction for ~p too soon. "
                           "Next run will be in ~ps", [Message, RepeatIn]),
                RepeatIn * 1000;
            false ->
                0
        end,

    State#state{start_ts = undefined,
                timer = misc:arm_timer(Timeout, Timer)}.

-spec start_now(#state{}) -> #state{}.
start_now(State) ->
    State#state{start_ts = now_utc_seconds()}.

-spec cancel(#state{}) -> #state{}.
cancel(#state{timer = Timer} = State) ->
    State#state{timer = misc:cancel_timer(Timer)}.

now_utc_seconds() ->
    calendar:datetime_to_gregorian_seconds(erlang:universaltime()).
