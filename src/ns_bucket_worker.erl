%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2019 Couchbase, Inc.
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
-module(ns_bucket_worker).

-behavior(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2]).

-include("cut.hrl").
-include("ns_common.hrl").

-define(SERVER, ?MODULE).

-record(state, {running_buckets :: [bucket_name()]}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% callbacks
init([]) ->
    Self = self(),
    ns_pubsub:subscribe_link(ns_config_events, config_event_handler(Self, _)),
    submit_update(Self),
    {ok, #state{running_buckets = []}}.

handle_call(Call, From, State) ->
    ?log_warning("Received unexpected "
                 "call ~p from ~p. State:~n~p", [Call, From, State]),
    {reply, nack, State}.

handle_cast(update_buckets, State) ->
    {noreply, update_buckets(State)};
handle_cast(Cast, State) ->
    ?log_warning("Received unexpected cast ~p. State:~n~p", [Cast, State]),
    {noreply, State}.

%% internal
config_event_handler(WorkerPid, Event) ->
    case is_interesting_event(Event) of
        true ->
            submit_update(WorkerPid);
        false ->
            ok
    end.

is_interesting_event({buckets, _}) ->
    true;
is_interesting_event({node, Node, membership}) when Node =:= node() ->
    true;
is_interesting_event({node, Node, services}) when Node =:= node() ->
    true;
is_interesting_event(_) ->
    false.

submit_update(Pid) ->
    gen_server:cast(Pid, update_buckets).

update_buckets(#state{running_buckets = RunningBuckets} = State) ->
    NewBuckets = ns_bucket:node_bucket_names(node()),

    ToStart = NewBuckets -- RunningBuckets,
    ToStop  = RunningBuckets -- NewBuckets,

    start_buckets(ToStart),
    stop_buckets(ToStop),

    State#state{running_buckets = NewBuckets}.

start_buckets(Buckets) ->
    lists:foreach(fun start_one_bucket/1, Buckets).

start_one_bucket(Bucket) ->
    ?log_debug("Starting new bucket: ~p", [Bucket]),
    ok = ns_bucket_sup:start_bucket(Bucket).

stop_buckets(Buckets) ->
    lists:foreach(fun stop_one_bucket/1, Buckets).

stop_one_bucket(Bucket) ->
    ?log_debug("Stopping child for dead bucket: ~p", [Bucket]),
    TimeoutPid =
        diag_handler:arm_timeout(
          30000,
          fun (_) ->
                  ?log_debug("Observing slow bucket supervisor "
                             "stop request for ~p", [Bucket]),
                  timeout_diag_logger:log_diagnostics(
                    {slow_bucket_stop, Bucket})
          end),

    try
        ok = ns_bucket_sup:stop_bucket(Bucket)
    after
        diag_handler:disarm_timeout(TimeoutPid)
    end.
