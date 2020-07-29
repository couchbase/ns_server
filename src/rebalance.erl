%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2020 Couchbase, Inc.
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
-module(rebalance).

-export([running/0,
         running/1,
         type/0,
         status_uuid/0,
         status/0,
         reset_status/1,
         set_status/3,
         start/3,
         stop/1,
         progress/0,
         progress/1]).

-include("ns_common.hrl").

rebalancer(Config) ->
   case ns_config:search(Config, rebalancer_pid) of
       {value, Pid} when is_pid(Pid) ->
           Pid;
       _ ->
           undefined
   end.

running() ->
    running(ns_config:latest()).

running(Config) ->
    rebalancer(Config) =/= undefined.

type() ->
    ns_config:read_key_fast(rebalance_type, rebalance).

status_uuid() ->
    ns_config:read_key_fast(rebalance_status_uuid, undefined).

status() ->
    ns_config:read_key_fast(rebalance_status, undefined).

reset_status(Fn) ->
    ok =
        ns_config:update(
          fun ({rebalance_status, Value}) ->
                  case Value of
                      running ->
                          NewValue = Fn(),
                          {update, {rebalance_status, NewValue}};
                      _ ->
                          skip
                  end;
              ({rebalancer_pid, Pid}) when is_pid(Pid) ->
                  {update, {rebalancer_pid, undefined}};
              (_Other) ->
                  skip
          end).

set_status(Type, Status, Pid) ->
    ns_config:set(
      [{rebalance_status, Status},
       {rebalance_status_uuid, couch_uuids:random()},
       {rebalancer_pid, Pid},
       {rebalance_type, Type},
       %% needed for compatibility with pre-6.5 nodes
       {graceful_failover_pid,
        case Type of
            graceful_failover ->
                Pid;
            _ ->
                undefined
        end}]).

start(KnownNodes, EjectedNodes, DeltaRecoveryBuckets) ->
    ns_orchestrator:start_rebalance(KnownNodes, EjectedNodes,
                                    DeltaRecoveryBuckets).

stop(AllowUnsafe) ->
    %% NOTE: this is inherently raceful. But race is tiny and largely
    %% harmless. So we KISS instead.
    case can_stop(AllowUnsafe) of
        true ->
            ns_orchestrator:stop_rebalance();
        false ->
            unsafe
    end.

can_stop(true) ->
    true;
can_stop(false) ->
    case rebalancer(ns_config:latest()) of
        undefined ->
            true;
        Pid ->
            node(Pid) =:= mb_master:master_node()
    end.

-spec progress() -> {running, [{atom(), float()}]} |
                    not_running |
                    {error, timeout}.
progress() ->
    progress(?REBALANCE_OBSERVER_TASK_DEFAULT_TIMEOUT).

-spec progress(non_neg_integer()) -> {running, [{atom(), float()}]} |
                                     not_running |
                                     {error, timeout}.
progress(Timeout) ->
    case running() of
        false ->
            not_running;
        true ->
            case ns_rebalance_observer:get_aggregated_progress(Timeout) of
                {ok, Aggr} ->
                    {running, Aggr};
                Err ->
                    ?log_error("Couldn't reach ns_rebalance_observer"),
                    Err
            end
    end.
