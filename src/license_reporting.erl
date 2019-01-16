%% @author Couchbase <info@couchbase.com>
%% @copyright 2016-2019 Couchbase, Inc.
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

%% @doc the main purpose of this process is to send 'on-demand pricing' reports
%% to configured server with configured period

-module(license_reporting).

-behaviour(gen_server).

%% API
-export([start_link/0, build_settings/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("ns_common.hrl").

-record(s, {
    enabled = false :: boolean(),
    reporting_interval :: pos_integer(),
    report_timer_ref :: undefined | reference()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

build_settings() ->
    Settings = ns_config:read_key_fast(license_settings, []),
    misc:update_proplist(defaults(), Settings).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    case cluster_compat_mode:is_enterprise() of
        true ->
            Self = self(),
            EventHandler =
                fun ({license_settings, _} = E) -> Self ! E;
                    (_) -> ok
                end,
            ns_pubsub:subscribe_link(ns_config_events, EventHandler),
            State = #s{reporting_interval = get_setting(reporting_interval),
                       enabled = get_setting(reporting_enabled)},
            {ok, restart_timer(State), hibernate};
        false ->
            ignore
    end.

handle_call(Request, _From, State) ->
    ?log_error("Unhandled call: ~p", [Request]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?log_error("Unhandled cast: ~p", [Msg]),
    {noreply, State}.

handle_info(report, State) ->
    send_report(),
    {noreply, restart_timer(State), hibernate};

handle_info({license_settings, _},
            #s{reporting_interval = Interval, enabled = Enabled} = State) ->
    Settings = build_settings(),
    NewInterval = proplists:get_value(reporting_interval, Settings, Interval),
    NewEnabled = proplists:get_value(reporting_enabled, Settings, Enabled),

    NewState = State#s{reporting_interval = NewInterval, enabled = NewEnabled},

    NewState2 =
        case NewState == State of
            true -> NewState;
            false -> restart_timer(NewState)
        end,

    {noreply, NewState2, hibernate};

handle_info(Info, State) ->
    ?log_error("Unhandled info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

send_report() ->
    Report = create_report(),
    ?log_info("Sending license report:~n~p", [Report]),
    ok.

get_setting(Prop) ->
    proplists:get_value(Prop, build_settings()).

restart_timer(#s{report_timer_ref = Ref,
                 enabled = Enabled,
                 reporting_interval = Timeout} = State) ->
    Ref =/= undefined andalso erlang:cancel_timer(Ref),
    NewRef =
        case Enabled of
            true -> erlang:send_after(max(Timeout, 10000), self(), report);
            false -> undefined
        end,
    State#s{report_timer_ref = NewRef}.

defaults() ->
    [{reporting_enabled, false},
     {reporting_interval, 3600000}, % 1 hour
     {contract_id, ""},
     {customer_token, {password, ""}}].

create_report() ->
    Nodes = ns_node_disco:nodes_actual(),
    NodesData =
        lists:map(
          fun (Node) ->
              Props = ns_doctor:get_node(Node),
              SystemStats = proplists:get_value(system_stats, Props, []),
              MemLimit = proplists:get_value(mem_limit, SystemStats),
              Cores = proplists:get_value(cpu_cores_available, SystemStats),
              {_, Hostname} = misc:node_name_host(Node),
              {[{node, Node},
                {hostname, iolist_to_binary(Hostname)},
                {cpu_cores_available, Cores},
                {mem_limit, MemLimit}]}
          end, Nodes),

    {[{timestamp, iolist_to_binary(misc:timestamp_utc_iso8601())},
      {cluster_uuid, ns_config:read_key_fast(uuid, 1)},
      {contract_id, iolist_to_binary(get_setting(contract_id))},
      {cluster_size, length(Nodes)},
      {nodes, NodesData}]}.
