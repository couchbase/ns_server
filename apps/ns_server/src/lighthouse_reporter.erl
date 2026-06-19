%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

%% @doc This process sends telemetry reports to a lighthouse portal, at regular
%% intervals.

-module(lighthouse_reporter).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("ns_test.hrl").
-endif.


-behaviour(gen_server).

%% API
-export([start_link/0, config_key/0, build_settings/0, ingest/2,
         max_external_payload_size/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, {via, leader_registry, ?MODULE}).

-define(CONFIG_KEY, lighthouse).
-define(TABLE, external_payloads).
-define(SENDS_METRIC, <<"lighthouse_telemetry_sends">>).

-record(state, {
                enabled = true :: boolean(),
                report_timer_ref :: undefined | timer:tref(),
                report_pid :: undefined | pid(),
                max_external_nodes = 0 :: integer()
               }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    misc:start_singleton(gen_server, ?MODULE, [], []).

config_key() ->
    ?CONFIG_KEY.

build_settings() ->
    Settings = ns_config:read_key_fast(?CONFIG_KEY, #{}),
    maps:merge(default_config(), Settings).

ingest(Opts, Payload) ->
    gen_server:call(?SERVER, {ingest, Opts, Payload}).

max_external_payload_size() ->
    get_setting(external_nodes_max_payload_bytes, build_settings()).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Self = self(),
    ns_pubsub:subscribe_link(ns_config_events, handle_config_event(Self, _)),
    create_metric(),
    ets:new(?TABLE, [named_table, set]),
    {ok, update_config(#state{})}.

handle_call({ingest, Opts, Payload}, _From,
            #state{max_external_nodes = MaxExternalNodes} = State) ->
    {reply, ingest_external_payload(Opts, Payload, MaxExternalNodes), State};
handle_call(_Call, _From, State) ->
    {reply, ok, State}.

handle_cast(_Info, State) ->
    {noreply, State}.

handle_info(report, #state{enabled = true,
                           report_pid = undefined} = State) ->
    NewReportPid = send_report(build_settings()),
    {noreply, State#state{report_pid = NewReportPid}};
handle_info(report, State) ->
    %% Ignore unnecessary report message, when either reporting is disabled, or
    %% a report is already in progress
    {noreply, State};
handle_info(report_done, State) ->
    %% Clear the external payloads now they've been sent to the lighthouse which
    %% should retain the information
    ets:delete_all_objects(?TABLE),
    {noreply, State#state{report_pid = undefined}};
handle_info(config_change, State) ->
    {noreply, update_config(State)};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handle_config_event(Self, {?CONFIG_KEY, _}) ->
    Self ! config_change;
handle_config_event(_, _) ->
    ok.

create_metric() ->
    lists:foreach(
      fun (Result) ->
              ns_server_stats:create_counter(
                {?SENDS_METRIC, [{result, Result}]})
      end, [success, failure]).

update_metric(Result) ->
    ns_server_stats:notify_counter(
      {?SENDS_METRIC, [{result, Result}]}).

ingest_external_payload(#{product_name := ProductName, instance_id := Instance},
                        Payload, MaxExternalNodes) ->
    Key = {list_to_binary(ProductName), Instance},
    IsUpdate = ets:member(?TABLE, Key),
    case IsUpdate orelse ets:info(?TABLE, size) < MaxExternalNodes of
        true ->
            ets:insert(?TABLE, {Key, Payload}),
            ok;
        false ->
            {error, too_many_payloads}
    end.

update_config(State0) ->
    Config = build_settings(),

    Enabled = get_setting(reporting_enabled, Config),
    MaxExternalNodes = get_setting(external_nodes_max_count, Config),
    State1 = State0#state{enabled = Enabled,
                          max_external_nodes = MaxExternalNodes},

    %% Update the reporter state
    ReportIntervalHours = get_setting(reporting_interval_hours, Config),
    restart_timer(State1, round(timer:hours(ReportIntervalHours))).

default_config() ->
    #{reporting_enabled => true,
      reporting_interval_hours => 2,
      reporting_timeout_seconds => 1,
      reporting_endpoint => <<"lighthouse.couchbase.internal">>,
      reporting_port => 443,
      external_nodes_max_payload_bytes => 10_240,  %% 10KiB
      external_nodes_max_count => 100}.

-spec get_setting(Key, #{Key => Value}) -> Value when
      Key :: reporting_enabled |
             reporting_interval_hours |
             reporting_timeout_seconds |
             reporting_endpoint |
             reporting_port |
             external_nodes_max_payload_bytes |
             external_nodes_max_count,
      Value :: term().
get_setting(Key, Config) ->
    maps:get(Key, Config).

restart_timer(#state{report_timer_ref = undefined} = State,
              ReportIntervalMs) ->
    %% Immediately start a report after re-configuring
    self() ! report,
    {ok, Ref} = timer:send_interval(ReportIntervalMs, report),
    State#state{report_timer_ref = Ref};
restart_timer(#state{report_timer_ref = TRef} = State, ReportIntervalMs) ->
    %% We need to make sure there is only one timer at any given moment,
    %% otherwise the system would be fragile to future changes or diag/evals
    timer:cancel(TRef),
    restart_timer(State#state{report_timer_ref = undefined}, ReportIntervalMs).

send_report(Config) ->
    Parent = self(),
    spawn_link(
      fun () ->
              Endpoint = get_setting(reporting_endpoint, Config),
              URL = binary_to_list(Endpoint),
              Port = get_setting(reporting_port, Config),
              Report = create_report(),
              Timeout = timer:seconds(get_setting(reporting_timeout_seconds,
                                                  Config)),
              Result = post(URL, Port, Report, Timeout),
              update_metric(Result),
              Parent ! report_done
      end).

post(URL, Port, Body, Timeout) ->
    Scheme = https,
    Request = {Scheme, URL, Port, "/api/v1/ingest/telemetry",
               "application/json", Body},
    try menelaus_rest:json_request_hilevel(post, Request,
                                           ?HIDE({basic_auth, "", ""}),
                                           [{connect_timeout, Timeout},
                                            {server_verification, false}]) of
        ok ->
            ?log_debug("Lighthouse report sent successfuly"),
            success;
        {error, rest_error, Reason, _} ->
            %% When the lighthouse isn't available, we will usually get an
            %% nxdomain error, so we don't need to log it at error level
            ?log_debug("Sending lighthouse report failed. Error: ~s", [Reason]),
            failure;
        {client_error, JsonResponse} ->
            %% Error from lighthouse itself
            ?log_debug("Lighthouse report rejected by portal. Error: ~s",
                       [ejson:encode(JsonResponse)]),
            failure;
        {ok, _JsonResponse} ->
            %% Ignore unexpected success payload
            ?log_debug("Lighthouse report sent successfuly. Ignored unexpected "
                       "response"),
            success
    catch
        _:Error:Stack ->
            ?log_error("Sending lighthouse report crashed with error: ~p"
                       "~nStacktrace: ~p",
                       [Error, Stack]),
            failure
    end.

build_product() ->
    #{name => build_name(),
      version => build_version()}.

build_name() ->
    <<"Couchbase Server">>.

build_version() ->
    misc:compat_version_to_binary(cluster_compat_mode:get_compat_version()).

build_edition(Node, Config) ->
    case cluster_compat_mode:is_enterprise(Node, Config) of
        true -> <<"enterprise">>;
        false -> <<"community">>
    end.

build_services(Node) ->
    lists:map(fun ns_cluster_membership:json_service_name/1,
              ns_cluster_membership:node_active_services(Node)).

build_external_nodes() ->
    ets:foldl(
      fun ({{Product, _Instance}, PayloadEncoded}, Acc) ->
              PayloadDecoded = json:decode(PayloadEncoded),
              maps:update_with(Product, [PayloadDecoded | _],
                               [PayloadDecoded], Acc)

      end, #{}, ?TABLE).

create_report() ->
    Config = ns_config:get(),
    Nodes = ns_node_disco:nodes_actual(),
    NodesData =
        lists:map(
          fun (Node) ->
                  Props = ns_doctor:get_node(Node),
                  Os = iolist_to_binary(
                         proplists:get_value(system_arch, Props, "unknown")),
                  Hostname = iolist_to_binary(misc:extract_node_address(Node)),
                  IsEnterprise = build_edition(Node, Config),
                  UptimeSeconds = proplists:get_value(wall_clock, Props, 0),
                  CoresLogical = proplists:get_value(cpu_count, Props, 0),
                  SystemStats = proplists:get_value(system_stats, Props, []),
                  CoresPhysical = proplists:get_value(cpu_host_cores_available,
                                                      Props, 0),
                  RamBytesTotal = proplists:get_value(mem_total,
                                                      SystemStats, 0),
                  RamBytesUsed = proplists:get_value(mem_actual_used,
                                                     SystemStats, 0),
                  CgroupRamBytesTotal = proplists:get_value(mem_cgroup_limit,
                                                            SystemStats, 0),
                  CgroupRamBytesUsed = proplists:get_value(mem_cgroup_used,
                                                           SystemStats, 0),
                  StorageBytesTotal =
                      proplists:get_value(data_disk_bytes_available, Props, 0),
                  StorageBytesUsed =
                      proplists:get_value(data_disk_bytes_used, Props, 0),
                  Services = build_services(Node),
                  #{os => Os,
                    hostname => Hostname,
                    edition => IsEnterprise,
                    uptimeSeconds => UptimeSeconds,
                    cpuLogicalCores => CoresLogical,
                    cpuPhysicalCores => CoresPhysical,
                    ramBytesTotal => RamBytesTotal,
                    ramBytesUsed => RamBytesUsed,
                    cgroupRamBytesTotal => CgroupRamBytesTotal,
                    cgroupRamBytesUsed => CgroupRamBytesUsed,
                    storageBytesTotal => StorageBytesTotal,
                    storageBytesUsed => StorageBytesUsed,
                    services => Services}
          end, Nodes),

    Now = os:timestamp(),
    CollectedAt = list_to_binary(misc:timestamp_iso8601(Now, utc)),
    Product = build_product(),
    ClusterUuid = menelaus_web:get_uuid_formatted(),
    ExternalNodes = build_external_nodes(),
    BasePayload = #{collectedAt => CollectedAt,
                    product => Product,
                    clusterUuid => ClusterUuid,
                    externalNodes => ExternalNodes},
    ClusterDetails = #{nodes => NodesData},
    Payload1 = maps:merge(BasePayload, ClusterDetails),
    json:encode(Payload1).

-ifdef(TEST).

report_keys() ->
    [<<"clusterUuid">>,
     <<"collectedAt">>,
     <<"nodes">>,
     <<"product">>,
     <<"externalNodes">>].

node_keys() ->
    [<<"cpuLogicalCores">>,
     <<"cpuPhysicalCores">>,
     <<"hostname">>,
     <<"os">>,
     <<"edition">>,
     <<"ramBytesTotal">>,
     <<"ramBytesUsed">>,
     <<"cgroupRamBytesTotal">>,
     <<"cgroupRamBytesUsed">>,
     <<"services">>,
     <<"storageBytesTotal">>,
     <<"storageBytesUsed">>,
     <<"uptimeSeconds">>].

create_report_test_() ->
    {setup,
     fun () ->
             fake_ns_config:setup(),
             fake_chronicle_kv:setup(),
             PidMap1 = mock_helpers:setup_mocks([ns_heart]),
             {ok, NsDoctorPid} = ns_doctor:start_link(),
             PidMap2 = PidMap1#{ns_doctor => NsDoctorPid},
             meck:expect(ns_node_disco, nodes_actual, 0, [node()]),
             ets:new(?TABLE, [named_table, set]),
             PidMap2
     end,
     fun (PidMap) ->
             ets:delete(?TABLE),
             %% Shut down ns_heart first, as it depends on other processes
             mock_helpers:teardown(
               maps:filter(fun (Key, _) -> Key =:= ns_heart end, PidMap)),
             %% It's now safe to shut down the rest without crashing ns_heart
             mock_helpers:teardown(PidMap),
             fake_chronicle_kv:teardown(),
             fake_ns_config:teardown(),
             meck:unload()
     end,
     fun () ->
             Report = create_report(),
             %% Convert back to maps for validation
             ReportMap = json:decode(list_to_binary(Report)),
             ?assertListsEqual(report_keys(), maps:keys(ReportMap)),
             [NodeMap] = maps:get(<<"nodes">>, ReportMap),
             ?assertListsEqual(node_keys(), maps:keys(NodeMap))
     end}.

-endif.
