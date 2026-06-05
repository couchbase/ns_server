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
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("ns_test.hrl").
-endif.


-behaviour(gen_server).

%% API
-export([start_link/0, build_settings/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(CONFIG_KEY, lighthouse).

-record(state, {
                enabled :: boolean(),
                report_pid :: undefined | pid()
               }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    misc:start_singleton(gen_server, ?MODULE, [], []).

build_settings() ->
    Settings = ns_config:read_key_fast(?CONFIG_KEY, #{}),
    maps:merge(default_config(), Settings).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    State = init_state(),
    self() ! report,
    {ok, State}.

handle_call(_Call, _From, State) ->
    {reply, ok, State}.

handle_cast(_Info, State) ->
    {noreply, State}.

handle_info(report, #state{enabled = true,
                           report_pid = undefined} = State0) ->
    NewReportPid = send_report(build_settings()),
    {noreply, State0#state{report_pid = NewReportPid}};
handle_info(report, State) ->
    %% Ignore unexpected report message, when either reporting is disabled, or
    %% a report is already in progress
    {noreply, State};
handle_info(report_done, State) ->
    {noreply, State#state{report_pid = undefined}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

init_state() ->
    Config = build_settings(),

    Enabled = get_setting(reporting_enabled, Config),

    %% Update the reporter state
    #state{enabled = Enabled}.

default_config() ->
    #{reporting_enabled => true,
      reporting_timeout_milliseconds => 1000,
      reporting_endpoint => <<"lighthouse.couchbase.internal">>}.

-spec get_setting(Key, #{Key => Value}) -> Value when
      Key :: reporting_enabled |
             reporting_timeout_milliseconds |
             reporting_endpoint,
      Value :: term().
get_setting(Key, Config) ->
    maps:get(Key, Config).

send_report(Config) ->
    Parent = self(),
    spawn_link(
      fun () ->
              Endpoint = get_setting(reporting_endpoint, Config),
              URL = binary_to_list(Endpoint),
              Report = create_report(),
              Timeout = get_setting(reporting_timeout_milliseconds, Config),
              post(URL, Report, Timeout),
              Parent ! report_done
      end).

post(URL, Body, Timeout) ->
    %% TODO: Switch to https once AV-131457 is implemented in lighthouse
    Scheme = http,
    Request = {Scheme, URL, 8080, "/api/v1/ingest/telemetry",
               "application/json", Body},
    try menelaus_rest:json_request_hilevel(post, Request,
                                           ?HIDE({basic_auth, "", ""}),
                                           [{connect_timeout, Timeout}]) of
        ok ->
            ?log_debug("Lighthouse report sent successfuly");
        {error, rest_error, Reason, _} ->
            %% When the lighthouse isn't available, we will usually get an
            %% nxdomain error, so we don't need to log it at error level
            ?log_debug("Sending lighthouse report failed. Error: ~s", [Reason]);
        {Error, Stacktrace} ->
            Reason = case Error of
                         ok -> bad_value;
                         _ -> Error
                     end,
            ?log_error("Sending lighthouse report failed. Error: ~p",
                       [{Reason, Stacktrace}])
    catch
        _:Error:Stack ->
            ?log_error("Sending lighthouse report crashed with error: ~p"
                       "~nStacktrace: ~p",
                       [Error, Stack])
    end.

build_product() ->
    #{name => build_name(),
      version => build_version()}.

build_name() ->
    <<"Couchbase Server">>.

build_version() ->
    misc:compat_version_to_binary(cluster_compat_mode:get_compat_version()).

build_edition(Node, Config) ->
    case cluster_compat_mode:is_node_enterprise(Node, Config) of
        true -> <<"enterprise">>;
        false -> <<"community">>
    end.

build_services(Node) ->
    ns_cluster_membership:node_active_services(Node).

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
    BasePayload = #{collectedAt => CollectedAt,
                    product => Product,
                    clusterUuid => ClusterUuid},
    ClusterDetails = #{nodes => NodesData},
    Payload1 = maps:merge(BasePayload, ClusterDetails),
    json:encode(Payload1).

-ifdef(TEST).

report_keys() ->
    [<<"clusterUuid">>,
     <<"collectedAt">>,
     <<"nodes">>,
     <<"product">>].

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
             PidMap2
     end,
     fun (PidMap) ->
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
