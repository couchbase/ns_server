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
        {ok, {RespBody}} when is_list(RespBody) ->
            case proplists:get_value(<<"success">>, RespBody) of
                true ->
                    ?log_debug("Lighthouse report sent successfuly");
                false ->
                    ?log_error("Sending lighthouse report failed. "
                               "Remote server returned:~n~p",
                               [RespBody])
            end;
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
      edition => build_edition(),
      version => build_version()}.

build_name() ->
    %% TODO: Actual product name
    <<"couchbase">>.

build_edition() ->
    %% TODO: Actual edition name
    <<"enterprise">>.

build_version() ->
    %% TODO: Actual product version
    <<"7.6">>.

build_resource_telemetry(_Statuses) ->
    %% TODO: Resource telemetry
    StorageBytesUsed = 0,
    StorageBytesTotal = 0,
    RamBytesUsed = 0,
    RamBytesTotal = 0,
    CpuPhysicalCores = 0,
    CpuLogicalCores = 0,
    #{storageBytesUsed => StorageBytesUsed,
      storageBytesTotal => StorageBytesTotal,
      ramBytesUsed => RamBytesUsed,
      ramBytesTotal => RamBytesTotal,
      cpuPhysicalCores => CpuPhysicalCores,
      cpuLogicalCores => CpuLogicalCores}.

build_services() ->
    [].

create_report() ->
    Now = os:timestamp(),
    CollectedAt = list_to_binary(misc:timestamp_iso8601(Now, utc)),
    Product = build_product(),
    ClusterUuid = menelaus_web:get_uuid_formatted(),
    BasePayload = #{collectedAt => CollectedAt,
                    product => Product,
                    clusterUuid => ClusterUuid},
    ResourceTelemetry = build_resource_telemetry([]),
    Payload1 = maps:merge(BasePayload, ResourceTelemetry),
    ClusterDetails = #{services => build_services(),
                       nodes => []},
    Payload2 = maps:merge(Payload1, ClusterDetails),
    json:encode(Payload2).
