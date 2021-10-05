%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included
%% in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
%% in that file, in accordance with the Business Source License, use of this
%% software will be governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.

-module(event_log).

-include("ns_common.hrl").
-include("cut.hrl").

-export([validators/0,
         log/1,
         add_log/1,
         add_log/2]).

-spec event_details(atom()) -> {integer(), atom(), atom(), binary()}.
%% event_ids block for ns_server related events: [0-1023]
event_details(node_join_success) ->
    {0, ns_server, info, <<"Node successfully joined the cluster">>};

%% event_ids block for Security related events: [9216, ..., 10239]
event_details(audit_enabled) ->
    {9216, security, info, <<"Audit enabled">>};
event_details(audit_disabled) ->
    {9217, security, info, <<"Audit disabled">>};
event_details(audit_cfg_changed) ->
    {9218, security, info, <<"Audit configuration change">>};

%% event_ids block for Data related events: [8192, ... 9215]
event_details(bucket_created) ->
    {8192, data, info, <<"Bucket created">>};
event_details(bucket_deleted) ->
    {8193, data, info, <<"Bucket deleted">>};
event_details(scope_created) ->
    {8194, data, info, <<"Scope created">>};
event_details(scope_deleted) ->
    {8195, data, info, <<"Scope deleted">>};
event_details(collection_created) ->
    {8196, data, info, <<"Collection created">>};
event_details(collection_deleted) ->
    {8197, data, info, <<"Collection deleted">>};
event_details(bucket_flushed) ->
    {8198, data, info, <<"Bucket flushed">>};
event_details(bucket_online) ->
    {8199, data, info, <<"Bucket online">>};
event_details(bucket_offline) ->
    {8200, data, info, <<"Bucket offline">>};
event_details(bucket_cfg_changed) ->
    {8201, data, info, <<"Bucket configuration changed">>}.

jsonify(Key, Value) when is_list(Value) ->
    [{Key, list_to_binary(Value)}].

is_valid_event_id(Id, "ns_server") when Id >= 0, Id < 1024 ->
    ok;
is_valid_event_id(Id, "query") when Id >= 1*1024, Id < 2*1024 ->
    ok;
is_valid_event_id(Id, "indexing") when Id >= 2*1024, Id < 3*1024 ->
    ok;
is_valid_event_id(Id, "search") when Id >= 3*1024, Id < 4*1024 ->
    ok;
is_valid_event_id(Id, "eventing") when Id >= 4*1024, Id < 5*1024 ->
    ok;
is_valid_event_id(Id, "analytics") when Id >= 5*1024, Id < 6*1024 ->
    ok;
is_valid_event_id(Id, "backup") when Id >= 6*1024, Id < 7*1024 ->
    ok;
is_valid_event_id(Id, "xdcr") when Id >= 7*1024, Id < 8*1024 ->
    ok;
is_valid_event_id(Id, "data") when Id >= 8*1024, Id < 9*1024 ->
    ok;
is_valid_event_id(Id, "security") when Id >= 9*1024, Id < 10*1024 ->
    ok;
is_valid_event_id(Id, "views") when Id >= 10*1024, Id < 11*1024 ->
    ok;
is_valid_event_id(Id, Service) ->
    {error, io_lib:format("event_id ~p outside the allocated block for ~p",
                          [Id, list_to_atom(Service)])}.

valid_component() ->
    ["ns_server", "query", "indexing", "search", "eventing", "analytics",
     "backup", "xdcr", "data", "security", "views"].

valid_info_levels() ->
    ["info", "error", "warn", "fatal"].

validators() ->
    [validator:required(component, _), validator:string(component, _),
     validator:one_of(component, valid_component(), _),

     validator:required(event_id, _), validator:integer(event_id, _),
     validator:validate_relative(fun is_valid_event_id/2,
                                 event_id, component, _),

     validator:required(severity, _), validator:string(severity, _),
     validator:one_of(severity, valid_info_levels(), _),

     validator:required(timestamp, _), validator:string(timestamp, _),
     validator:iso_8601_utc(timestamp, [required_msecs], _),

     validator:required(uuid, _), validator:string(uuid, _),
     validator:v4uuid(uuid, _),

     validator:required(description, _),
     validator:string(description, _),
     validator:length(description, 1, 80, _)].

build_nodename() ->
    {_, Name} = misc:node_name_host(node()),
    jsonify(node, Name).

build_event_details(Event) ->
    {Code, Comp, Level, Desc} = event_details(Event),
    [{event_id, Code}, {component, Comp},
     {description, Desc}, {severity, Level}].

build_mandatory_attributes(Event) ->
    [build_event_details(Event), build_nodename()].

build_extra_attributes([]) ->
    [];
build_extra_attributes(Extra) ->
    [{extra_attributes, {struct, lists:flatten(Extra)}}].

add_log(Event) ->
    add_log(Event, []).

add_log(Event, Extras) ->
    %% Event logs are enabled only when all the nodes are at 7.1.0.
    case cluster_compat_mode:is_cluster_NEO() of
        true ->
            Timestamp = misc:timestamp_iso8601(erlang:timestamp(), utc),
            Id = misc:uuid_v4(),
            Log = lists:flatten([jsonify(timestamp, Timestamp),
                                 build_mandatory_attributes(Event),
                                 [{uuid, Id}],
                                 build_extra_attributes(Extras)]),

            event_log_server:log(Timestamp, Id, Log);
        false ->
            ok
    end.

log(Event) ->
    {JSON} = ejson:decode(Event),
    Timestamp = binary_to_list(proplists:get_value(<<"timestamp">>, JSON)),
    Id = proplists:get_value(<<"uuid">>, JSON),

    %% Populate the node field for event logs received from the Services.

    JSON1 = case proplists:get_value(<<"node">>, JSON) of
                undefined ->
                    JSON ++ build_nodename();
                _ ->
                    JSON
           end,
    event_log_server:log(Timestamp, Id, JSON1).
