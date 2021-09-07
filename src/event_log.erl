%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-Present Couchbase, Inc.
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
         log/1]).

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
     validator:iso_8601_utc(timestamp, _),

     validator:required(uuid, _), validator:string(uuid, _),
     validator:v4uuid(uuid, _),

     validator:required(description, _),
     validator:string(description, _),
     validator:length(description, 1, 80, _)].

build_nodename() ->
    {_, Name} = misc:node_name_host(node()),
    jsonify(node, Name).

log(Event) ->
    {JSON} = ejson:decode(Event),
    % Timestamp = binary_to_list(proplists:get_value(<<"timestamp">>, JSON)),
    % Id = proplists:get_value(<<"uuid">>, JSON),

    %% Populate the node field for event logs received from the Services.

    JSON1 = case proplists:get_value(<<"node">>, JSON) of
                undefined ->
                    JSON ++ build_nodename();
                _ ->
                    JSON
           end,
    ?log_debug("Event log JSON - ~p~n", [JSON1]).
    % event_log_server:log(Timestamp, Id, JSON1).
