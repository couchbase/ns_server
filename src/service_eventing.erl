%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2018 Couchbase, Inc.
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
-module(service_eventing).

-include("ns_common.hrl").

-export([get_functions/0,
         start_keeper/0,
         get_type/0,
         get_local_status/1,
         get_remote_items/1,
         process_status/1,
         compute_version/2]).

get_functions() ->
    {ok, Functions, _, _} = service_status_keeper:get_items(?MODULE),
    Functions.

start_keeper() ->
    service_status_keeper:start_link(?MODULE).

get_type() ->
    eventing.

get_port() ->
    service_ports:get_port(eventing_http_port).

get_local_status(_Headers) ->
    Timeout = ?get_timeout(status, 30000),
    rest_utils:get_json_local(eventing, "api/v1/functions",
                              get_port(), Timeout).

get_remote_items(Node) ->
    remote_api:get_service_remote_items(Node, ?MODULE).

process_status(Status) ->
    {ok, lists:filtermap(
           fun ({Function}) ->
                   {_, Name} = lists:keyfind(<<"appname">>, 1, Function),
                   {_, {Settings}} = lists:keyfind(<<"settings">>, 1, Function),
                   case lists:keyfind(<<"processing_status">>, 1, Settings) of
                       {_, true} ->
                           {true, Name};
                       {_, false} ->
                           false
                   end
           end, Status)}.

compute_version(Items, IsStale) ->
    erlang:phash2({Items, IsStale}).
