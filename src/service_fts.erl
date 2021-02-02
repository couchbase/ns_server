%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2015-2018 Couchbase, Inc.
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
-module(service_fts).

-include("ns_common.hrl").

-export([start_keeper/0, get_indexes/0]).

-export([get_type/0,
         get_remote_items/1,
         get_local_status/0,
         process_status/1,
         compute_version/2]).

get_indexes() ->
    service_status_keeper:get_items(?MODULE).

get_type() ->
    fts.

get_port() ->
    service_ports:get_port(fts_http_port).

get_timeout() ->
    ?get_timeout(rest_request, 10000).

get_remote_items(Node) ->
    remote_api:get_fts_indexes(Node).

get_local_status() ->
    rest_utils:get_json_local(fts, "api/nsstatus", get_port(), get_timeout()).

status_mapping() ->
    [{[index, id], <<"name">>},
     {bucket, <<"bucket">>},
     {hosts, <<"hosts">>}].

process_status(Status) ->
    service_status_keeper:process_indexer_status(?MODULE, Status,
                                                 status_mapping()).

start_keeper() ->
    service_status_keeper:start_link(?MODULE).

compute_version(Items, IsStale) ->
    erlang:phash2({Items, IsStale}).
