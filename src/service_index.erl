%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2015-2021 Couchbase, Inc.
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
-module(service_index).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_keeper/0, get_indexes/0, get_indexes_version/0]).

-export([get_type/0, get_remote_items/1, get_local_status/0,
         process_status/1, compute_version/2]).

get_indexes() ->
    service_status_keeper:get_items(?MODULE).

get_indexes_version() ->
    service_status_keeper:get_version(?MODULE).

get_type() ->
    index.

get_port() ->
    service_ports:get_port(indexer_http_port).

get_timeout() ->
    ?get_timeout(rest_request, 10000).

get_remote_items(Node) ->
    remote_api:get_indexes(Node).

get_local_status() ->
    rest_utils:get_json_local(indexer, "getIndexStatus",
                              get_port(), get_timeout()).

status_mapping() ->
    AddType0 = [{storageMode, <<"indexType">>}],
    AddType = case cluster_compat_mode:is_enterprise() of
                  true ->
                      [{instId, <<"instId">>},
                       {partitioned, <<"partitioned">>},
                       {numPartition, <<"numPartition">>},
                       {partitionMap, <<"partitionMap">>} | AddType0];
                  false ->
                      AddType0
              end,

    [{id, <<"defnId">>},
     {index, <<"name">>},
     {indexName, <<"indexName">>},
     {lastScanTime, <<"lastScanTime">>},
     {numReplica, <<"numReplica">>},
     {bucket, <<"bucket">>},
     {scope, <<"scope">>},
     {collection, <<"collection">>},
     {status, <<"status">>},
     {definition, <<"definition">>},
     {progress, <<"completion">>},
     {stale, <<"stale">>},
     {hosts, <<"hosts">>} | AddType].

process_status(Status) ->
    service_status_keeper:process_indexer_status(?MODULE, Status,
                                                 status_mapping()).

start_keeper() ->
    service_status_keeper:start_link(?MODULE).

compute_version_ignored_items() ->
    [lastScanTime, progress].

compute_version(Items, IsStale) ->
    %% Don't include items that change frequently and are "unimportant"
    %% wrt determining whether or not a change has occurred.  This is done
    %% to avoid unnecessary change notifications.
    Items0 = lists:map(
               fun (ItemList) ->
                       lists:foldl(
                         fun (Key, Acc) ->
                                 lists:keydelete(Key, 1, Acc)
                         end, ItemList, compute_version_ignored_items())
               end, Items),
    erlang:phash2({Items0, IsStale}).

-ifdef(TEST).
compute_version_test() ->
    ItemsWithLst = [[{storageMode,<<"plasma">>},
                     {progress,100},
                     {hosts,[<<"127.0.0.1:9000">>]},
                     {lastScanTime,<<"Mon Sep 23 11:07:30 PDT 2019">>},
                     {index,<<"beer_primary">>}],
                    [{storageMode,<<"plasma">>},
                     {progress,55},
                     {hosts,[<<"127.0.0.1:9001">>]},
                     {lastScanTime,<<"Mon Sep 23 12:11:22 PDT 2019">>},
                     {index,<<"def_airportname">>}]],
    ItemsRedactedLst = [[{storageMode,<<"plasma">>},
                         {hosts,[<<"127.0.0.1:9000">>]},
                         {index,<<"beer_primary">>}],
                        [{storageMode,<<"plasma">>},
                         {hosts,[<<"127.0.0.1:9001">>]},
                         {index,<<"def_airportname">>}]],
    LstVersion = compute_version(ItemsWithLst, false),
    NoLstVersion = compute_version(ItemsRedactedLst, false),
    Direct = erlang:phash2({ItemsRedactedLst, false}),

    ?assertEqual(LstVersion, NoLstVersion),
    ?assertEqual(LstVersion, Direct).

-endif.
