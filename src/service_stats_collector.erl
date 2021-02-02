%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2015-2019 Couchbase, Inc.
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
-module(service_stats_collector).

-include("ns_common.hrl").
-include("ns_stats.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([service_prefix/1,
         service_event_name/1,
         global_stat/2,
         per_item_stat/3]).

service_prefix(Service) ->
    "@" ++ atom_to_list(Service:get_type()) ++ "-".

service_event_name(Service) ->
    "@" ++ atom_to_list(Service:get_type()).

per_item_stat(Service, Item, Metric) ->
    iolist_to_binary([atom_to_list(Service:get_type()), $/, Item, $/, Metric]).

global_stat(Service, StatName) ->
    iolist_to_binary([atom_to_list(Service:get_type()), $/, StatName]).
