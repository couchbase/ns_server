%% @author Couchbase <info@couchbase.com>
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
-module(project_intact).

-export([is_node_vulnerable/1, default_config/0]).

is_node_vulnerable(Node) ->
    is_node_vulnerable(ns_config:latest(), Node).

is_node_vulnerable(Config, Node) ->
    is_forced_all_vulnerable(Config) orelse
        ns_config:search_node_with_default(Node, Config,
                                           is_vulnerable_key(), true).

default_config() ->
    [{{node, node(), is_vulnerable_key()}, false}].

%% internal
is_vulnerable_key() ->
    config_key(is_vulnerable).

config_key(Name) ->
    {project_intact, Name}.

is_forced_all_vulnerable(Config) ->
    ns_config:search(Config,
                     config_key(force_all_vulnerable), false).
