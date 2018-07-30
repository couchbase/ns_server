%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-2018 Couchbase, Inc.
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

%% @doc helpers related to ports exposed by various revices

-module(service_ports).

-export([find_by_rest_name/1,
         rest_name/1,
         service_ports/1,
         service_ports_config_name/1,
         get_external_host_and_ports/3]).

-include("ns_common.hrl").

-record(port, {config, rest, service}).
-define(define_port(ConfName, RestName, Service),
        #port{config  = ConfName,
              rest    = <<??RestName>>,
              service = Service}).
all_ports() ->
    [%% rest service ports
     ?define_port(rest_port, mgmt, rest),
     ?define_port(ssl_rest_port, mgmtSSL, rest),
     %% kv service ports
     ?define_port(memcached_port, kv, kv),
     ?define_port(memcached_ssl_port, kvSSL, kv),
     ?define_port(capi_port, capi, kv),
     ?define_port(ssl_capi_port, capiSSL, kv),
     ?define_port(projector_port, projector, kv),
     %% query service ports
     ?define_port(query_port, n1ql, n1ql),
     ?define_port(ssl_query_port, n1qlSSL, n1ql),
     %% index service ports
     ?define_port(indexer_admin_port, indexAdmin, index),
     ?define_port(indexer_scan_port, indexScan, index),
     ?define_port(indexer_http_port, indexHttp, index),
     ?define_port(indexer_https_port, indexHttps, index),
     ?define_port(indexer_stinit_port, indexStreamInit, index),
     ?define_port(indexer_stcatchup_port, indexStreamCatchup, index),
     ?define_port(indexer_stmaint_port, indexStreamMaint, index),
     %% fts service ports
     ?define_port(fts_http_port, fts, fts),
     ?define_port(fts_ssl_port, ftsSSL, fts),
     %% eventing service ports
     ?define_port(eventing_http_port, eventingAdminPort, eventing),
     ?define_port(eventing_https_port, eventingSSL, eventing),
     ?define_port(eventing_debug_port, eventingDebug, eventing),
     %% cbas service ports
     ?define_port(cbas_http_port, cbas, cbas),
     ?define_port(cbas_admin_port, cbasAdmin, cbas),
     ?define_port(cbas_cc_http_port, cbasCc, cbas),
     ?define_port(cbas_ssl_port, cbasSSL, cbas),
     %% miscellaneous cbas ports
     ?define_port(cbas_cluster_port, cbasCluster, misc),
     ?define_port(cbas_cc_cluster_port, cbasCcCluster, misc),
     ?define_port(cbas_cc_client_port, cbasCcClient, misc),
     ?define_port(cbas_console_port, cbasConsole, misc),
     ?define_port(cbas_data_port, cbasData, misc),
     ?define_port(cbas_result_port, cbasResult, misc),
     ?define_port(cbas_messaging_port, cbasMessaging, misc),
     ?define_port(cbas_debug_port, cbasDebug, misc),
     ?define_port(cbas_parent_port, cbasParent, misc),
     ?define_port(cbas_replication_port, cbasReplication, misc)].

service_ports(Service) ->
    [{P#port.config, P#port.rest} ||
     P <- all_ports(), P#port.service =:= Service].

service_ports_config_name(Service) ->
    [C || {C, _} <- service_ports(Service)].

find_by_rest_name(RestName) when is_atom(RestName) ->
    find_by_rest_name(atom_to_binary(RestName, latin1));
find_by_rest_name(RestName) when is_list(RestName) ->
    find_by_rest_name(list_to_binary(RestName));
find_by_rest_name(RestName) when is_binary(RestName) ->
    case lists:keyfind(RestName, #port.rest, all_ports()) of
        false ->
            undefined;
        Port ->
            Port#port.config
    end.

rest_name(Key) ->
    Port = lists:keyfind(Key, #port.config, all_ports()),
    Port#port.rest.

get_internal_ports(Node, Config) ->
    Services = ns_cluster_membership:node_active_services(Config, Node),
    lists:map(
      fun ({P, PN}) ->
              PortKey = find_by_rest_name(P),
              true = PortKey =/= undefined,
              {PortKey, PN}
      end, bucket_info_cache:build_services(Node, Config, Services)).

get_external_host_and_ports(Node, Config, WantedPorts) ->
    External = ns_config:search_node_prop(Node, Config,
                                          alternate_addresses, external,
                                          []),
    Hostname = proplists:get_value(hostname, External),
    Ports = case proplists:get_value(ports, External, []) of
                [] when Hostname =/= undefined ->
                    get_internal_ports(Node, Config);
                P ->
                    P
            end,
    {Hostname, filter_rename_ports(Ports, WantedPorts)}.

filter_rename_ports([], _WantedPorts) -> [];
filter_rename_ports(Ports, WantedPorts) ->
    lists:filtermap(
      fun (ConfigName) ->
              case lists:keyfind(ConfigName, 1, Ports) of
                  false ->
                      false;
                  {ConfigName, Value} ->
                      {true, {rest_name(ConfigName), Value}}
              end
      end, WantedPorts).
