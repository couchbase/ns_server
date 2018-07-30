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

-export([default/2,
         default_config/1,
         find_by_rest_name/1,
         service_ports_config_name/1,
         get_external_host_and_ports/3,
         get_ports_for_services/3]).

-include("ns_common.hrl").

-record(port, {config, rest, service, default, secure}).
-define(define_port(ConfName, RestName, Service, Default, Sec),
        #port{config  = ConfName,
              rest    = rest_name_to_bin(RestName),
              service = Service,
              default = Default,
              secure  = Sec}).

-define(define_port(ConfName, RestName, Service, Default),
        ?define_port(ConfName, RestName, Service, Default, unsecure)).

rest_name_to_bin(undefined) ->
    undefined;
rest_name_to_bin(RestName) ->
    atom_to_binary(RestName, latin1).

all_ports() ->
    [%% rest service ports
     ?define_port(rest_port,     mgmt,    rest, 8091),
     ?define_port(ssl_rest_port, mgmtSSL, rest, 18091, secure),
     %% xdcr ports
     ?define_port(xdcr_rest_port, undefined, xdcr, 9998),
     %% kv service ports
     ?define_port(memcached_port,           kv,        kv, 11210),
     ?define_port(memcached_ssl_port,       kvSSL,     kv, 11207, secure),
     ?define_port(memcached_dedicated_port, undefined, kv, 11209),
     ?define_port(capi_port,                capi,      kv, 8092),
     ?define_port(ssl_capi_port,            capiSSL,   kv, 18092, secure),
     ?define_port(projector_port,           projector, kv, 9999),
     %% query service ports
     ?define_port(query_port,     n1ql,    n1ql, 8093),
     ?define_port(ssl_query_port, n1qlSSL, n1ql, 18093, secure),
     %% index service ports
     ?define_port(indexer_admin_port,     indexAdmin,         index, 9100),
     ?define_port(indexer_scan_port,      indexScan,          index, 9101),
     ?define_port(indexer_http_port,      indexHttp,          index, 9102),
     ?define_port(indexer_stinit_port,    indexStreamInit,    index, 9103),
     ?define_port(indexer_stcatchup_port, indexStreamCatchup, index, 9104),
     ?define_port(indexer_stmaint_port,   indexStreamMaint,   index, 9105),
     ?define_port(indexer_https_port,     indexHttps,         index, 19102,
                  secure),
     %% fts service ports
     ?define_port(fts_http_port, fts,    fts, 8094),
     ?define_port(fts_ssl_port,  ftsSSL, fts, 18094, secure),
     %% eventing service ports
     ?define_port(eventing_http_port,  eventingAdminPort, eventing, 8096),
     ?define_port(eventing_debug_port, eventingDebug,     eventing, 9140),
     ?define_port(eventing_https_port, eventingSSL,       eventing, 18096,
                  secure),
     %% cbas service ports
     ?define_port(cbas_http_port,    cbas,      cbas, 8095),
     ?define_port(cbas_admin_port,   cbasAdmin, cbas, 9110),
     ?define_port(cbas_cc_http_port, cbasCc,    cbas, 9111),
     ?define_port(cbas_ssl_port,     cbasSSL,   cbas, 18095, secure),
     %% miscellaneous cbas ports
     ?define_port(cbas_cc_cluster_port,        cbasCcCluster,   misc, 9112),
     ?define_port(cbas_cc_client_port,         cbasCcClient,    misc, 9113),
     ?define_port(cbas_console_port,           cbasConsole,     misc, 9114),
     ?define_port(cbas_cluster_port,           cbasCluster,     misc, 9115),
     ?define_port(cbas_data_port,              cbasData,        misc, 9116),
     ?define_port(cbas_result_port,            cbasResult,      misc, 9117),
     ?define_port(cbas_messaging_port,         cbasMessaging,   misc, 9118),
     ?define_port(cbas_metadata_callback_port, undefined,       misc, 9119),
     ?define_port(cbas_replication_port,       cbasReplication, misc, 9120),
     ?define_port(cbas_metadata_port,          undefined,       misc, 9121),
     ?define_port(cbas_parent_port,            cbasParent,      misc, 9122),
     ?define_port(cbas_debug_port,             cbasDebug,       misc, -1)
    ].

complex_config_key(memcached_port) ->
    true;
complex_config_key(memcached_ssl_port) ->
    true;
complex_config_key(memcached_dedicated_port) ->
    true;
complex_config_key(_) ->
    false.

default(Key, IsEnterprise) ->
    default(Key, lists:keyfind(Key, #port.config, all_ports()), IsEnterprise).

default(_Key, #port{secure = secure}, false = _IsEnterprise) ->
    undefined;
default(Key, #port{default = Default}, _IsEnterprise) ->
    misc:get_env_default(Key, Default).

default_config(#port{config = rest_port, default = Default}, _IsEnterprise) ->
    PortMeta = case application:get_env(rest_port) of
                   {ok, _Port} -> local;
                   undefined -> global
               end,
    [{rest, [{port, Default}]},
     {{node, node(), rest},
      [{port, misc:get_env_default(rest_port, Default)},
       {port_meta, PortMeta}]}];
default_config(#port{config = Key} = P, IsEnterprise) ->
    [{{node, node(), Key}, default(Key, P, IsEnterprise)}].

default_config(IsEnterprise) ->
    lists:flatmap(fun (#port{config = Key} = P) ->
                          case complex_config_key(Key) of
                              true ->
                                  [];
                              false ->
                                  default_config(P, IsEnterprise)
                          end
                  end, all_ports()).

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
      end, get_ports_for_services(Node, Config, Services)).

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

get_ports_for_services(Node, Config, Services) ->
    GetPort = fun (ConfigKey) ->
                      case ns_config:search_node(Node, Config, ConfigKey) of
                          {value, Value} when Value =/= undefined ->
                              case rest_name(ConfigKey) of
                                  undefined ->
                                      [];
                                  JKey ->
                                      [{JKey, Value}]
                              end;
                          _ ->
                              []
                      end
              end,

    GetPortFromProp = fun (ConfigKey, ConfigSubKey, JKey) ->
                              case ns_config:search_node_prop(Node, Config, ConfigKey, ConfigSubKey) of
                                  undefined ->
                                      [];
                                  Port ->
                                      [{JKey, Port}]
                              end
                      end,

    OptServices =
        [case S of
             kv ->
                 %% Special handling needed for kv service.
                 GetPort(ssl_capi_port) ++
                     GetPort(capi_port) ++
                     GetPort(projector_port) ++
                     GetPortFromProp(memcached, ssl_port,
                                     rest_name(memcached_ssl_port)) ++
                     GetPortFromProp(memcached, port,
                                     rest_name(memcached_port));
             example ->
                 [];
             Service ->
                 ServicePorts = service_ports(Service),
                 lists:filtermap(
                   fun ({_, undefined}) ->
                           false;
                       ({ConfigKey, RestKey}) ->
                           case ns_config:search(
                                  Config, {node, Node, ConfigKey}, undefined) of
                               undefined ->
                                   false;
                               Port ->
                                   {true, {RestKey, Port}}
                           end
                   end, ServicePorts)
         end || S <- Services],

    MgmtSSL = GetPort(ssl_rest_port),
    Mgmt = {rest_name(rest_port), misc:node_rest_port(Config, Node)},
    [Mgmt | lists:append([MgmtSSL | OptServices])].
