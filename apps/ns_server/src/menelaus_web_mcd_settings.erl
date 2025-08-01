%% @author Couchbase <info@couchbase.com>
%% @copyright 2014-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(menelaus_web_mcd_settings).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([handle_global_get/1,
         handle_effective_get/2,
         handle_global_post/1,
         handle_global_delete/2,
         handle_node_get/2,
         handle_node_post/2,
         handle_node_setting_get/3,
         handle_node_setting_delete/3,
         config_upgrade_to_79/1,
         config_upgrade_to_morpheus/1]).

-import(menelaus_util,
        [reply_json/2,
         reply_json/3]).

%% We are encoding our base64 parameters directly into the config rather than
%% storing the raw value. This lets us handle parameters on this node even if
%% other nodes in the cluster are an older version correctly, as the base64
%% encoded version will still be sent to memcached on those nodes, rather than
%% a non-encoded version.
-define(BASE64_PARAMS, [dcp_disconnect_when_stuck_name_regex]).

%% Updates to these settings go to the '{node, node(), memcached}' or
%% 'memcached' keys depending on whether the write is per-node or global.
%% These change values of keys in memcached.json.

supported_setting_names() ->
    [{max_connections, {int, 2000, ?MAX_32BIT_SIGNED_INT}},
     {num_reader_threads, fun validate_num_threads/1},
     {num_writer_threads, fun validate_num_threads/1},
     {num_auxio_threads, fun validate_num_storage_auxio_nonio_threads/1},
     {num_nonio_threads, fun validate_num_storage_auxio_nonio_threads/1},
     {num_storage_threads, fun validate_num_storage_auxio_nonio_threads/1},
     {system_connections, {int, 1000, ?MAX_32BIT_SIGNED_INT}},
     {verbosity, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {ssl_cipher_list, string},
     {connection_idle_time, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {breakpad_enabled, bool},
     {breakpad_minidump_dir_path, string},
     {dedupe_nmvb_maps, bool},
     {tracing_enabled, bool},
     {datatype_snappy, bool},
     {tcp_keepalive_idle, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {tcp_keepalive_interval, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {tcp_keepalive_probes, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {tcp_user_timeout, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {free_connection_pool_size, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {max_client_connection_details, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {fusion_migration_rate_limit, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {fusion_sync_rate_limit, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {dcp_consumer_max_marker_version, {one_of, ["2.0", "2.2"]}},
     {dcp_snapshot_marker_hps_enabled, bool},
     {dcp_snapshot_marker_purge_seqno_enabled, bool}]
        ++
        %% KV stopped supporting this is 7.6, they just ignore it, but we
        %% should probably support it in mixed mode. Even though we "support" it
        %% in the API, we will not actually set it in the memcached config on
        %% this node, just the other older nodes.
        case cluster_compat_mode:is_cluster_79() of
            true -> [];
            false ->
                [{connection_limit_mode, {one_of, ["disconnect", "recycle"]}}]
        end.

%% Updates to these settings go to the '{node, node(), memcached_config_extra}'
%% or 'memcached_config_extra' keys depending on whether the write is per-node
%% or global. These add new keys to memcached.json.

supported_extra_setting_names() ->
    [{default_reqs_per_event, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {reqs_per_event_high_priority, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {reqs_per_event_med_priority, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {reqs_per_event_low_priority, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {threads, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {dcp_disconnect_when_stuck_timeout_seconds,
      {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {dcp_disconnect_when_stuck_name_regex, string},
     {external_auth_request_timeout, {int, 0, ?MAX_32BIT_SIGNED_INT}},
     {not_locked_returns_tmpfail, bool},
     {clustermap_push_notifications_enabled, bool},
     {magma_blind_write_optimisation_enabled, bool}].

supported_nodes() ->
    ns_node_disco:nodes_wanted().

parse_validate_node("self") ->
    parse_validate_node(atom_to_list(node()));
parse_validate_node(Name) ->
    NodesWantedS = [atom_to_list(N) || N <- supported_nodes()],
    case lists:member(Name, NodesWantedS) of
        false ->
            unknown;
        true ->
            {ok, list_to_atom(Name)}
    end.

with_parsed_node(Name, Req, Body) ->
    case parse_validate_node(Name) of
        unknown ->
            reply_json(Req, [], 404);
        {ok, Node} ->
            Body(Node)
    end.

handle_global_get(Req) ->
    handle_get(Req, memcached, memcached_config_extra, 200).

handle_effective_get(Name, Req) ->
    with_parsed_node(
      Name, Req,
      fun (Node) ->
              KVsGlobal = build_setting_kvs(memcached, memcached_config_extra),
              KVsLocal = build_setting_kvs({node, Node, memcached},
                                           {node, Node, memcached_config_extra}),
              KVsDefault = build_setting_kvs({node, Node, memcached_defaults},
                                             erlang:make_ref()),
              KVs = lists:foldl(
                      fun ({K, V}, Acc) ->
                              lists:keystore(K, 1, Acc, {K, V})
                      end, [], lists:append([KVsDefault, KVsGlobal, KVsLocal])),
              reply_json(Req, {KVs}, 200)
      end).

handle_node_get(Name, Req) ->
    with_parsed_node(
      Name, Req,
      fun (Node) ->
              handle_get(Req,
                         {node, Node, memcached},
                         {node, Node, memcached_config_extra},
                         200)
      end).

map_settings(SettingNames, Settings) ->
    lists:flatmap(
      fun ({Name, _}) ->
              case lists:keyfind(Name, 1, Settings) of
                  false ->
                      [];
                  {_, Value0} ->
                      Value =
                          case lists:member(Name, ?BASE64_PARAMS) of
                              true ->
                                  base64:decode(Value0);
                              false ->
                                  case is_list(Value0) of
                                      true ->
                                          list_to_binary(Value0);
                                      false ->
                                          Value0
                                  end
                          end,
                      [{Name, Value}]
              end
      end, SettingNames).

build_setting_kvs(SettingsKey, ExtraConfigKey) ->
    {value, McdSettings} = ns_config:search(ns_config:latest(), SettingsKey),
    ExtraSettings = ns_config:search(ns_config:latest(), ExtraConfigKey, []),
    map_settings(supported_setting_names(), McdSettings)
        ++ map_settings(supported_extra_setting_names(), ExtraSettings).

handle_get(Req, SettingsKey, ExtraConfigKey, Status) ->
    KVs = build_setting_kvs(SettingsKey, ExtraConfigKey),
    reply_json(Req, {KVs}, Status).

handle_global_post(Req) ->
    handle_post(Req, memcached, memcached_config_extra).

handle_node_post(Name, Req) ->
    with_parsed_node(
      Name, Req,
      fun (Node) ->
              handle_post(Req,
                          {node, Node, memcached},
                          {node, Node, memcached_config_extra})
      end).

handle_post(Req, SettingsKey, ExtraConfigKey) ->
    KnownNames = lists:map(fun ({A, _}) -> atom_to_list(A) end,
                           supported_setting_names() ++ supported_extra_setting_names()),
    Params = mochiweb_request:parse_post(Req),
    UnknownParams = [K || {K, _} <- Params,
                          not lists:member(K, KnownNames)],
    case UnknownParams of
        [] ->
            continue_handle_post(Req, Params, SettingsKey, ExtraConfigKey);
        _ ->
            Msg = io_lib:format("Unknown POST parameters: ~p", [UnknownParams]),
            reply_json(Req, {[{'_', iolist_to_binary(Msg)}]}, 400)
    end.

validate_param(Value, {int, Min, Max}) ->
    menelaus_util:parse_validate_number(Value, Min, Max);
validate_param(Value, bool) ->
    case Value of
        "true" ->
            {ok, true};
        "false" ->
            {ok, false};
        _->
            <<"must be either true or false">>
    end;
validate_param(Value, string) ->
    {ok, Value};
validate_param(Value, {one_of, Values}) ->
    case lists:member(Value, Values) of
        true -> {ok, list_to_binary(Value)};
        false -> list_to_binary(io_lib:format("must be one of: [~s]",
                                              [string:join(Values, ", ")]))
    end;
validate_param(Value, Fun) when is_function(Fun, 1) ->
    Fun(Value).

%% Support "default" for backwards compatibility.
validate_num_threads("default") -> {ok, <<"balanced">>};
validate_num_threads("disk_io_optimized") -> {ok, <<"disk_io_optimized">>};
validate_num_threads("balanced") -> {ok, <<"balanced">>};
validate_num_threads(Value) -> validate_param(Value, {int, 1, 64}).

validate_num_storage_auxio_nonio_threads("default") -> {ok, <<"default">>};
validate_num_storage_auxio_nonio_threads(Value) -> validate_param(Value, {int, 1, 64}).

continue_handle_post(Req, Params, SettingsKey, ExtraConfigKey) ->
    ParsedParams =
        lists:flatmap(
          fun ({Name, ValidationType}) ->
                  NameString = atom_to_list(Name),
                  case lists:keyfind(NameString, 1, Params) of
                      false ->
                          [];
                      {_, Value} ->
                          [{Name, validate_param(Value, ValidationType)}]
                  end
          end, supported_setting_names() ++ supported_extra_setting_names()),
    InvalidParams = [{K, V} || {K, V} <- ParsedParams,
                               case V of
                                   {ok, _} -> false;
                                   _ -> true
                               end],
    case InvalidParams of
        [_|_] ->
            reply_json(Req, {InvalidParams}, 400);
        [] ->
            KVs0 = [{K, V} || {K, {ok, V}} <- ParsedParams],
            %% We are encoding our base64 parameters directly into the config
            %% rather than storing the raw value. This lets us handle parameters
            %% on this node even if other nodes in the cluster are an older
            %% version correctly, as the base64 encoded version will still be
            %% sent to memcached on those nodes, rather than a non-encoded
            %% version.
            KVs = lists:map(
                    fun ({Name, Value}) ->
                            case lists:member(Name, ?BASE64_PARAMS) of
                                true ->
                                    {Name, base64:encode(Value)};
                                false ->
                                    {Name, Value}
                            end
                    end, KVs0),
            {OS, NS} = case update_config(
                              supported_setting_names(), SettingsKey, KVs) of
                           {commit, _, {OS0, NS0}} ->
                               {OS0, NS0};
                           _ ->
                               {[], []}
                       end,
            {EOS, ENS} = case update_config(
                                supported_extra_setting_names(),
                                ExtraConfigKey, KVs) of
                             {commit, _, {EOS0, ENS0}} ->
                                 {EOS0, ENS0};
                             _ ->
                                 {[], []}
                         end,
            %% Merge both the old settings and extra old settings, so that we
            %% can add a single event log.
            OldSettings = OS ++ EOS,
            NewSettings = NS ++ ENS,

            if
                NewSettings =/= [] andalso NewSettings =/= OldSettings ->
                    event_log:add_log(
                      memcached_cfg_changed,
                      [{old_settings, {OldSettings}},
                       {new_settings, {NewSettings}}]);
                true ->
                    ok
            end,

            handle_get(Req, SettingsKey, ExtraConfigKey, 202)
    end.

update_config(Settings, ConfigKey, KVs) ->
    ns_config:run_txn(
      fun (OldConfig, SetFn) ->
              OldValue = ns_config:search(OldConfig, ConfigKey, []),
              NewValue =
                  lists:foldl(
                    fun ({K, V}, NewValue0) ->
                            case lists:keyfind(K, 1, Settings) =/= false of
                                true ->
                                    lists:keystore(K, 1, NewValue0, {K, V});
                                _ ->
                                    NewValue0
                            end
                    end, OldValue, KVs),
              NewConfig = case NewValue =/= OldValue of
                              true ->
                                  SetFn(ConfigKey, NewValue, OldConfig);
                              _ ->
                                  OldConfig
                          end,
              {commit, NewConfig, {OldValue, NewValue}}
      end).

handle_node_setting_get(NodeName, SettingName, Req) ->
    with_parsed_node(
      NodeName, Req,
      fun (Node) ->
              KVs = build_setting_kvs({node, Node, memcached},
                                      {node, Node, memcached_config_extra}),
              MaybeProp = [V || {K, V} <- KVs,
                                atom_to_list(K) =:= SettingName],
              case MaybeProp of
                  [] ->
                      reply_json(Req, [], 404);
                  [Value] ->
                      reply_json(Req, {[{value, Value}]})
              end
      end).

handle_global_delete(Setting, Req) ->
    %% global delete only supports the extra settings, these are settings that
    %% we can add, so we should be able to delete them. The other settings are
    %% always present in the global config, so we should not allow their
    %% deletion.
    MaybeExtra = [K || {K, _} <- supported_extra_setting_names(),
                       atom_to_list(K) =:= Setting],
    case MaybeExtra of
        [] ->
            Msg = io_lib:format("Unknown/unsupported setting: ~p", [Setting]),
            reply_json(Req, {[{'_', iolist_to_binary(Msg)}]}, 404);
        _ ->
            case do_delete_txn(memcached_config_extra, hd(MaybeExtra)) of
                ok ->
                    reply_json(Req, [], 202);
                missing ->
                    reply_json(Req, [], 404)
            end
    end.

handle_node_setting_delete(NodeName, SettingName, Req) ->
    with_parsed_node(
      NodeName, Req,
      fun (Node) ->
              case perform_delete_txn(Node, SettingName) of
                  ok ->
                      reply_json(Req, [], 202);
                  missing ->
                      reply_json(Req, [], 404)
              end
      end).

perform_delete_txn(Node, SettingName) ->
    MaybeSetting = [K || {K, _} <- supported_setting_names(),
                         atom_to_list(K) =:= SettingName],
    MaybeExtra = [K || {K, _} <- supported_extra_setting_names(),
                       atom_to_list(K) =:= SettingName],
    if
        MaybeSetting =/= [] ->
            do_delete_txn({node, Node, memcached}, hd(MaybeSetting));
        MaybeExtra =/= [] ->
            do_delete_txn({node, Node, memcached_config_extra}, hd(MaybeExtra));
        true ->
            missing
    end.

do_delete_txn(Key, Setting) ->
    RV =
        ns_config:run_txn(
          fun (Config, SetFn) ->
                  OldValue = ns_config:search(Config, Key, []),
                  NewValue = lists:keydelete(Setting, 1, OldValue),
                  case OldValue =:= NewValue of
                      true ->
                          {abort, []};
                      false ->
                          {commit, SetFn(Key, NewValue, Config)}
                  end
          end),
    case RV of
        {abort, _} ->
            missing;
        {commit, _} ->
            ok
    end.

config_upgrade_to_79(Config) ->
    config_upgrade_to_79_global_memcached_cfg(Config) ++
    config_upgrade_to_79_node_memcached_cfg(Config).

config_upgrade_to_79_global_memcached_cfg(Config) ->
    case ns_config:search(Config, memcached) of
        false -> [];
        {value, Value} ->
            case proplists:get_value(connection_limit_mode, Value) of
                undefined -> [];
                _ ->
                    [{set, memcached,
                         proplists:delete(connection_limit_mode, Value)}]
            end

    end.

config_upgrade_to_79_node_memcached_cfg(Config) ->
    lists:foldl(
        fun(Node, Acc) ->
            NodeMcdCfg = ns_config:search(Config, {node, Node, memcached}, []),
            case NodeMcdCfg of
                [] -> Acc;
                Value ->
                    case proplists:get_value(connection_limit_mode, Value) of
                        undefined -> Acc;
                        _ ->
                            [{set, {node, Node, memcached},
                              proplists:delete(connection_limit_mode, Value)}
                            | Acc]
                    end
            end
        end, [], supported_nodes()).

config_upgrade_to_morpheus(Config) ->
    %% We want to enable the magma blind write optimisation by default for all
    %% 8.0 clusters. We have a get_param though such that we can turn this off
    %% prior to the upgrade just in case.
    EnableMagmaBlindWriteOptimisation =
        [{magma_blind_write_optimisation_enabled,
          ?get_param(magma_blind_write_optimisation_enabled, true)}],
    case ns_config:search(Config, memcached) of
        false ->
            %% This key really should exist...
            [{set, memcached, EnableMagmaBlindWriteOptimisation}];
        {value, Value} ->
            %% Merge the new setting into the existing memcached config...
            [{set, memcached,
              misc:update_proplist(Value, EnableMagmaBlindWriteOptimisation)}]
    end.

-ifdef(TEST).
upgrade_config_test_setup() ->
    ns_config_default:ns_config_default_mock_setup(),

    %% We upgrade node keys so we need to mock the method we use to get the
    %% nodes list.
    meck:new(ns_node_disco),
    meck:expect(ns_node_disco, nodes_wanted,
                fun () -> [node()] end),

    meck:new(ns_config, [passthrough]),
    meck:expect(ns_config, search_node_with_default,
                fun(_, Default) ->
                        Default
                end).

upgrade_config_test_teardown(R) ->
    ns_config_default:ns_config_default_mock_teardown(R),
    meck:unload().

upgrade_config_from_76_to_79_t() ->
    %% We'll use a default config to test, but add some of the older verrsion
    %% values that are relevant to the upgrade.
    Default = ns_config_default:default(?VERSION_79),

    %% Firstly lets add the connection_limit_mode to the global memcached config
    GlobalMcdCfgKey = memcached,
    {GlobalMcdCfgKey, MemcachedCfg} =
        lists:keyfind(GlobalMcdCfgKey, 1, Default),
    NewMemcachedCfg = lists:keystore(connection_limit_mode, 1, MemcachedCfg,
                                     {connection_limit_mode, "disconnect"}),
    TestCfg0 = lists:keystore(GlobalMcdCfgKey, 1, Default,
                              {GlobalMcdCfgKey, NewMemcachedCfg}),

    %% Now, lets add connection_limit_mode to the node specific memcached
    %% config.
    NodeMcdCfgKey = {node, node(), memcached},
    {NodeMcdCfgKey, NodeMcdCfg} = lists:keyfind(NodeMcdCfgKey, 1, TestCfg0),
    NewNodeMcdCfg = lists:keystore(connection_limit_mode, 1, NodeMcdCfg,
                                   {connection_limit_mode, "disconnect"}),
    TestCfg1 = lists:keyreplace(NodeMcdCfgKey, 1, TestCfg0,
                                {NodeMcdCfgKey, NewNodeMcdCfg}),

    Txns = config_upgrade_to_79([TestCfg1]),

    {set, GlobalMcdCfgKey, UpgradedGlobalMcdCfg} =
        lists:keyfind(GlobalMcdCfgKey, 2, Txns),
    ?assertEqual(false,
                 lists:keyfind(connection_limit_mode, 1,
                               UpgradedGlobalMcdCfg)),

    {set, NodeMcdCfgKey, UpgradedNodeMcdCfg} =
        lists:keyfind(NodeMcdCfgKey, 2, Txns),
    ?assertEqual(false,
                 lists:keyfind(connection_limit_mode, 1, UpgradedNodeMcdCfg)).

upgrade_config_to_morpheus_t() ->
    Default = ns_config_default:default(?VERSION_MORPHEUS),

    Txns0 = config_upgrade_to_morpheus([Default]),
    ?assertEqual(
       [{set, memcached,
         [{magma_blind_write_optimisation_enabled, true}]}],
       Txns0),

    DefaultWithoutMcd = proplists:delete(memcached, Default),
    Txns1 = config_upgrade_to_morpheus([DefaultWithoutMcd]),
    ?assertEqual(
       [{set, memcached,
         [{magma_blind_write_optimisation_enabled, true}]}], Txns1),

    meck:expect(ns_config, search_node_with_default,
                fun({_,magma_blind_write_optimisation_enabled}, _) ->
                        false
                end),

    Txns2 = config_upgrade_to_morpheus([DefaultWithoutMcd]),
    ?assertEqual(
       [{set, memcached,
         [{magma_blind_write_optimisation_enabled, false}]}], Txns2).


upgrade_config_test_() ->
    {setup, fun upgrade_config_test_setup/0,
            fun upgrade_config_test_teardown/1,
            [fun upgrade_config_from_76_to_79_t/0,
             fun upgrade_config_to_morpheus_t/0]}.

-endif.
