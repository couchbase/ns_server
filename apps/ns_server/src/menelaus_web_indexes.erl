%% @author Couchbase <info@couchbase.com>
%% @copyright 2015-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(menelaus_web_indexes).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").
-export([handle_settings_get/1, handle_settings_post/1, handle_index_status/1,
         apply_indexes_settings/2, validate_storage_mode/2]).

handle_settings_get(Req) ->
    Settings = get_settings(),
    true = (Settings =/= undefined),
    menelaus_util:reply_json(Req, {Settings}).

enterprise_only_settings() ->
    [redistributeIndexes, enablePageBloomFilter].

serverless_only_settings() ->
    [memHighThreshold, memLowThreshold,
     unitsHighThreshold, unitsLowThreshold] ++
    rebalance_blob_storage_params().

maybe_filter_settings(Settings) ->
    FilterOutSettings =
        lists:flatten([enterprise_only_settings() ||
                       not cluster_compat_mode:is_enterprise()] ++
                      [serverless_only_settings() ||
                       not config_profile:is_serverless()]),
    maybe_filter_settings(Settings, FilterOutSettings).

maybe_filter_settings(Settings, []) ->
    Settings;
maybe_filter_settings(Settings, FilterOutSettings) ->
    lists:filter(
      fun( {Key, _Value}) ->
              not lists:member(Key, FilterOutSettings)
      end, Settings).

get_settings() ->
    Settings =
        index_settings_manager:get(generalSettings) ++
        [{storageMode, index_settings_manager:get(storageMode)}],
    maybe_filter_settings(Settings).

rebalance_blob_storage_params() ->
    [blobStorageScheme, blobStorageBucket, blobStoragePrefix, blobStorageRegion].

valid_rebalance_blob_storage_param(blobStorageScheme, State) ->
    validator:one_of(blobStorageScheme, ["s3"], State);
valid_rebalance_blob_storage_param(_Param, State) ->
    State.

rebalance_blob_storage_params_validator() ->
    Params = rebalance_blob_storage_params(),

    % Validation should pass if:
    % 1. None of the rebalanceBlobStorage Params are present.
    % 2. Or if all of the rebalanceBlobStorage Params are present and are all
    %    valid.
    [validator:validate_multiple(
       fun (_Values, State) ->
               NewState =
                   functools:chain(
                     State,
                     lists:foldr(
                       fun (Param, Acc) ->
                               [validator:required(Param, _),
                                validator:string(Param, _),
                                valid_rebalance_blob_storage_param(Param, _),
                                validator:convert(
                                  Param, fun list_to_binary/1, _)
                                | Acc]
                       end, [], Params)),
               {ok, NewState}
       end, Params, _)].

settings_post_validators() ->
    [validator:integer(indexerThreads, 0, 1024, _),
     validator:integer(memorySnapshotInterval, 1, max_uint64, _),
     validator:integer(stableSnapshotInterval, 1, max_uint64, _),
     validator:integer(maxRollbackPoints, 1, max_uint64, _),
     validator:integer(numReplica, 0, 16, _)] ++
        case cluster_compat_mode:is_enterprise() of
            true ->
                [validator:boolean(redistributeIndexes, _),
                 validator:boolean(enablePageBloomFilter, _)];
            false ->
                []
        end ++
        case cluster_compat_mode:is_cluster_76() of
            true ->
                case config_profile:is_serverless() of
                    true -> [validator:integer(memHighThreshold, 0, 100, _),
                             validator:integer(memLowThreshold, 0, 100, _),
                             validator:integer(unitsHighThreshold, 0, 100, _),
                             validator:integer(unitsLowThreshold, 0, 100, _)] ++
                                rebalance_blob_storage_params_validator();
                    false -> []
                end ++ %% 7.6 + ANY deployment model
                    [validator:boolean(enableShardAffinity, _)];
            false ->
                []
        end ++
        case cluster_compat_mode:is_cluster_79() of
            true ->
                [validator:boolean(deferBuild, _)];
            false ->
                []
        end ++
        [validate_param(logLevel, logLevel, _),
         validate_storage_mode(storageMode, _)].

validate_storage_mode(Name, State) ->
    %% Note, at the beginning the storage mode will be empty. Once set,
    %% validate_param will prevent user from changing it back to empty
    %% since it is not one of the acceptable values.
    State1 = validate_param(Name, storageMode, State),

    %% Do not allow:
    %% - setting index storage mode to mem optimized or plasma in community edition
    %% - changing index storage mode in community edition
    %% - changing index storage mode when there are nodes running index
    %%   service in the cluster in enterprise edition.
    %% - changing index storage mode back to forestdb after having it set to either
    %%   memory_optimized or plasma in enterprise edition.
    %% - setting the storage mode to forestdb on a newly configured 5.0 enterprise cluster.
    IndexErr = "Changing the optimization mode of global indexes is not supported when index service nodes are present in the cluster. Please remove all index service nodes to change this option.",

    OldValue = index_settings_manager:get(Name),
    validator:validate(
      fun (Value) when Value =:= OldValue ->
              ok;
          (Value) ->
              case OldValue =:= <<"">> of
                  true ->
                      is_storage_mode_acceptable(Value);
                  false ->
                      %% Note it is not sufficient to check service_active_nodes(index) because the
                      %% index nodes could be down or failed over. However, we should allow the
                      %% storage mode to be changed if there is an index node in "inactiveAdded"
                      %% state (the state set when a node has been added but the rebalance has not
                      %% been run yet).
                      NodesWanted = ns_node_disco:nodes_wanted(),
                      AllIndexNodes = ns_cluster_membership:service_nodes(NodesWanted, index),
                      InactiveAddedNodes = ns_cluster_membership:inactive_added_nodes(),
                      IndexNodes = AllIndexNodes -- InactiveAddedNodes,

                      case IndexNodes of
                          [] ->
                              is_storage_mode_acceptable(Value);
                          _ ->
                              ?log_debug("Index nodes ~p present. Cannot change index storage mode.~n",
                                         [IndexNodes]),
                              {error, IndexErr}
                      end
              end
      end, Name, State1).

is_storage_mode_acceptable(Value) ->
    ReportError = fun(Msg) ->
                          ?log_debug(Msg),
                          {error, Msg}
                  end,

    case Value of
        ?INDEX_STORAGE_MODE_FORESTDB ->
            case cluster_compat_mode:is_enterprise() of
                true ->
                    ReportError("Storage mode cannot be set to 'forestdb' in 5.0 enterprise edition.");
                false ->
                    ok
            end;
        ?INDEX_STORAGE_MODE_MEMORY_OPTIMIZED ->
            case cluster_compat_mode:is_enterprise() of
                true ->
                    ok;
                false ->
                    ReportError("Memory optimized indexes are restricted to enterprise edition and "
                                "are not available in the community edition.")
            end;
        ?INDEX_STORAGE_MODE_PLASMA ->
            case cluster_compat_mode:is_enterprise() of
                true ->
                    ok;
                false ->
                    ReportError("Storage mode can be set to 'plasma' only if the cluster is "
                                "5.0 enterprise edition.")
            end;
        _ ->
            ReportError(io_lib:format("Invalid value '~s'", [binary_to_list(Value)]))
    end.

acceptable_values(logLevel) ->
    ["silent", "fatal", "error", "warn", "info", "verbose", "timing", "debug",
     "trace"];
acceptable_values(storageMode) ->
    Modes = case cluster_compat_mode:is_enterprise() of
                true ->
                    [?INDEX_STORAGE_MODE_PLASMA,
                     ?INDEX_STORAGE_MODE_MEMORY_OPTIMIZED];
                false ->
                    [?INDEX_STORAGE_MODE_FORESTDB]
            end,
    [binary_to_list(X) || X <- Modes].

validate_param(Name, InternalName, State) ->
    functools:chain(
      State,
      [validator:one_of(Name, acceptable_values(InternalName), _),
       validator:convert(Name, fun list_to_binary/1, _)]).

update_storage_mode(Req, Values) ->
    case proplists:get_value(storageMode, Values) of
        undefined ->
            Values;
        StorageMode ->
            ok = update_settings(storageMode, StorageMode),
            ns_audit:modify_index_storage_mode(Req, StorageMode),
            proplists:delete(storageMode, Values)
    end.
update_settings(Key, Value) ->
    case index_settings_manager:update(Key, Value) of
        {ok, _} ->
            ok;
        retry_needed ->
            erlang:error(exceeded_retries)
    end.

handle_settings_post(Req) ->
    validator:handle(
      fun (Values) ->
              apply_indexes_settings(Req, Values),
              menelaus_util:reply_json(Req, {get_settings()})
      end, Req, form,
      settings_post_validators() ++
          [validator:has_params(_),
           validator:no_duplicate_keys(_),
           validator:unsupported(_)]).

apply_indexes_settings(Req, Values) ->
    Values1 = update_storage_mode(Req, Values),
    case Values1 of
        [] ->
            ok;
        _ ->
            ok = update_settings(generalSettings, Values1),
            ns_audit:settings(Req, modify_index, Values1)
    end.

filter_indexes(Roles, Indexes) ->
    lists:filter(
      fun (Index) ->
              B = binary_to_list(proplists:get_value(bucket, Index)),
              {S, C} = {binary_to_list(proplists:get_value(scope, Index)),
                        binary_to_list(proplists:get_value(collection, Index))},
              menelaus_roles:is_allowed(
                {[{collection, [B, S, C]}, n1ql, index], read}, Roles)
      end, Indexes).

handle_index_status(Req) ->
    AuthnRes = menelaus_auth:get_authn_res(Req),
    Roles = menelaus_roles:get_compiled_roles(AuthnRes),
    {ok, Indexes, Stale, Version} = service_index:get_indexes(),
    Filtered = filter_indexes(Roles, Indexes),

    Warnings =
        case Stale of
            true ->
                Msg = <<"Cannot communicate with indexer process. "
                        "Information on indexes may be stale. Will retry.">>,
                [Msg];
            false ->
                []
        end,

    menelaus_util:reply_json(Req, {[{indexes, [{I} || I <- Filtered]},
                                    {version, Version},
                                    {warnings, Warnings}]}).
