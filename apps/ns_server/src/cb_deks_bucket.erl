%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

-module(cb_deks_bucket).

-behaviour(cb_deks).

-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(CONT_BACKUP_CBAUTH_LABEL, "cbcontbk-cbauth").

-export([get_encryption_method/3,
         update_deks/2,
         get_required_usage/1,
         get_deks_lifetime/2,
         get_deks_rotation_interval/2,
         get_drop_deks_timestamp/2,
         get_force_encryption_timestamp/2,
         get_dek_ids_in_use/2,
         initiate_drop_deks/3,
         synchronize_deks/2,
         fetch_chronicle_keys_in_txn/2,
         dek_consumers/2]).

-spec get_encryption_method(cb_deks:dek_kind(), cluster | node,
                            cb_cluster_secrets:chronicle_snapshot()) ->
              {ok, cb_deks:encryption_method()} | {error, not_found}.
get_encryption_method({bucketDek, BucketUUID}, Scope, Snapshot)
                                            when Scope == cluster;
                                                 Scope == node ->
    maybe
        {ok, BucketName} ?= ns_bucket:uuid2bucket(BucketUUID, Snapshot),
        {ok, BucketConfig} ?= ns_bucket:get_bucket(BucketName, Snapshot),
        %% Meaning of Scope:
        %% When Scope == cluster, we check if encryption for this bucket is
        %% enabled in general.
        %% When Scope == node, we check if this bucket is encrypted on this
        %% node (this node should have DEKs for this bucket)
        case (Scope == cluster) orelse
             bucket_exists_on_node(BucketUUID, Snapshot) of
            true ->
                case proplists:get_value(encryption_secret_id, BucketConfig,
                                         ?SECRET_ID_NOT_SET) of
                    ?SECRET_ID_NOT_SET -> {ok, disabled};
                    Id -> {ok, {secret, Id}}
                end;
            false ->
                {error, not_found}
        end
    else
        not_present ->
            {error, not_found};
        {error, R} ->
            {error, R}
    end.

bucket_exists_on_node(BucketUUID, Snapshot) ->
    maybe
        {ok, BucketName} ?= ns_bucket:uuid2bucket(BucketUUID, Snapshot),
        {ok, BucketConfig} ?= ns_bucket:get_bucket(BucketName, Snapshot),
        IsNodeInServers = lists:member(node(), ns_bucket:get_servers(BucketConfig)),
        IsNodeInServers orelse
            begin %% In case of failed over node the data may still be on disk
                Services = ns_cluster_membership:node_services(Snapshot, node()),
                IsKVNode = lists:member(kv, Services),
                %% Data of a newly added node is left from its previous
                %% membership, it will not be used. Note that a node that is
                %% being removed looks newly added too, as its membership
                %% keys are deleted, and its data will not be used either.
                IsNewNode = ns_cluster_membership:is_newly_added_node(
                              node(), Snapshot),
                Dir = ns_storage_conf:this_node_bucket_dbdir(BucketUUID),
                ExistsOnDisk = filelib:is_dir(Dir),
                IsKVNode andalso not IsNewNode andalso ExistsOnDisk
            end
    else
        %% Bucket is not in config, so even if data is on disk it is not
        %% relevant and can be ignored.
        not_present ->
            false;
        {error, not_found} ->
            false
    end.

-spec update_deks(cb_deks:dek_kind(),
                  cb_cluster_secrets:chronicle_snapshot()) -> ok | {error, _}.
update_deks({bucketDek, BucketUUID} = Kind, Snapshot) ->
    maybe
        %% Push keys to backup first to avoid a theoretical
        %% race when memcached already knows a new key, but
        %% backup haven't received it yet.
        %% In the case where kv has the key but continuous backup does
        %% not it will be handled via retries.
        ok ?= case ns_ports_setup:should_run(cont_backup, Snapshot) of
                  true ->
                      cb_deks_cbauth:call_update_keys_db(
                        Kind, [?CONT_BACKUP_CBAUTH_LABEL], true);
                  false ->
                      ok
              end,
        ok ?= ns_memcached:set_active_dek_for_bucket_uuid(BucketUUID),
        ok
    end.

-spec dek_consumers(cb_deks:dek_kind(),
                    cb_cluster_secrets:chronicle_snapshot()) -> [term()].
dek_consumers(_Kind, Snapshot) ->
    %% Continuous backup is the only bucket dek consumer that has no other
    %% channel for receiving keys (memcached gets them as a part of the bucket
    %% config), so it must be reported here. Otherwise cb_cluster_secrets
    %% doesn't notice that cbcontbk has (re)started, and can skip pushing
    %% keys to it (see call_set_active_cb).
    case ns_ports_setup:should_run(cont_backup, Snapshot) of
        true -> [json_rpc_connection:get_pid(?CONT_BACKUP_CBAUTH_LABEL)];
        false -> []
    end.

-spec get_required_usage(cb_deks:dek_kind()) ->
          cb_cluster_secrets:secret_usage().
get_required_usage({bucketDek, BucketUUID}) ->
    {bucket_encryption, BucketUUID}.

-spec get_deks_lifetime(cb_deks:dek_kind(),
                        cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, undefined | pos_integer()} | {error, not_found}.
get_deks_lifetime({bucketDek, BucketUUID}, Snapshot) ->
    ns_bucket:get_dek_lifetime(BucketUUID, Snapshot).

-spec get_deks_rotation_interval(cb_deks:dek_kind(),
                                 cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, undefined | pos_integer()} | {error, not_found}.
get_deks_rotation_interval({bucketDek, BucketUUID}, Snapshot) ->
    ns_bucket:get_dek_rotation_interval(BucketUUID, Snapshot).

-spec get_drop_deks_timestamp(cb_deks:dek_kind(),
                              cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, undefined | calendar:datetime()} | {error, not_found}.
get_drop_deks_timestamp({bucketDek, BucketUUID}, Snapshot) ->
    ns_bucket:get_drop_keys_timestamp(BucketUUID, Snapshot).

-spec get_force_encryption_timestamp(cb_deks:dek_kind(),
                                    cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, undefined | calendar:datetime()} | {error, not_found}.
get_force_encryption_timestamp({bucketDek, BucketUUID}, Snapshot) ->
    ns_bucket:get_force_encryption_timestamp(BucketUUID, Snapshot).

-spec get_dek_ids_in_use(cb_deks:dek_kind(),
                         cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, [cb_deks:dek_id()]} | {error, _}.
get_dek_ids_in_use({bucketDek, BucketUUID}, Snapshot) ->
    case ns_memcached:get_dek_ids_in_use(BucketUUID) of
        {ok, Ids} ->
            {ok, Ids};
        {error, retry} ->
            {error, retry};
        {error, not_found} ->
            case bucket_exists_on_node(BucketUUID,
                                       Snapshot) of
                true -> {error, not_found};
                false -> {ok, []}
            end
    end.

-spec initiate_drop_deks(cb_deks:dek_kind(), [cb_deks:dek_id()],
                         cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, done | started} | {error, not_found | retry | _}.
initiate_drop_deks({bucketDek, BucketUUID},
                   DekIds, Snapshot) ->
    Continuation = fun (_) ->
                       cb_cluster_secrets:dek_drop_complete(
                           "kv", {bucketDek, BucketUUID}, ok)
                   end,
    case bucket_exists_on_node(BucketUUID, Snapshot) of
        true ->
            ns_memcached:drop_deks(BucketUUID, DekIds, cb_cluster_secrets,
                                   Continuation);
        false ->
            {error, not_found}
    end.

-spec synchronize_deks(cb_deks:dek_kind(),
                      cb_cluster_secrets:chronicle_snapshot()) ->
          ok | {error, _}.
synchronize_deks(_Kind, _Snapshot) ->
    ok.

-spec fetch_chronicle_keys_in_txn(cb_deks:dek_kind(), Txn :: term()) ->
          cb_cluster_secrets:chronicle_snapshot().
fetch_chronicle_keys_in_txn({bucketDek, BucketUUID}, Txn) ->
    BucketKeys = ns_bucket:all_keys_by_uuid([BucketUUID],
                                            [props, encr_at_rest, uuid], Txn),
    chronicle_compat:txn_get_many(
      [ns_bucket:root() | BucketKeys] ++
      ns_cluster_membership:node_membership_keys(node()), Txn).

-ifdef(TEST).

bucket_exists_on_node_test() ->
    UUID = <<"uuid">>,
    Dir = path_config:tempfile("cb_deks_bucket_test", ""),
    meck:new(ns_bucket, [passthrough]),
    meck:new(ns_storage_conf, [passthrough]),
    try
        meck:expect(ns_bucket, uuid2bucket,
                    fun (U, _) when U =:= UUID -> {ok, "b"};
                        (_, _) -> {error, not_found}
                    end),
        meck:expect(ns_storage_conf, this_node_bucket_dbdir,
                    fun (U) when U =:= UUID -> Dir end),
        Snapshot =
            fun (Servers, NodeKVs) ->
                maps:from_list(
                  [{K, {V, rev}} ||
                      {K, V} <- [{ns_bucket:sub_key("b", props),
                                  [{servers, Servers}]} | NodeKVs]])
            end,
        Node = fun (Membership, RecoveryType, Services) ->
                   [{{node, node(), membership}, Membership},
                    {{node, node(), recovery_type}, RecoveryType},
                    {{node, node(), services}, Services}]
               end,
        Active = Node(active, none, [kv]),
        FailedOver = Node(inactiveFailed, none, [kv]),
        Exists = fun (S) -> bucket_exists_on_node(UUID, S) end,

        ?assert(Exists(Snapshot([node()], Active))),
        ?assertNot(bucket_exists_on_node(<<"unknown">>,
                                         Snapshot([node()], Active))),
        ?assertNot(Exists(Snapshot([], FailedOver))),

        ok = file:make_dir(Dir),
        ?assert(Exists(Snapshot([], FailedOver))),
        ?assert(Exists(Snapshot([], Node(inactiveAdded, delta, [kv])))),
        ?assertNot(Exists(Snapshot([], Node(inactiveFailed, none, [index])))),
        %% Newly added node
        ?assertNot(Exists(Snapshot([], Node(inactiveAdded, none, [kv])))),
        %% Node that is being removed, its membership keys are deleted
        ?assertNot(Exists(Snapshot([], [])))
    after
        file:del_dir(Dir),
        meck:unload([ns_bucket, ns_storage_conf])
    end.

-endif.