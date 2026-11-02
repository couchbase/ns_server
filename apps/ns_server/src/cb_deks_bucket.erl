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
        %% Push keys to cbauth consumers (cbcontbk) first, so memcached
        %% doesn't start using a key that a connected cbcontbk doesn't know
        %% about. A missing connection is ignored so cbcontbk being down
        %% doesn't block key rotation: it gets the keys when it connects, and
        %% it retries files with unknown keys until then.
        ok ?= cb_deks_cbauth:update_deks(Kind, Snapshot),
        ok ?= ns_memcached:set_active_dek_for_bucket_uuid(BucketUUID),
        ok
    end.

-spec dek_consumers(cb_deks:dek_kind(),
                    cb_cluster_secrets:chronicle_snapshot()) -> [term()].
dek_consumers(Kind, Snapshot) ->
    %% cbauth consumers are reported by pid, so cb_cluster_secrets notices
    %% when cbcontbk (re)starts and pushes keys to it again (see
    %% call_set_active_cb). Memcached is a constant because it gets keys as a
    %% part of the bucket config after a restart.
    [memcached | cb_deks_cbauth:dek_consumers(Kind, Snapshot)].

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
get_dek_ids_in_use({bucketDek, BucketUUID} = Kind, Snapshot) ->
    case ns_memcached:get_dek_ids_in_use(BucketUUID) of
        {ok, KvIds} ->
            %% cbcontbk must be asked after memcached: magma stops reporting
            %% a dek only after the backup generation that uses it is on
            %% disk, so each dek is seen by at least one of the two calls.
            maybe
                {ok, CbauthIds} ?=
                    cb_deks_cbauth:get_dek_ids_in_use(Kind, Snapshot),
                {ok, lists:uniq(KvIds ++ CbauthIds)}
            end;
        {error, retry} ->
            {error, retry};
        {error, not_found} ->
            case bucket_exists_on_node(BucketUUID,
                                       Snapshot) of
                true -> {error, not_found};
                %% Memcached not knowing the bucket doesn't mean cbauth
                %% consumers don't use its deks (e.g. cbcontbk may still
                %% have backup files)
                false -> cb_deks_cbauth:get_dek_ids_in_use(Kind, Snapshot)
            end
    end.

-spec initiate_drop_deks(cb_deks:dek_kind(), [cb_deks:dek_id()],
                         cb_cluster_secrets:chronicle_snapshot()) ->
          {ok, done | started} | {error, not_found | retry | _}.
initiate_drop_deks({bucketDek, BucketUUID} = Kind,
                   DekIds, Snapshot) ->
    Continuation = fun (_) ->
                       cb_cluster_secrets:dek_drop_complete(
                           "kv", {bucketDek, BucketUUID}, ok)
                   end,
    case bucket_exists_on_node(BucketUUID, Snapshot) of
        true ->
            %% cbauth consumers (cbcontbk) go first because a failed drop is
            %% retried soon, and we don't want to restart compaction in
            %% memcached each time when cbcontbk is unavailable.
            maybe
                {ok, started} ?=
                    cb_deks_cbauth:initiate_drop_deks(Kind, DekIds, Snapshot),
                ns_memcached:drop_deks(BucketUUID, DekIds, cb_cluster_secrets,
                                       Continuation)
            end;
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

-define(TEST_UUID, <<"5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f">>).
-define(TEST_KIND, {bucketDek, ?TEST_UUID}).
-define(TEST_SNAPSHOT, #{}).

-define(MOCKED_MODULES, [cb_deks_cbauth, ns_memcached, ns_bucket]).

setup() ->
    meck:new(?MOCKED_MODULES, [passthrough]),
    meck:expect(ns_bucket, uuid2bucket, fun (_, _) -> {ok, "test"} end),
    meck:expect(ns_bucket, get_bucket, fun (_, _) -> {ok, []} end),
    meck:expect(ns_bucket, get_servers, fun (_) -> [node()] end).

teardown(_) ->
    meck:unload(?MOCKED_MODULES).

%% Makes the mocked calls report themselves to the test process, so tests can
%% check the order of calls to memcached and cbauth consumers
expect_calls(Results) ->
    Self = self(),
    Report = fun (Name) -> Self ! {called, Name}, maps:get(Name, Results) end,
    meck:expect(cb_deks_cbauth, update_deks,
                fun (_, _) -> Report(cbauth_update) end),
    meck:expect(cb_deks_cbauth, get_dek_ids_in_use,
                fun (_, _) -> Report(cbauth_in_use) end),
    meck:expect(cb_deks_cbauth, initiate_drop_deks,
                fun (_, _, _) -> Report(cbauth_drop) end),
    meck:expect(ns_memcached, set_active_dek_for_bucket_uuid,
                fun (_) -> Report(kv_update) end),
    meck:expect(ns_memcached, get_dek_ids_in_use,
                fun (_) -> Report(kv_in_use) end),
    meck:expect(ns_memcached, drop_deks,
                fun (_, _, _, _) -> Report(kv_drop) end).

received_calls() ->
    receive
        {called, Name} -> [Name | received_calls()]
    after 0 ->
        []
    end.

update_deks_test_() ->
    Ok = #{cbauth_update => ok, kv_update => ok},
    {foreach, fun setup/0, fun teardown/1,
     [?_test(begin
                 expect_calls(Ok),
                 ?assertEqual(ok, update_deks(?TEST_KIND, ?TEST_SNAPSHOT)),
                 ?assertEqual([cbauth_update, kv_update], received_calls())
             end),
      ?_test(begin
                 expect_calls(Ok#{cbauth_update => {error, retry}}),
                 ?assertEqual({error, retry},
                              update_deks(?TEST_KIND, ?TEST_SNAPSHOT)),
                 ?assertEqual([cbauth_update], received_calls())
             end)]}.

get_dek_ids_in_use_test_() ->
    Ok = #{kv_in_use => {ok, [<<"a">>, <<"b">>]},
           cbauth_in_use => {ok, [<<"b">>, <<"c">>, ?NULL_DEK]}},
    {foreach, fun setup/0, fun teardown/1,
     [?_test(begin
                 expect_calls(Ok),
                 ?assertEqual({ok, [<<"a">>, <<"b">>, <<"c">>, ?NULL_DEK]},
                              get_dek_ids_in_use(?TEST_KIND, ?TEST_SNAPSHOT)),
                 ?assertEqual([kv_in_use, cbauth_in_use], received_calls())
             end),
      ?_test(begin
                 expect_calls(Ok#{cbauth_in_use => {error, retry}}),
                 ?assertEqual({error, retry},
                              get_dek_ids_in_use(?TEST_KIND, ?TEST_SNAPSHOT))
             end),
      ?_test(begin
                 expect_calls(Ok#{kv_in_use => {error, retry}}),
                 ?assertEqual({error, retry},
                              get_dek_ids_in_use(?TEST_KIND, ?TEST_SNAPSHOT)),
                 ?assertEqual([kv_in_use], received_calls())
             end),
      %% Bucket data is still on the node, so nothing can be removed
      ?_test(begin
                 expect_calls(Ok#{kv_in_use => {error, not_found}}),
                 ?assertEqual({error, not_found},
                              get_dek_ids_in_use(?TEST_KIND, ?TEST_SNAPSHOT)),
                 ?assertEqual([kv_in_use], received_calls())
             end),
      ?_test(begin
                 expect_calls(Ok#{kv_in_use => {error, not_found}}),
                 meck:expect(ns_bucket, uuid2bucket,
                             fun (_, _) -> {error, not_found} end),
                 ?assertEqual({ok, [<<"b">>, <<"c">>, ?NULL_DEK]},
                              get_dek_ids_in_use(?TEST_KIND, ?TEST_SNAPSHOT)),
                 ?assertEqual([kv_in_use, cbauth_in_use], received_calls())
             end)]}.

initiate_drop_deks_test_() ->
    Ok = #{cbauth_drop => {ok, started}, kv_drop => {ok, started}},
    {foreach, fun setup/0, fun teardown/1,
     [?_test(begin
                 expect_calls(Ok),
                 ?assertEqual({ok, started},
                              initiate_drop_deks(?TEST_KIND, [<<"a">>],
                                                 ?TEST_SNAPSHOT)),
                 ?assertEqual([cbauth_drop, kv_drop], received_calls())
             end),
      ?_test(begin
                 expect_calls(Ok#{cbauth_drop => {error, retry}}),
                 ?assertEqual({error, retry},
                              initiate_drop_deks(?TEST_KIND, [<<"a">>],
                                                 ?TEST_SNAPSHOT)),
                 ?assertEqual([cbauth_drop], received_calls())
             end)]}.

-endif.
