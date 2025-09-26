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

-export([get_encryption_method/3,
         update_deks/1,
         get_required_usage/1,
         get_deks_lifetime/2,
         get_deks_rotation_interval/2,
         get_drop_deks_timestamp/2,
         get_force_encryption_timestamp/2,
         get_dek_ids_in_use/1,
         initiate_drop_deks/2,
         fetch_chronicle_keys_in_txn/2]).

-spec get_encryption_method(cb_deks:dek_kind(), cluster | node,
                            cb_cluster_secrets:chronicle_snapshot()) ->
              {ok, cb_deks:encryption_method()} | {error, not_found}.
get_encryption_method({bucketDek, BucketUUID}, Scope, Snapshot) ->
    ns_bucket:get_encryption(BucketUUID, Scope, Snapshot).

-spec update_deks(cb_deks:dek_kind()) -> ok | {error, _}.
update_deks({bucketDek, BucketUUID}) ->
    ns_memcached:set_active_dek_for_bucket_uuid(BucketUUID).

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

-spec get_dek_ids_in_use(cb_deks:dek_kind()) ->
          {ok, [cb_deks:dek_id()]} | {error, _}.
get_dek_ids_in_use({bucketDek, BucketUUID}) ->
    ns_memcached:get_dek_ids_in_use(BucketUUID).

-spec initiate_drop_deks(cb_deks:dek_kind(), [cb_deks:dek_id()]) ->
          {ok, done | started} | {error, not_found | retry | _}.
initiate_drop_deks({bucketDek, BucketUUID}, DekIds) ->
    Continuation = fun (_) ->
                       cb_cluster_secrets:dek_drop_complete(
                           {bucketDek, BucketUUID}, ok)
                   end,
    ns_memcached:drop_deks(BucketUUID, DekIds, cb_cluster_secrets,
                           Continuation).

-spec fetch_chronicle_keys_in_txn(cb_deks:dek_kind(), Txn :: term()) ->
          cb_cluster_secrets:chronicle_snapshot().
fetch_chronicle_keys_in_txn({bucketDek, BucketUUID}, Txn) ->
    BucketKeys = ns_bucket:all_keys_by_uuid([BucketUUID],
                                            [props, encr_at_rest, uuid], Txn),
    chronicle_compat:txn_get_many(
        [ns_bucket:root() | BucketKeys] ++
         ns_cluster_membership:node_membership_keys(node()), Txn).