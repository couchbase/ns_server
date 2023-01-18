%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

-module(hibernation_utils).

-include("ns_common.hrl").
-include("cut.hrl").

-export([run_hibernation_op/3,
         get_snapshot/1,
         set_hibernation_status/2,
         update_hibernation_status/1,
         build_hibernation_task/0,
         unpause_bucket/1,
         unpause_bucket/2,
         sync_s3/3,
         upload_metadata_to_s3/3,
         get_bucket_version/1,
         get_bucket_config/1,
         get_bucket_uuid/1,
         get_bucket_manifest/1,
         get_bucket_metadata_from_s3/1,
         get_data_component_path/0,
         get_bucket_data_component_path/1,
         get_node_data_remote_path/2,
         get_bucket_data_remote_path/3]).

run_hibernation_op(_Body, _Args = [], _Timeout) ->
    ok;
run_hibernation_op(Body, Args, Timeout) ->
    case async:run_with_timeout(
           fun () ->
                   async:foreach(
                     Body, Args, [exit_on_first_error])
           end, Timeout) of
        {ok, Result} ->
            Result;
        {error, timeout} ->
            exit(timeout)
    end.

get_snapshot(Bucket) ->
    chronicle_compat:get_snapshot(
      [ns_bucket:fetch_snapshot(Bucket, _),
       ns_cluster_membership:fetch_snapshot(_)]).

get_hibernation_status(Snapshot) ->
    chronicle_compat:get(Snapshot, hibernation_status, #{default => undefined}).

set_hibernation_status(Bucket, Status) ->
    chronicle_compat:set_multiple(
      [{hibernation_status, Status},
       {hibernation_uuid, couch_uuids:random()},
       {hibernation_bucket, Bucket}]).

update_hibernation_status(Status) ->
    chronicle_kv:transaction(
      kv, [hibernation_status],
      fun (Snapshot) ->
              case get_hibernation_status(Snapshot) of
                  {Op, running} ->
                      {commit, [{set, hibernation_status, {Op, Status}}]};
                  _ ->
                      {abort, ok}
              end
      end),
    ok.

keys() ->
    [hibernation_status, hibernation_uuid, hibernation_bucket].

fetch_snapshot(Txn) ->
    chronicle_compat:txn_get_many(keys(), Txn).

build_task_prop(_, undefined) ->
    [];
build_task_prop(hibernation_status, {Op, Status}) when is_atom(Status) ->
    [{op, Op}, {status, Status}];
build_task_prop(hibernation_bucket, Bucket) when is_list(Bucket) ->
    [{bucket, list_to_binary(Bucket)}];
build_task_prop(hibernation_uuid, UUID) when is_binary(UUID) ->
    [{id, UUID}].

build_hibernation_task() ->
    Snapshot = chronicle_compat:get_snapshot([fetch_snapshot(_)]),
    TaskProps = [begin
                     Val = chronicle_compat:get(Snapshot, Key,
                                                #{default => undefined}),
                     build_task_prop(Key, Val)
                 end
                 || Key <- keys()],
    Task = lists:flatten(TaskProps),
    case Task of
        [] ->
            [];
        _ ->
            [[{type, hibernation} | Task] ++
             [{isStale,
               leader_registry:whereis_name(ns_orchestrator) =:= undefined}]]

    end.

unpause_bucket(Bucket) ->
    {ok, BucketConfig} = ns_bucket:get_bucket(Bucket),
    BucketNodes = ns_bucket:get_servers(BucketConfig),
    unpause_bucket(Bucket, BucketNodes).

unpause_bucket(Bucket, BucketNodes) ->
    misc:with_trap_exit(
      fun () ->
              {Worker, Ref} =
                  misc:spawn_monitor(
                    ?cut(unpause_bucket_body(Bucket, BucketNodes))),
              receive
                  {'DOWN', Ref, process, Worker, Reason} ->
                      case Reason of
                          normal ->
                              ?log_debug("unpause_bucket for bucket ~p "
                                         "completed successfully on nodes: ~p.",
                                         [Bucket, BucketNodes]),
                              ok;
                          _ ->
                              ?log_error("unpause_bucket for bucket ~p failed. "
                                         "BucketNodes: ~p, Reason: ~p.",
                                         [Bucket, BucketNodes, Reason]),
                              ok
                      end;
                  {'EXIT', _Pid, Reason} ->
                      ?log_debug("Received 'EXIT' while unpausing bucket: ~p. "
                                 "Terminating worker: ~p. Reason: ~p.",
                                 [Bucket, Worker, Reason]),
                      misc:terminate_and_wait(Worker, Reason)
              end
      end).

unpause_bucket_body(Bucket, BucketNodes) ->
    Timeout = ?get_timeout(unpause_bucket, 5000),

    leader_activities:run_activity(
      {unpause_bucket, Bucket}, majority,
      fun () ->
              %% Make a best-case effort to unpause bucket on the BucketNodes.
              Results =
                  misc:parallel_map_partial(
                    fun (BucketNode) ->
                            try
                                kv_hibernation_agent:unpause_bucket(
                                  Bucket, BucketNode)
                            catch
                                E:T:S ->
                                    ?log_error("unpause_bucket for bucket: ~p ",
                                               "failed on node: ~p. "
                                               "Error: {~p, ~p, ~p} ",
                                               [Bucket, BucketNode,
                                                E, T, S]),
                                    {error, unpause_bucket_failed}
                            end
                    end,
                    BucketNodes, Timeout),

              OkNodes =
                  lists:filtermap(
                    fun ({Node, {ok, ok}}) ->
                            {true, Node};
                        (_) ->
                            false
                    end, lists:zip(BucketNodes, Results)),

              case BucketNodes -- OkNodes of
                  [] ->
                      ok;
                  FailedNodes ->
                      exit({unpause_bucket_failed, {failed_nodes, FailedNodes}})
              end
      end).

-spec sync_s3(string(), string(), atom())->
          ok | {error, non_neg_integer(), binary()}.
sync_s3(Source, Dest, SyncCode) ->
    Cmd = path_config:component_path(bin, "cbobjutil"),
    {SPath, DPath} = case SyncCode of
                         to ->
                             {Source, "s3:/" ++ Dest};
                         from ->
                             {"s3:/" ++ Source, Dest}
                     end,
    Args = ["sync", SPath, DPath],
    {Status, Output} = misc:run_external_tool(Cmd, Args, [],
                                              [graceful_shutdown]),
    case Status of
        0 ->
            ok;
        _ ->
            ?log_error("cbobjutil call `~s` returned ~b:~n~s",
                       [Cmd, Status, Output]),
            {error, Status, Output}
    end.

get_data_component_path() ->
    path_config:component_path(data, "data").

get_bucket_data_component_path(Bucket) ->
    filename:join(get_data_component_path(), Bucket).

get_node_data_remote_path(RemotePath, Node) ->
    filename:join(RemotePath, atom_to_list(Node)).

get_bucket_data_remote_path(RemotePath, Node, Bucket) ->
    filename:join(get_node_data_remote_path(RemotePath, Node), Bucket).

get_bucket_metadata_filename() ->
    "Metadata".

get_version_filename() ->
    "version.json".

write_to_temp_file(FileName, Data) ->
    TempFile = path_config:component_path(tmp, FileName),
    ok = misc:write_file(TempFile, Data),
    TempFile.

s3_upload_and_remove_file(TempFile, Dest) ->
    try
        sync_s3(TempFile, Dest, to)
    catch
        _:_ -> {error, sync_to_s3}
    after
        file:delete(TempFile)
    end.

encode_term(Term) ->
    io_lib:format("~0p.~n", [Term]).

upload_bucket_metadata(Metadata, Dest) ->
    FileName = get_bucket_metadata_filename(),
    TempFile = write_to_temp_file(FileName, encode_term(Metadata)),
    s3_upload_and_remove_file(TempFile, Dest).

encode_version(Version) ->
    ejson:encode({[{version, Version}]}).

upload_version_json(Version, Dest) ->
    FileName = get_version_filename(),
    TempFile = write_to_temp_file(FileName, encode_version(Version)),
    s3_upload_and_remove_file(TempFile, Dest).

upload_metadata_to_s3(BucketName, Snapshot, Dest) ->
    {ok, BucketCfg} = ns_bucket:get_bucket(BucketName, Snapshot),
    Manifest = collections:get_manifest(BucketName, Snapshot),
    BucketUUID = ns_bucket:uuid(BucketName, Snapshot),
    Metadata = [{bucket_cfg, BucketCfg}, {bucket_uuid, BucketUUID},
                {bucket_manifest, Manifest}],
    ok = upload_bucket_metadata(Metadata, Dest),
    ok = upload_version_json(cluster_compat_mode:get_compat_version(), Dest).

s3_sync_from_file(FileName, Rpath, DataFromFileFunc) ->
    Source = Rpath ++ FileName,
    TempFile = path_config:component_path(tmp, FileName),
    ok = sync_s3(Source, TempFile, from),
    try
        DataFromFileFunc(TempFile)
    catch
        _:_ -> {error, file_sync_failure}
    after
        file:delete(TempFile)
    end.

get_bucket_metadata_from_s3(Rpath) ->
    FileName = get_bucket_metadata_filename(),
    {ok, Metadata} =
        s3_sync_from_file(FileName, Rpath,
                          fun(TempFile) ->
                                  {ok, [Data]} = file:consult(TempFile),
                                  {ok, Data}
                          end),
    Version = get_version_from_s3(Rpath),
    Metadata ++ [{version, Version}].

get_bucket_version(Metadata) ->
    proplists:get_value(version, Metadata).

get_bucket_config(Metadata) ->
    proplists:get_value(bucket_cfg, Metadata).

get_bucket_manifest(Metadata) ->
    proplists:get_value(bucket_manifest, Metadata).

get_bucket_uuid(Metadata) ->
    proplists:get_value(bucket_uuid, Metadata).

decode_version(Data) ->
    {Json} = ejson:decode(Data),
    proplists:get_value(<<"version">>, Json).

get_version_from_s3(Rpath) ->
    FileName = get_version_filename(),
    {ok, Version} =
        s3_sync_from_file(FileName, Rpath,
                          fun(TempFile) ->
                                  {ok, Data} = file:read_file(TempFile),
                                  {ok, decode_version(Data)}
                          end),
    Version.