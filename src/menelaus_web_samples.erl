%% @author Couchbase <info@couchbase.com>
%% @copyright 2017-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

%% @doc implementation of samples REST API's

-module(menelaus_web_samples).

-include("cut.hrl").

-export([handle_get/1,
         handle_post/1]).

-import(menelaus_util,
        [reply_json/2,
         reply_json/3]).

-define(COUCHDB_REQUIRED_SAMPLES, ["gamesim-sample", "beer-sample"]).
-define(SAMPLE_BUCKET_QUOTA_MB, 200).
-define(SAMPLE_BUCKET_QUOTA, 1024 * 1024 * ?SAMPLE_BUCKET_QUOTA_MB).

handle_get(Req) ->
    Buckets = [Bucket || {Bucket, _} <- ns_bucket:get_buckets()],

    Map = [ begin
                Name = filename:basename(Path, ".zip"),
                Installed = lists:member(Name, Buckets),
                {[{name, list_to_binary(Name)},
                  {installed, Installed},
                  {quotaNeeded, ?SAMPLE_BUCKET_QUOTA}]}
            end || Path <- list_sample_files() ],

    reply_json(Req, Map).

-spec none_use_couchdb(Samples :: [{binary(), binary()}]) -> boolean().
none_use_couchdb(Samples) ->
    lists:all(
      fun ({Sample, _Bucket, _BucketState}) ->
              samples_without_couchdb(binary_to_list(Sample))
      end, Samples).

-spec samples_without_couchdb(Name :: string()) -> Return :: boolean().
samples_without_couchdb(Name) when is_list(Name) ->
    not lists:member(string:trim(Name), ?COUCHDB_REQUIRED_SAMPLES).

build_samples_input_list(Samples) ->
    lists:foldl(
      fun ({[{<<"sample">>, Sample},{<<"bucket">>, Bucket}]}, AccIn) ->
              [{Sample, Bucket, bucket_must_exist} | AccIn];
          (Sample, AccIn) ->
              [{Sample, Sample, bucket_must_not_exist} | AccIn]
      end, [], Samples).

%% There are two types of input to this request. The classic/original input
%% is a list of  names (e.g. ["travel-sample", "beer-sample"]) where the
%% data is found is <name>.zip and the bucket of name <name> does not
%% already exist and will be created and loaded.
%%
%% The second input is a list of json objects each of which consists of list
%% of [{"sample", <sample-name>}, {"bucket", <bucket-name>}] where
%% <sample-name>.zip contains the data and <bucket-name> is the destination
%% bucket (which must already exist).
%%
%% Thee two types of input are normalized into a list of tuples to facilitate
%% common handling of the two.
%% [{<sample-name>, <bucket-name>]}

handle_post(Req) ->
    menelaus_util:assert_is_71(),
    menelaus_web_rbac:assert_no_users_upgrade(),
    case try_decode(mochiweb_request:recv_body(Req)) of
        {ok, Samples} when is_list(Samples), not is_binary(Samples) ->
            Samples2 = build_samples_input_list(Samples),
            case config_profile:get_bool({couchdb, disabled}) of
                true ->
                    case none_use_couchdb(Samples2) of
                        true ->
                            process_post(Req, Samples2);
                        false ->
                            SampleNames =
                                lists:map(
                                  fun (FullPath) ->
                                          list_to_binary(
                                            filename:basename(FullPath, ".zip"))
                                  end, list_sample_files()),
                            Err =
                                list_to_binary(
                                  io_lib:format(
                                    "Attempted to load invalid samples for current configuration profile. "
                                    "Attempted: ~p, Valid: ~p", [Samples, SampleNames])),
                            reply_json(Req, Err, 400)
                    end;
                false ->
                    process_post(Req, Samples2)
            end;
        {ok, _Samples} ->
            reply_json(
              Req,
              list_to_binary("A [list] of names must be specified."), 400);
        {error, Error} ->
            reply_json(Req, list_to_binary(Error), 400)
    end.

process_post(Req, Samples) ->
    case ns_orchestrator:ensure_janitor_run(services) of
        ok ->
            ok;
        _ ->
            menelaus_util:web_exception(
              503, "System services have not completed startup. "
              "Please try again shortly.")
    end,

    Errors = case validate_post_sample_buckets(Samples) of
                 ok ->
                     start_loading_samples(Req, Samples);
                 X1 ->
                     X1
             end,


    case Errors of
        ok ->
            reply_json(Req, [], 202);
        X2 ->
            reply_json(Req, [Msg || {error, Msg} <- X2], 400)
    end.

try_decode(Body) ->
    try
        {ok, ejson:decode(Body)}
    catch
        throw:invalid_utf8 ->
            {error, "Invalid JSON: Illegal UTF-8 character"};
        _:_ ->
            {error, "Invalid JSON"}
    end.

start_loading_samples(Req, Samples) ->
    lists:foreach(fun ({Sample, Bucket, BucketState}) ->
                          start_loading_sample(Req, binary_to_list(Sample),
                                               binary_to_list(Bucket),
                                               BucketState)
                  end, Samples).

start_loading_sample(Req, Sample, Bucket, BucketState) ->
    case samples_loader_tasks:start_loading_sample(Sample, Bucket,
                                                   ?SAMPLE_BUCKET_QUOTA_MB,
                                                   BucketState) of
        ok ->
            ns_audit:start_loading_sample(Req, Bucket);
        already_started ->
            ok
    end.

list_sample_files() ->
    BinDir = path_config:component_path(bin),
    AllSamples = filelib:wildcard(
                   filename:join([BinDir, "..", "samples", "*.zip"])),
    case config_profile:get_bool({couchdb, disabled}) of
        true ->
            lists:filter(
              ?cut(samples_without_couchdb(
                     filename:basename(_, ".zip"))), AllSamples);
        false ->
            AllSamples
    end.

sample_exists(Name) ->
    BinDir = path_config:component_path(bin),
    filelib:is_file(filename:join([BinDir, "..", "samples", binary_to_list(Name) ++ ".zip"])).

validate_post_sample_buckets(Samples) ->
    case check_valid_samples(Samples) of
        ok ->
            check_quota(Samples);
        X ->
            X
    end.

check_quota(Samples) ->
    Config = ns_config:get(),
    Snapshot =
        chronicle_compat:get_snapshot(
          [ns_bucket:fetch_snapshot(all, _, [props]),
           ns_cluster_membership:fetch_snapshot(_)], #{ns_config => Config}),

    NodesCount =
        length(ns_cluster_membership:service_active_nodes(Snapshot, kv)),
    StorageInfo = ns_storage_conf:cluster_storage_info(Config, Snapshot),
    RamQuotas = proplists:get_value(ram, StorageInfo),
    QuotaUsed = proplists:get_value(quotaUsed, RamQuotas),
    QuotaTotal = proplists:get_value(quotaTotal, RamQuotas),
    Required = ?SAMPLE_BUCKET_QUOTA * erlang:length(Samples),

    case (QuotaTotal - QuotaUsed) <  (Required * NodesCount) of
        true ->
            Err = ["Not enough Quota, you need to allocate ", format_MB(Required),
                   " to install sample buckets"],
            [{error, list_to_binary(Err)}];
        false ->
            ok
    end.

check_sample_exists(Sample) ->
    case sample_exists(Sample) of
        false ->
            Err2 = ["Sample ", Sample, " is not a valid sample."],
            {error, list_to_binary(Err2)};
        true -> ok
    end.

check_valid_samples(Samples) ->
    Errors =
        lists:foldl(
          fun ({Sample, Sample, bucket_must_not_exist}, AccIn) ->
                  %% Classic case where data is loaded into non-existent
                  %% bucket with the same name as the sample data.
                  RV =
                    case ns_bucket:name_conflict(binary_to_list(Sample)) of
                        true ->
                            Err1 = ["Sample bucket ", Sample,
                                    " is already loaded."],
                            {error, list_to_binary(Err1)};
                        false ->
                            check_sample_exists(Sample)
                    end,
                    [RV | AccIn];
              ({Sample, Bucket, bucket_must_exist}, AccIn) ->
                  %% Newer case where the bucket must already exist.
                  RV =
                    case ns_bucket:name_conflict(binary_to_list(Bucket)) of
                        false ->
                            Err1 =
                                ["Sample bucket ", Bucket,
                                 " must already exist and will be loaded "
                                 "with the sample data."],
                            {error, list_to_binary(Err1)};
                        true ->
                            check_sample_exists(Sample)
                    end,
                  [RV | AccIn]
          end, [], Samples),

    case [X || X <- Errors, X =/= ok] of
        [] ->
            ok;
        X ->
            X
    end.

format_MB(X) ->
    integer_to_list(misc:ceiling(X / 1024 / 1024)) ++ "MB".
