%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc metakv2 API's
%%
%% The metakv2 storage is organized as a hierarchy of keys, some of which are
%% directories and some of which can be associated with value. For example
%% if we set /fusion/bucket1/key1 = value1, the key /fusion/bucket1/key1
%% is a leaf key that is associated with the value, /fusion/bucket1 key is
%% associated with the directory that contains /fusion/bucket1/key1
%%
%% All values in the below API's are passed as base64 encoded strings.
%%
%% Keys can be created recursively (with all underlying directories) if
%% the option recursive is set to true
%%
%% One might pass the key revision into PUT /_metakv2/path and
%% POST /_metakv2/_controller/setRecursive api's
%% thus making sure that API's will error out if the fetched revision
%% of the same key is incompatible.
%%
%% For more details see the following document:
%% https://docs.google.com/document/d/1J43NENn5NZ2Mf7h72cnVcgitvpidSJ5WFZSb_DKFggk

-module(menelaus_metakv2).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-export([handle_get/2,
         handle_post_get_snapshot/1,
         handle_put/2,
         handle_post_set_multiple/1,
         handle_delete/2,
         handle_post_sync_quorum/1]).

get_key(Path) ->
    "_metakv2" ++ Key = Path,
    decode_path(uri_string:unquote(Key)).

decode_path(Path) ->
    lists:reverse([list_to_binary(T) || T <- string:tokens(Path, "/")]).

encode_path_str(Path, Type) ->
    Str = "/" ++
        string:join([binary_to_list(T) || T <- lists:reverse(Path)], "/"),
    case Type of
        dir ->
            Str ++ "/";
        leaf ->
            Str
    end.

encode_path(Path, Type) ->
    list_to_binary(encode_path_str(Path, Type)).

encode_revision({HistoryId, SeqNo}) ->
    iolist_to_binary(io_lib:format("~s:~B", [HistoryId, SeqNo])).

decode_revision(undefined) ->
    undefined;
decode_revision(RevisionString) ->
    case string:tokens(RevisionString, ":") of
        [HistoryId, SeqNo] ->
            try list_to_integer(SeqNo) of
                N -> {list_to_binary(HistoryId), N}
            catch
                _:_ ->
                    error
            end;
        _ ->
            error
    end.

massage_directory_content({Key, {Subkeys, Rev}}) when is_list(Subkeys) ->
    {encode_path(Key, dir),
     {[{revision, encode_revision(Rev)},
       {value, {[massage_directory_content(S) || S <- Subkeys]}}]}};
massage_directory_content({Key, {Value, Rev}}) ->
    {encode_path(Key, leaf),
     {[{revision, encode_revision(Rev)},
       {value, Value}]}}.

reply_not_found(Req, Path) ->
    reply_error(Req, {not_found, Path}).

encode_path_error(Msg, Path) ->
    {[{error, iolist_to_binary(
                io_lib:format(Msg, [encode_path_str(Path, leaf)]))}]}.

reply_error(Req, {not_found, Path}) ->
    menelaus_util:reply_json(Req, encode_path_error("~s is not found.", Path),
                             404);
reply_error(Req, {not_a_dir, Path}) ->
    menelaus_util:reply_json(Req, encode_path_error("~s is not a dir.", Path),
                             400);
reply_error(Req, {not_a_leaf, Path}) ->
    menelaus_util:reply_json(Req, encode_path_error("~s is not a leaf.", Path),
                             400);
reply_error(Req, not_changed) ->
    menelaus_util:reply_text(Req, "Not changed", 200);
reply_error(Req, {exists, Path}) ->
    menelaus_util:reply_json(Req, encode_path_error("~s already exists.", Path),
                             400);
reply_error(Req, {cas, Path}) ->
    menelaus_util:reply_json(Req, encode_path_error("Conflict at ~p", Path),
                             409);
reply_error(Req, duplicate_keys) ->
    menelaus_util:reply_text(Req, "Duplicate keys.", 400).

reply_result(Req, _, {ok, Rev}) ->
    menelaus_util:reply_json(Req, {[{revision, encode_revision(Rev)}]});
reply_result(Req, dir, {error, {wrong_type, Key}}) ->
    reply_error(Req, {not_a_dir, Key});
reply_result(Req, leaf, {error, {wrong_type, Key}}) ->
    reply_error(Req, {not_a_leaf, Key});
reply_result(Req, _, {error, Error}) ->
    reply_error(Req, Error).

is_directory(Path) ->
    case lists:reverse(Path) of
        [$/ | _] ->
            true;
        _ ->
            false
    end.

with_recursive(Fun, Req) ->
    validator:handle(
      fun (Params) ->
              Fun(proplists:get_value(recursive, Params, false))
      end, Req, qs,
      [validator:boolean(recursive, _),
       validator:unsupported(_)]).

handle_get(Path, Req) ->
    Key = get_key(Path),
    case is_directory(Path) of
        true ->
            with_recursive(
              fun (Recursive) ->
                      case chronicle_metakv:get_dir(Key, Recursive) of
                          {ok, {Content, SnapshotRev}} ->
                              menelaus_util:reply_json(
                                Req,
                                {[{revision, encode_revision(SnapshotRev)},
                                  {value, {[massage_directory_content(
                                              Content)]}}]});
                          {error, not_found} ->
                              reply_not_found(Req, Key)
                      end
              end, Req);
        false ->
            case chronicle_metakv:get(Key) of
                {ok, {Value, Revision}} ->
                    menelaus_util:reply_json(
                      Req, {[{value, Value},
                             {revision, encode_revision(Revision)}]});
                {error, not_found} ->
                    reply_not_found(Req, Key)
            end
    end.

validate_and_decode_path(Name, State) ->
    validator:validate(
      fun ("/" ++ _ = S) ->
              case lists:reverse(S) of
                  ("/" ++ _) ->
                      {error, "Key cannot be a directory."};
                  (_) ->
                      {value, decode_path(S)}
              end;
          (_) ->
              {error, "Key should start with /."}
      end, Name, State).

handle_post_get_snapshot(Req) ->
    validator:handle(
      fun (List) ->
              Keys = [K || [{key, K}] <- List],
              {ok, {KVList, Rev}} = chronicle_metakv:get_snapshot(Keys),
              Json = {[{revision, encode_revision(Rev)},
                       {value, {[{encode_path(K, leaf),
                                  {[{value, V},
                                    {revision, encode_revision(R)}]}} ||
                                    {K, {V, R}} <- KVList]}}]},
              menelaus_util:reply_json(Req, Json)
      end, Req, json_array,
      [validator:extract_internal(root, key, _),
       validator:required(key, _),
       validator:string(key, _),
       validate_and_decode_path(key, _),
       validator:unsupported(_)]).

validate_revision(Name, State) ->
  validator:validate(
    fun (Val) ->
            case decode_revision(Val) of
                error ->
                    {error, "Corrupted revision string"};
                Converted ->
                    {value, Converted}
            end
    end, Name, State).

handle_put(Path, Req) ->
    IsDirectory = is_directory(Path),
    validator:handle(
      fun (Params) ->
              Key = get_key(Path),
              Recursive = proplists:get_value(recursive, Params, false),
              case IsDirectory of
                  true ->
                      reply_result(Req, dir,
                                   chronicle_metakv:mkdir(Key, Recursive));
                  false ->
                      Rev =
                          case proplists:get_value(create, Params, false) of
                              true ->
                                  new;
                              false ->
                                  proplists:get_value(rev, Params)
                          end,
                      reply_result(Req, leaf,
                                   chronicle_metakv:set(
                                     Key, mochiweb_request:recv_body(Req),
                                     Rev, Recursive))
              end
      end, Req, qs,
      [validator:boolean(recursive, _),
       validator:boolean(create, _)] ++
          case IsDirectory of
              true ->
                  [validator:required(create, _),
                   validator:validate(
                     fun (true) -> ok;
                         (false) ->
                             {error, "Create parameter should be true "
                              "if directory is specified"}
                     end, create, _)];
              false ->
                  [validator:string(rev, _),
                   validate_revision(rev, _)]
          end ++
          [validator:validate_relative(
             fun (true, _) ->
                     {error, "Create parameter cannot be true if rev is"
                      " specified"};
                 (false, _) ->
                     ok
             end, create, rev, _),
           validator:unsupported(_)]).

handle_post_set_multiple(Req) ->
    with_recursive(handle_post_set_multiple(Req, _), Req).

handle_post_set_multiple(Req, Recursive) ->
    validator:handle(
      fun (List) ->
              KVR =
                  lists:map(
                    fun (Props) ->
                            Key = proplists:get_value(key, Props),
                            Value = proplists:get_value(value, Props),
                            Rev = case proplists:get_value(create, Props,
                                                           false) of
                                      true ->
                                          new;
                                      false ->
                                          proplists:get_value(revision, Props)
                                  end,
                            {Key, {Value, Rev}}
                    end, List),
              reply_result(Req, leaf,
                           chronicle_metakv:set_multiple(KVR, Recursive)),
              menelaus_util:reply(Req, 200)
      end, Req, json_map,
      [validator:required(key, _),
       validator:string(key, _),
       validate_and_decode_path(key, _),
       validator:required(value, _),
       validator:string(value, _),
       validator:convert(value, fun list_to_binary/1, _),
       validator:string(revision, _),
       validate_revision(revision, _),
       validator:boolean(create, _),
       validator:unsupported(_)]).

reply_delete_result(Req, {ok, Rev}) ->
    menelaus_util:reply_json(Req, {[{revision, encode_revision(Rev)}]});
reply_delete_result(Req, {error, not_found}) ->
    menelaus_util:reply_text(Req, "Not found.", 404);
reply_delete_result(Req, {error, not_empty}) ->
    menelaus_util:reply_text(Req, "Not empty.", 400).

handle_delete(Path, Req) ->
    Key = get_key(Path),
    case is_directory(Path) of
        true ->
            with_recursive(
              ?cut(reply_delete_result(
                     Req, chronicle_metakv:delete_dir(Key, _))), Req);
        false ->
            reply_delete_result(Req, chronicle_metakv:delete(Key))
    end.

handle_post_sync_quorum(Req) ->
    validator:handle(
      fun (Props) ->
              case chronicle_metakv:sync_quorum(
                     proplists:get_value(key, Props)) of
                  ok ->
                      menelaus_util:reply(Req, 200);
                  {error, timeout} ->
                      menelaus_util:reply_text(Req, "Timeout.", 504)
              end
      end, Req, qs,
      [validator:integer(timeout, 1000, 360000, _),
       validator:unsupported(_)]).
