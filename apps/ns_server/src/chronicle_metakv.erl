%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc chronicle metakv
%%
%% These API's provide hierarchical structure of leaves/directories on top of
%% dedicated metakv chronicle rsm.
%%
%% The code leverages the key/value chronicle_kv storage to store an
%% hierarchical structure, where each key contains full path to the leaf or
%% directory
%%
%% Leaves are Key-Value pairs {leaf, Path} -> Value, where Value is arbitrary.
%%
%% Directories are Key-Value pairs {dir, Path} -> [Children], where Childen is
%% a list of either {dir, Name} - representing subdirectories or {leaf, Name}
%% representing leaves situated in the current directory.
%%
%% Path is a list of names [Name1, Name2, Name3, Root] which represents leaf or
%% directory full path /Root/Name3/Name2/Name1
%%
%% Chronicle also attaches the revision number to each key/value.
%% Revisions of the previously fetched keys might be passed into set and
%% set_multiple API's which guarantees that the API won't succeed if the
%% revisions of the keys have changed since the keys were fetched.

-module(chronicle_metakv).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([upgrade_to_morpheus/3,
         get/1,
         get_snapshot/1,
         get_dir/2,
         set/4,
         set_multiple/2,
         mkdir/2,
         delete/1,
         delete_dir/2,
         sync_quorum/1]).

-type key() :: list().
-type value() :: any().
-type revision() :: chronicle:revision() | new | undefined.
-type kvr() :: {key(), {value(), revision()}}.

upgrade_to_morpheus(_, _, _) ->
    case chronicle_agent:get_info_for_rsm(metakv) of
        {error, no_rsm} ->
            ?log_debug("Add metakv rsm to chronicle"),
            ok = chronicle:put_rsm({metakv, chronicle_kv, []});
        _ ->
            ok
    end.

-type get_result() :: {ok, {value(), revision()}} | {error, not_found}.

%% fetches the value and revision of the leaf
-spec get(key()) -> get_result().
get(Key) ->
    chronicle_kv:get(metakv, {leaf, Key}).

%% fetches consistent snapshot of multiple keys
-spec get_snapshot([key()]) -> {ok, {[kvr()], revision()}}.
get_snapshot(Keys) ->
    chronicle_kv:ro_txn(metakv, fetch_leaves(_, Keys)).

fetch_leaves(Txn, Keys) ->
    lists:filtermap(
      fun (Key) ->
              case chronicle_kv:txn_get({leaf, Key}, Txn) of
                  {ok, {_, _} = VR} ->
                      {true, {Key, VR}};
                  {error, not_found} ->
                      false
              end
      end, Keys).

%% fetches either full(hierarchical) or flat(just first level leaves) snapshot
%% of the directory
-spec get_dir(key(), boolean()) ->
          {ok, {{key(), {list(), revision()}}, revision()}} |
          {error, not_found}.
get_dir(Dir, Recursive) ->
    case chronicle_kv:ro_txn(metakv, fetch_dir(_, Dir, Recursive)) of
        {ok, {{error, not_found}, _}} ->
            {error, not_found};
        Res ->
            Res
    end.

fetch_dir(Txn, Dir, Recursive) ->
    case chronicle_kv:txn_get({dir, Dir}, Txn) of
        {ok, {Subkeys, Rev}} ->
            Leaves = [[Leaf | Dir] || {leaf, Leaf} <- Subkeys],
            LeavesValues = fetch_leaves(Txn, Leaves),
            DirsValues =
                case Recursive of
                    true ->
                        Dirs = [[D | Dir] || {dir, D} <- Subkeys],
                        lists:map(fetch_dir(Txn, _, Recursive), Dirs);
                    false ->
                        []
                end,
            {Dir, {LeavesValues ++ DirsValues, Rev}};
        {error, not_found} ->
            {error, not_found}
    end.

check_revision(Res, undefined) ->
    Res;
check_revision({ok, _}, new) ->
    {error, exists};
check_revision({ok, {_, {FetchedHistoryId, FetchedSeqNo}}} = Res,
               {HistoryId, SeqNo}) when FetchedHistoryId =:= HistoryId andalso
                                        FetchedSeqNo =< SeqNo ->
    Res;
check_revision({ok, _}, {_, _}) ->
    {error, cas};
check_revision({error, not_found}, _) ->
    {error, not_found}.

%% Snapshot here is used to accumulate fetched values with modifications
%% applied on top. So in the case of [get, set, get] sequence the last get
%% returns value modified by set, not the value from chronicle. Later this
%% snapshot will be converted to the list of set commands.
txn_get(Key, Txn, Snapshot) ->
    txn_get(Key, Txn, Snapshot, undefined).

txn_get(Key, Txn, Snapshot, Rev) ->
    case maps:find(Key, Snapshot) of
        {ok, VR} ->
            {VR, Snapshot};
        error ->
            Value = check_revision(chronicle_kv:txn_get(Key, Txn), Rev),
            NewSnapshot = maps:put(Key, Value, Snapshot),
            {Value, NewSnapshot}
    end.

txn_set(Key, Value, Snapshot) ->
    maps:put(Key, {ok, {Value, modified}}, Snapshot).

snapshot_to_sets(Snapshot) ->
    [{set, Key, Value} ||
        {Key, {ok, {Value, modified}}} <- maps:to_list(Snapshot)].

process_result({abort, Error}) ->
    {abort, {error, Error}};
process_result({ok, Snapshot}) ->
    case snapshot_to_sets(Snapshot) of
        [] ->
            {abort, {error, not_changed}};
        Sets ->
            {commit, Sets}
    end.

-type set_result_no_cas() :: {ok, revision()} |
                             {error, {not_found, key()} | {wrong_type, key()} |
                              not_changed | {exists, key()}}.
-type set_result() :: set_result_no_cas() | {error, {cas, key()}}.

%% sets the value of the key. checks revision if it is provided and enforces
%% that key does not exist if the provided revision is 'new'
-spec set(key(), value(), revision(), boolean()) -> set_result().
set(Key, Value, Rev, Recursive) ->
    set_multiple([{Key, {Value, Rev}}], Recursive).

%% sets multiple keys in a single transaction. checks revisions if they
%% are provided and enforces that keys do not exist if the provided
%% revision is 'new'
-spec set_multiple([kvr()], boolean()) ->
          set_result() | {error, duplicate_keys}.
set_multiple(KVR, Recursive) ->
    Keys = [K || {K, _} <- KVR],
    case length(Keys) =:= length(lists:usort(Keys)) of
        true ->
            chronicle_kv:txn(
              metakv,
              fun (Txn) ->
                      process_result(set_multiple(Txn, KVR, #{}, Recursive))
              end);
        false ->
            {error, duplicate_keys}
    end.

set_multiple(_, [], Snapshot, _) ->
    {ok, Snapshot};
set_multiple(Txn, [{Key, {Value, Rev}} | KVR], Snapshot, Recursive) ->
    case txn_get({leaf, Key}, Txn, Snapshot, Rev) of
        {{ok, {Value, _}}, Snapshot1} ->
            set_multiple(Txn, KVR, Snapshot1, Recursive);
        {{error, not_found}, Snapshot1}
          when Rev =:= new orelse Rev =:= undefined ->
            case add_key(Txn, {leaf, Key}, Value, Snapshot1, Recursive) of
                {abort, _} = Abort ->
                    Abort;
                {ok, Snapshot2} ->
                    set_multiple(Txn, KVR, Snapshot2, Recursive)
            end;
        {{ok, _}, Snapshot1} ->
            set_multiple(Txn, KVR, txn_set({leaf, Key}, Value, Snapshot1),
                         Recursive);
        {{error, Error}, _} ->
            {abort, {Error, Key}}
    end.

invert_type(leaf) ->
    dir;
invert_type(dir) ->
    leaf.

add_key(Txn, {Type, [Leaf | _] = Key}, Value, Snapshot, Recursive) ->
    case txn_get({invert_type(Type), Key}, Txn, Snapshot) of
        {{_, not_found}, Snapshot1} ->
            Snapshot2 = txn_set({Type, Key}, Value, Snapshot1),
            case Key of
                [_] when Type =:= dir ->
                    {ok, Snapshot2};
                [_ | Dir] ->
                    case txn_get({dir, Dir}, Txn, Snapshot2) of
                        {{ok, {Entries, _}}, Snapshot3} ->
                            {ok, txn_set({dir, Dir}, [{Type, Leaf} | Entries],
                                         Snapshot3)};
                        {{error, not_found}, Snapshot3} ->
                            case Recursive of
                                true ->
                                    add_key(
                                      Txn, {dir, Dir}, [{Type, Leaf}],
                                      Snapshot3, Recursive);
                                false ->
                                    {abort, {not_found, Dir}}
                            end
                    end
            end;
        {{ok, _}, _} ->
            {abort, {wrong_type, Key}}
    end.

%% creates an empty directory
-spec mkdir(key(), boolean()) -> set_result_no_cas().
mkdir(Dir, Recursive) ->
    chronicle_kv:txn(
      metakv,
      fun (Txn) ->
              case txn_get({dir, Dir}, Txn, #{}) of
                  {{ok, _}, _} ->
                      {abort, {error, {exists, Dir}}};
                  {{error, not_found}, Snapshot} ->
                      process_result(
                        add_key(Txn, {dir, Dir}, [], Snapshot, Recursive))
              end
      end).

%% deletes the directory. either if it is empty or with the whole
%% content if Recursive=true
-spec delete_dir(key(), boolean()) ->
          {ok, revision()} | {error, not_found|not_empty}.
delete_dir([_] = Dir, Recursive) ->
    chronicle_kv:txn(
      metakv,
      fun (Txn) ->
              case maybe_delete_dir(Dir, Txn, Recursive) of
                  {error, Error} ->
                      {abort, {error, Error}};
                  Sets ->
                      {commit, Sets}
              end
      end);
delete_dir([DirName | Parent] = Dir, Recursive) ->
    chronicle_kv:txn(
      metakv,
      fun (Txn) ->
              case chronicle_kv:txn_get({dir, Parent}, Txn) of
                  {ok, {Entries, _}} ->
                      case maybe_delete_dir(Dir, Txn, Recursive) of
                          {error, Error} ->
                              {abort, {error, Error}};
                          Sets ->
                              {commit,
                               [{set, {dir, Parent},
                                 Entries -- [{dir, DirName}]} | Sets]}
                      end;
                  {error, not_found} ->
                      {abort, {error, not_found}}
              end
      end).

%% deletes leaf
-spec delete(key()) -> {ok, revision()} | {error, not_found}.
delete([Leaf | Parent] = Key) ->
    chronicle_kv:txn(
      metakv,
      fun (Txn) ->
              case chronicle_kv:txn_get({dir, Parent}, Txn) of
                  {ok, {Entries, _}} ->
                      case lists:member({leaf, Leaf}, Entries) of
                          true ->
                              {commit,
                               [{set, {dir, Parent}, Entries -- [{leaf, Leaf}]},
                                {delete, {leaf, Key}}]};
                          false ->
                              {abort, {error, not_found}}
                      end;
                  {error, not_found} ->
                      {abort, {error, not_found}}
              end
      end).

maybe_delete_dir(Dir, Txn, Recursive) ->
    case maybe_delete_dir_content(Dir, Txn, Recursive) of
        {error, Error} ->
            {error, Error};
        Sets when is_list(Sets) ->
            [{delete, {dir, Dir}} | lists:flatten(Sets)]
    end.

maybe_delete_dir_content(Dir, Txn, Recursive) ->
    case chronicle_kv:txn_get({dir, Dir}, Txn) of
        {ok, {[], _}} ->
            [];
        {ok, {Entries, _}} ->
            case Recursive of
                true ->
                    lists:map(
                      fun ({dir, Leaf}) ->
                              SubDir = [Leaf | Dir],
                              [{delete, {dir, SubDir}} |
                               maybe_delete_dir_content(SubDir, Txn, true)];
                          ({leaf, Leaf}) ->
                              [{delete, {leaf, [Leaf | Dir]}}]
                      end, Entries);
                false ->
                    {error, not_empty}
            end;
        {error, not_found} ->
            {error, not_found}
    end.

%% performs quorum read
-spec sync_quorum(integer()) -> ok | {error, timeout}.
sync_quorum(Timeout) ->
    try
        case Timeout of
            undefined ->
                chronicle_kv:sync(metakv);
            _ ->
                chronicle_kv:sync(metakv, Timeout)
        end
    catch
        exit:{error, timeout} ->
            {error, timeout}
    end.

-ifdef(TEST).

setup() ->
    fake_chronicle_kv:new().

teardown(_) ->
    fake_chronicle_kv:unload().

get_dir_content(Dir) ->
    get_dir_content(Dir, true).

get_dir_content(Dir, Recursive) ->
    case chronicle_metakv:get_dir(Dir, Recursive) of
        {error, _} = E ->
            E;
        {ok, {Content, _}} ->
            dir_content_to_map(Content, #{})
    end.

dir_content_to_map({_Key, {Subkeys, _Rev}}, Map) when is_list(Subkeys) ->
    lists:foldl(dir_content_to_map(_, _), Map, Subkeys);
dir_content_to_map({Key, {Value, _Rev}}, Map) ->
    maps:put(Key, Value, Map).

snapshot_to_map({ok, {Snapshot, _}}) ->
    maps:from_list([{K, V} || {K, {V, _R}} <- Snapshot]).

check_parent(dir, [_], _Snapshot) ->
    ok;
check_parent(Type, [Leaf | Parent], Snapshot) ->
    Val = maps:find({dir, Parent}, Snapshot),
    ?assertMatch({ok, {_, _}}, Val),
    {ok, {Entries, _}} = Val,
    ?assert(lists:member({Type, Leaf}, Entries)).

check_integrity() ->
    {ok, {Snapshot, {_, SnSeqno}}} = chronicle_kv:get_full_snapshot(metakv),
    lists:foreach(
      fun ({{dir, Dir}, {Entries, {_, Seqno}}}) ->
              ?assert(Seqno =< SnSeqno),
              check_parent(dir, Dir, Snapshot),
              lists:foreach(
                fun ({Type, Leaf}) ->
                        ?assert(maps:is_key({Type, [Leaf | Dir]}, Snapshot))
                end, Entries);
          ({{leaf, Key}, {_Value, {_, Seqno}}}) ->
              ?assert(Seqno =< SnSeqno),
              check_parent(leaf, Key, Snapshot);
          (_) ->
              ?assert(false)
      end, maps:to_list(Snapshot)).

test_set(Key, Val, Rev, Recursive) ->
    Ret = chronicle_metakv:set(Key, Val, Rev, Recursive),
    check_integrity(),
    Ret.

test_set_multiple(List, Recursive) ->
    Ret = chronicle_metakv:set_multiple(List, Recursive),
    check_integrity(),
    Ret.

test_mkdir(Dir, Recursive) ->
    Ret = chronicle_metakv:mkdir(Dir, Recursive),
    check_integrity(),
    Ret.

test_delete(Dir) ->
    Ret = chronicle_metakv:delete(Dir),
    check_integrity(),
    Ret.

test_delete_dir(Dir, Recursive) ->
    Ret = chronicle_metakv:delete_dir(Dir, Recursive),
    check_integrity(),
    Ret.

cas_testing(Fun) ->
    %% new key, non recursive, do not check revision
    ?assertEqual(
       {error, {not_found, [subkey0, root]}},
       Fun([key0, subkey0, root], v1, undefined, false)),
    %% new key, recursive, do not check revision
    ?assertMatch(
       {ok, _},
       Fun([key0, subkey0, root], v1, undefined, true)),
    %% new key, non recursive, expect add
    ?assertEqual(
       {error, {not_found, [subkey1, root]}},
       Fun([key1, subkey1, root], v1, new, false)),
    %% new key, recursive, expect add
    Ret = Fun([key1, subkey1, root], v1, new, true),
    ?assertMatch({ok, _}, Ret),
    {ok, OldRev} = Ret,
    %% update, recursive, expect add
    ?assertEqual(
       {error, {exists, [key1, subkey1, root]}},
       Fun([key1, subkey1, root], v1, new, true)),
    %% update, non recursive, expect add
    ?assertEqual(
       {error, {exists, [key1, subkey1, root]}},
       Fun([key1, subkey1, root], v1, new, false)),
    %% update, recursive, do not check revision
    ?assertMatch(
       {ok, _},
       Fun([key1, subkey1, root], v2, undefined, true)),
    %% update, non recursive, do not check revision
    ?assertMatch(
       {ok, _},
       Fun([key1, subkey1, root], v3, undefined, false)),
    %% update, recursive, old revision
    ?assertEqual(
       {error, {cas, [key1, subkey1, root]}},
       Fun([key1, subkey1, root], v2, OldRev, true)),
    %% update, non recursive, old revision
    ?assertEqual(
       {error, {cas, [key1, subkey1, root]}},
       Fun([key1, subkey1, root], v2, OldRev, false)),
    Ret1 = chronicle_metakv:get([key1, subkey1, root]),
    ?assertMatch({ok, {v3, _}}, Ret1),
    {ok, {_, NewRev}} = Ret1,
    %% update, non recursive, new revision
    Ret2 = Fun([key1, subkey1, root], v2, NewRev, false),
    ?assertMatch({ok, _}, Ret2),
    {ok, NewNewRev} = Ret2,
    ?assertMatch({ok, _}, Fun([key1, subkey1, root], v4, NewNewRev, true)).

basic_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [{"set, get",
       fun () ->
               ?assertEqual({error, not_found},
                            chronicle_metakv:get([key1, subkey1, root])),
               ?assertEqual({error, {not_found, [subkey1, root]}},
                            test_set([key1, subkey1, root], v1,
                                     undefined, false)),
               ?assertEqual({error, {not_found, [key1, subkey1, root]}},
                            test_set([key1, subkey1, root], v1,
                                     {<<"">>, 0}, true)),
               ?assertMatch({ok, _},
                            test_set([key1, subkey1, root], v1, new, true)),
               ?assertMatch({ok, _},
                            test_set([key2, subkey1, root], v2, undefined,
                                     true)),
               ?assertMatch({ok, {v1, _}},
                            chronicle_metakv:get([key1, subkey1, root])),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [key2, subkey1, root] => v2},
                            get_dir_content([root])),
               ?assertMatch({ok, _},
                            test_set([key3, subkey1, root], v3,
                                     new, false)),
               ?assertMatch({ok, {v2, _}},
                            chronicle_metakv:get([key2, subkey1, root])),
               ?assertEqual(
                  #{[key1, subkey1, root] => v1,
                    [key2, subkey1, root] => v2,
                    [key3, subkey1, root] => v3},
                  get_dir_content([root])),
               ?assertMatch({error, {wrong_type, [subkey1, root]}},
                            test_set([subkey1, root], v2,
                                     new, true))
       end},
      {"get_dir",
       fun () ->
               ?assertEqual({error, not_found}, get_dir_content([root]), false),
               ?assertEqual({error, not_found}, get_dir_content([root]), true),
               ?assertMatch({ok, _},
                            test_set([key1, subkey1, root], v1, new, true)),
               ?assertMatch({ok, _},
                            test_set([key1, subkey2, subkey1, root],
                                     v2, new, true)),
               ?assertEqual(#{}, get_dir_content([root], false)),
               ?assertEqual(#{[key1, subkey1, root] => v1},
                            get_dir_content([subkey1, root], false)),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [key1, subkey2, subkey1, root] => v2},
                            get_dir_content([subkey1, root], true))
       end},
      {"get_snapshot",
       fun () ->
               ?assertMatch({ok, _}, test_set([key1, subkey1, root], v1,
                                              new, true)),
               ?assertMatch({ok, _}, test_set([key3, subkey1, root], v3,
                                              new, true)),
               ?assertMatch({ok, _}, test_set([key2, subkey2, root], v2,
                                              new, true)),
               ?assertMatch({ok, _}, test_set([key4, subkey2, root], v4,
                                              new, true)),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [key2, subkey2, root] => v2,
                              [key3, subkey1, root] => v3},
                            snapshot_to_map(
                              chronicle_metakv:get_snapshot(
                                [[key1, subkey1, root],
                                 [key3, subkey1, root],
                                 [key2, subkey2, root],
                                 [key3, subkey3, root]])))
       end},
      {"mkdir",
       fun () ->
               ?assertEqual({error, {not_found, [root]}},
                            test_mkdir([subdir1, root], false)),
               ?assertMatch({ok, _},
                            test_mkdir([subdir1, root], true)),
               ?assertMatch({ok, _},
                            test_mkdir([subdir2, subdir2, root], true)),
               ?assertMatch({ok, _},
                            test_set([key1, subdir2, subdir2, root],
                                     v1, new, false)),
               ?assertEqual({error, {exists, [subdir2, subdir2, root]}},
                            test_mkdir([subdir2, subdir2, root], true)),
               ?assertEqual(
                  {error, {wrong_type, [key1, subdir2, subdir2, root]}},
                  test_mkdir([key1, subdir2, subdir2, root], true)),
               ?assertEqual(
                  {error, {wrong_type, [key1, subdir2, subdir2, root]}},
                  test_mkdir([key1, subdir2, subdir2, root], false))
       end},
      {"set, revision handling",
       fun () ->
               cas_testing(fun test_set/4)
       end},
      {"set_multiple, revision handling",
       fun () ->
               cas_testing(fun (Key, Val, Rev, Recursive) ->
                                   test_set_multiple([{Key, {Val, Rev}}],
                                                     Recursive)
                           end)
       end},
      {"set_multiple, revision handling (with other keys)",
       fun () ->
               ?assertMatch({ok, _},
                            test_set([key2, subkey2, root], v4, new, true)),
               cas_testing(
                 fun (Key, Val, Rev, Recursive) ->
                         test_set_multiple(
                           [{Key, {Val, Rev}},
                            {[key2, subkey2, root], {v8, undefined}}],
                           Recursive)
                 end)
       end},
      {"set_multiple, duplicate keys",
       fun () ->
               ?assertEqual(
                  {error, duplicate_keys},
                  test_set_multiple([{[key1, subkey1, root], {v1, new}},
                                     {[key2, subkey2, root], {v2, new}},
                                     {[key1, subkey1, root], {v3, new}}], true))
       end},
      {"not changed",
       fun () ->
               ?assertMatch({ok, _},
                            test_set([key2, subkey2, root], v4, new, true)),
               Ret = test_set([key1, subkey1, root], v0, new, true),
               ?assertMatch({ok, _}, Ret),
               {ok, Rev} = Ret,
               ?assertEqual({error, not_changed},
                            test_set([key1, subkey1, root], v0,
                                     undefined, true)),
               ?assertEqual({error, not_changed},
                            test_set([key1, subkey1, root], v0, Rev, false)),
               ?assertEqual({error, not_changed},
                            test_set_multiple(
                              [{[key1, subkey1, root], {v0, Rev}}], false)),
               ?assertEqual({error, not_changed},
                            test_set_multiple(
                              [{[key1, subkey1, root], {v0, Rev}},
                               {[key2, subkey2, root], {v4, undefined}}],
                              false)),
               ?assertMatch({ok, _},
                            test_set_multiple(
                              [{[key1, subkey1, root], {v1, Rev}},
                               {[key2, subkey2, root], {v4, undefined}}],
                              false))
       end},
      {"delete",
       fun () ->
               ?assertEqual({error, not_found},
                            test_delete([key1, subkey1, root])),
               ?assertMatch({ok, _},
                            test_set([key1, subkey1, root], v0, new, true)),
               ?assertMatch({ok, _}, test_delete([key1, subkey1, root])),
               ?assertEqual({error, not_found},
                            chronicle_metakv:get([key1, subkey1, root]))
       end},
      {"delete_dir",
       fun () ->
               %% no parent dir
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], false)),
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], true)),

               %% dir not found
               ?assertMatch({ok, _}, test_mkdir([root], true)),
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], false)),
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], true)),

               %% attempt to non recursively delete non empty dir
               ?assertMatch({ok, _},
                            test_set([key1, subkey1, root], v0, new, true)),
               ?assertMatch({ok, _},
                            test_set([key2, subkey3, subkey2, subkey1, root],
                                     v1, new, true)),
               ?assertEqual({error, not_empty},
                            test_delete_dir([subkey1, root], false)),

               %% non recursive delete of empty dir
               ?assertMatch({ok, _}, test_mkdir([subkey2, root], true)),
               ?assertMatch({ok, _}, test_delete_dir([subkey2, root], false)),

               %% recursive delete of non empty dir
               ?assertMatch({ok, _}, test_delete_dir([subkey1, root], true)),

               ?assertEqual({error, not_found},
                            chronicle_metakv:get_dir([subkey1, root], false)),
               ?assertEqual({error, not_found},
                            chronicle_metakv:get_dir([subkey2, root], false)),
               ?assertMatch({ok, {{[root], {[], _}}, _}},
                            chronicle_metakv:get_dir([root], true)),

               %% non recursive delete of empty root dir
               ?assertMatch({ok, _}, test_delete_dir([root], false)),
               ?assertEqual({error, not_found},
                            chronicle_metakv:get_dir([root], false)),

               %% recursive delete of non empty root dir
               ?assertMatch({ok, _},
                            test_set([key1, subkey1, root], v0, new, true)),
               ?assertMatch({ok, _}, test_delete_dir([root], true)),
               ?assertEqual({error, not_found},
                            chronicle_metakv:get_dir([root], false))
       end}]}.

-endif.
