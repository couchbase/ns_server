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
%%
%% A leaf may be marked sensitive at creation time, in which case its value is
%% stored wrapped as {?METAKV2_SENSITIVE, Value} and is masked by
%% chronicle_kv_log:sanitize/2 before it can reach a log or a diagnostic dump.
%% The wrapping is an implementation detail of this module: every read path
%% strips the tag, so callers always see the bare value along with a boolean
%% telling them whether the leaf is sensitive.
%%
%% Sensitivity is fixed when the leaf is created. An update that does not
%% mention the flag carries the old sensitivity forward. An update that asks
%% for the opposite of what is stored is refused, so that a caller cannot be
%% left believing it has protected a value when it has not.

-module(chronicle_metakv).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([upgrade_to_79/3,
         get/1,
         get_snapshot/1,
         get_dir/3,
         set/5,
         set_multiple/2,
         mkdir/2,
         delete/1,
         delete_dir/2,
         sync_quorum/1,
         invert_type/1]).

-type key() :: list().
-type value() :: any().
-type revision() :: chronicle:revision() | new | undefined.
-type sensitive() :: boolean().
%% undefined means the caller did not state it, so it is carried forward
-type sensitive_req() :: sensitive() | undefined.
-type kvr() :: {key(), {value(), revision()}}.
-type kvr_req() :: {key(), {value(), revision(), sensitive_req()}}.

-type get_result() :: {ok, {value(), revision()}} | {error, not_found}.

-type base_mutation_result() ::  {ok, revision(), create|update} |
                                 {error,
                                  {wrong_type, key()} |
                                  {not_found, key()} |
                                  exceeded_retries}.

-type mkdir_result() :: base_mutation_result() |
                        {error, {exists, key(), revision()}}.

-type set_result() :: base_mutation_result() |
                      {error,
                       {not_changed, key(), revision()} |
                       {top_level_leaf, key()} |
                       {sensitive_mismatch, key()} |
                       {sensitive_unsupported, key()} |
                       {cas, key(), revision}}.

-type set_multiple_result() :: base_mutation_result() |
                               {error,
                                not_changed |
                                {top_level_leaf, key()} |
                                {sensitive_mismatch, key()} |
                                {sensitive_unsupported, key()} |
                                {cas, key(), revision()} |
                                duplicate_keys}.

upgrade_to_79(_, _, _) ->
    case chronicle_agent:get_info_for_rsm(metakv) of
        {error, no_rsm} ->
            ?log_debug("Add metakv rsm to chronicle"),
            ok = chronicle:put_rsm({metakv, chronicle_kv, []});
        _ ->
            ok
    end.

add_sensitive(true, Value) ->
    {?METAKV2_SENSITIVE, Value};
add_sensitive(_, Value) ->
    Value.

strip_sensitive({?METAKV2_SENSITIVE, Value}) ->
    {true, Value};
strip_sensitive(Value) ->
    {false, Value}.

%% Clients may not check for cluster compat mode before requesting the
%% sensitive flag, and cannot do so without racing an upgrade. In a mixed mode
%% cluster a node that predates the flag has no step that strips it, so it
%% hands the raw {?METAKV2_SENSITIVE, Value} tuple to the JSON encoder and the
%% read fails rather than returning the value. The sensitive flag must not be
%% written until all nodes are aware of how to handle it.
check_sensitive_supported(KVR) ->
    case [Key || {Key, {_, _, true}} <- KVR] of
        [] ->
            ok;
        [Key | _] ->
            case cluster_compat_mode:is_cluster_totoro() of
                true ->
                    ok;
                false ->
                    {error, {sensitive_unsupported, Key}}
            end
    end.

%% The sensitivity of an existing leaf cannot be changed, so a caller that
%% asks for the opposite of what is stored is told rather than ignored.
check_sensitive(_Key, _Stored, undefined) ->
    ok;
check_sensitive(Key, Stored, Sensitive) ->
    case strip_sensitive(Stored) of
        {Sensitive, _} ->
            ok;
        _ ->
            {error, {sensitive_mismatch, Key}}
    end.

%% fetches the value and revision of the leaf
-spec get(key()) -> get_result().
get(Key) ->
    case chronicle_kv:get(metakv, {leaf, Key}) of
        {ok, {Stored, Rev}} ->
            {_Sensitive, Value} = strip_sensitive(Stored),
            {ok, {Value, Rev}};
        {error, not_found} ->
            {error, not_found}
    end.

%% fetches consistent snapshot of multiple keys
-spec get_snapshot([key()]) -> {ok, {[kvr()], revision()}}.
get_snapshot(Keys) ->
    chronicle_kv:ro_txn(metakv, fetch_leaves(_, Keys)).

fetch_leaves(Txn, Keys) ->
    fetch_leaves(Txn, Keys, fun (_Sensitive, Value, Rev) -> {Value, Rev} end).

fetch_dir_leaves(Txn, Keys) ->
    fetch_leaves(Txn, Keys,
                 fun (Sensitive, Value, Rev) -> {Value, Rev, Sensitive} end).

fetch_leaves(Txn, Keys, Format) ->
    lists:filtermap(
      fun (Key) ->
              case chronicle_kv:txn_get({leaf, Key}, Txn) of
                  {ok, {Stored, Rev}} ->
                      {Sensitive, Value} = strip_sensitive(Stored),
                      {true, {Key, Format(Sensitive, Value, Rev)}};
                  {error, not_found} ->
                      false
              end
      end, Keys).

%% fetches either full (hierarchical) depth limited (hierarchical) or
%% flat (just first level leaves) snapshot
%% of the directory
-spec get_dir(key(), boolean(), integer() | undefined) ->
          {ok, {{key(), {list(), revision()}}, revision()}} |
          {error, not_found}.
get_dir(Dir, Recursive, Depth) when
      (Recursive =:= false andalso Depth =:= undefined) orelse
      (Recursive =:= true andalso (Depth =:= undefined orelse Depth > 0)) ->
    case chronicle_kv:ro_txn(metakv, fetch_dir(_, Dir, Recursive, Depth)) of
        {ok, {{error, not_found}, _}} ->
            {error, not_found};
        Res ->
            Res
    end.

fetch_dir(Txn, Dir, Recursive, Depth) ->
    case chronicle_kv:txn_get({dir, Dir}, Txn) of
        {ok, {Subkeys, Rev}} ->
            Leaves = [[Leaf | Dir] || {leaf, Leaf} <- Subkeys],
            LeavesValues = fetch_dir_leaves(Txn, Leaves),
            DirsValues =
                case Recursive of
                    true ->
                        Dirs = [[D | Dir] || {dir, D} <- Subkeys],
                        NewDepth = case Depth of
                                       undefined ->
                                           Depth;
                                       _ ->
                                           Depth - 1
                                   end,
                        case NewDepth of
                            0 ->
                                lists:filtermap(
                                  fun (Key) ->
                                          case chronicle_kv:txn_get({dir, Key},
                                                                    Txn) of
                                              {ok, {_, R}} ->
                                                  {true, {Key, {dir, R}}};
                                              {error, not_found} ->
                                                  false
                                          end
                                  end, Dirs);
                            _ ->
                                lists:map(
                                  fetch_dir(Txn, _, Recursive, NewDepth), Dirs)
                        end;
                    false ->
                        []
                end,
            {Dir, {LeavesValues ++ DirsValues, Rev}};
        {error, not_found} ->
            {error, not_found}
    end.

check_revision(Res, undefined) ->
    Res;
check_revision({ok, {_, {FetchedHistoryId, FetchedSeqNo}}} = Res,
               {HistoryId, SeqNo}) when FetchedHistoryId =:= HistoryId andalso
                                        FetchedSeqNo =< SeqNo ->
    Res;
check_revision({ok, {_, Rev}}, _) ->
    {error, {cas, Rev}};
check_revision({error, not_found}, new) ->
    {error, not_found};
check_revision({error, not_found}, {_, _}) ->
    {error, {cas, undefined}}.


%% Snapshot here is used to accumulate fetched values with modifications
%% applied on top. So in the case of [get, set, get] sequence the last get
%% returns value modified by set, not the value from chronicle. Later this
%% snapshot will be converted to the list of set commands.
txn_get(Key, Txn, Snapshot) ->
    txn_get(Key, Txn, Snapshot, undefined).

txn_get(Key, Txn, Snapshot, Rev) ->
    case maps:find(Key, Snapshot) of
        {ok, Res} ->
            {check_revision(Res, Rev), Snapshot};
        error ->
            Res = chronicle_kv:txn_get(Key, Txn),
            {check_revision(Res, Rev), maps:put(Key, Res, Snapshot)}
    end.

txn_set(Key, Value, Snapshot) ->
    maps:put(Key, {ok, {Value, modified}}, Snapshot).

snapshot_to_sets(Snapshot) ->
    [{set, Key, Value} ||
        {Key, {ok, {Value, modified}}} <- maps:to_list(Snapshot)].

process_result(_CreateOrUpdate, {abort, Error}) ->
    {abort, {error, Error}};
process_result(CreateOrUpdate, {ok, Snapshot}) ->
    case snapshot_to_sets(Snapshot) of
        [] ->
            {abort, {error, not_changed}};
        Sets ->
            {commit, Sets, CreateOrUpdate}
    end.

%% sets the value of the key. checks revision if it is provided
-spec set(key(), value(), revision(), boolean(), sensitive_req()) ->
          set_result().
set([_] = Key, _Value, _Rev, _Recursive, _Sensitive) ->
    {error, {top_level_leaf, Key}};
set(Key, Value, Rev, Recursive, Sensitive) ->
    KVR = [{Key, {Value, Rev, Sensitive}}],
    case check_sensitive_supported(KVR) of
        {error, _} = Error ->
            Error;
        ok ->
            set_checked(KVR, Recursive)
    end.

set_checked([{Key, {Value, Rev, Sensitive}}] = KVR, Recursive) ->
    chronicle_kv:txn(
      metakv,
      fun (Txn) ->
              case txn_get({leaf, Key}, Txn, #{}, Rev) of
                  {{ok, {Stored, R}}, Snapshot} ->
                      case check_sensitive(Key, Stored, Sensitive) of
                          {error, _} = Error ->
                              {abort, Error};
                          ok ->
                              case strip_sensitive(Stored) of
                                  {_, Value} ->
                                      {abort,
                                       {error, {not_changed, Key, R}}};
                                  _ ->
                                      process_result(
                                        update,
                                        set_multiple(Txn, KVR, Snapshot,
                                                     Recursive))
                              end
                      end;
                  {_Res, Snapshot} ->
                      process_result(
                        create, set_multiple(Txn, KVR, Snapshot, Recursive))
              end
      end).

%% sets multiple keys in a single transaction. checks revisions if they
%% are provided
-spec set_multiple([kvr_req()], boolean()) -> set_multiple_result().
set_multiple(KVR, Recursive) ->
    case validate_kvr(KVR) of
        ok ->
            case check_sensitive_supported(KVR) of
                {error, _} = Error ->
                    Error;
                ok ->
                    set_multiple_checked(KVR, Recursive)
            end;
        Error ->
            {error, Error}
    end.

set_multiple_checked(KVR, Recursive) ->
    chronicle_kv:txn(
      metakv,
      fun (Txn) ->
              process_result(update, set_multiple(Txn, KVR, #{}, Recursive))
      end).

validate_kvr(KVR) ->
    Keys = [K || {K, _} <- KVR],
    case length(Keys) =:= length(lists:usort(Keys)) of
        false ->
            duplicate_keys;
        true ->
            case lists:dropwhile(fun ([_]) -> false; (_) -> true end, Keys) of
                [] ->
                    ok;
                [K | _] ->
                    {top_level_leaf, K}
            end
    end.

set_multiple(_, [], Snapshot, _) ->
    {ok, Snapshot};
set_multiple(Txn, [{Key, {Value, Rev, Sensitive}} | KVR], Snapshot,
             Recursive) ->
    case txn_get({leaf, Key}, Txn, Snapshot, Rev) of
        {{ok, {Stored, _}}, Snapshot1} ->
            case check_sensitive(Key, Stored, Sensitive) of
                {error, Reason} ->
                    {abort, Reason};
                ok ->
                    %% sensitivity of an existing leaf is carried forward
                    case strip_sensitive(Stored) of
                        {_, Value} ->
                            set_multiple(Txn, KVR, Snapshot1, Recursive);
                        {WasSensitive, _} ->
                            NewStored = add_sensitive(WasSensitive, Value),
                            set_multiple(
                              Txn, KVR,
                              txn_set({leaf, Key}, NewStored, Snapshot1),
                              Recursive)
                    end
            end;
        {{error, not_found}, Snapshot1}
          when Rev =:= new orelse Rev =:= undefined ->
            NewStored = add_sensitive(Sensitive, Value),
            case add_key(Txn, {leaf, Key}, NewStored, Snapshot1, Recursive) of
                {abort, _} = Abort ->
                    Abort;
                {ok, Snapshot2} ->
                    set_multiple(Txn, KVR, Snapshot2, Recursive)
            end;
        {{error, not_found}, _} ->
            {abort, {not_found, Key}};
        {{error, {cas, R}}, _} ->
            {abort, {cas, Key, R}}
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
-spec mkdir(key(), boolean()) -> mkdir_result().
mkdir(Dir, Recursive) ->
    chronicle_kv:txn(
      metakv,
      fun (Txn) ->
              case txn_get({dir, Dir}, Txn, #{}) of
                  {{ok, {_, Rev}}, _} ->
                      {abort, {error, {exists, Dir, Rev}}};
                  {{error, not_found}, Snapshot} ->
                      process_result(
                        create,
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
    fake_chronicle_kv:setup(),
    %% the sensitive flag is refused below this
    fake_chronicle_kv:setup_cluster_compat_version(?VERSION_TOTORO).

teardown(_) ->
    fake_chronicle_kv:teardown().

get_dir(Dir, Recursive) ->
    get_dir(Dir, Recursive, undefined).

get_dir_content(Dir) ->
    get_dir_content(Dir, true).

get_dir_content(Dir, Recursive) ->
    get_dir_content(Dir, Recursive, undefined).

get_dir_content(Dir, Recursive, Depth) ->
    case get_dir(Dir, Recursive, Depth) of
        {error, _} = E ->
            E;
        {ok, {Content, _}} ->
            dir_content_to_map(Content, #{})
    end.

dir_content_to_map({_Key, {Subkeys, _Rev}}, Map) when is_list(Subkeys) ->
    lists:foldl(dir_content_to_map(_, _), Map, Subkeys);
dir_content_to_map({Key, {dir, _Rev}}, Map) ->
    maps:put(Key, dir, Map);
dir_content_to_map({Key, {Value, _Rev, _Sensitive}}, Map) ->
    maps:put(Key, Value, Map).

dir_sensitivity(Dir) ->
    {ok, {{_Dir, {Entries, _}}, _}} = get_dir(Dir, false),
    lists:sort([{Key, Sensitive} ||
                   {Key, {_Value, _Rev, Sensitive}} <- Entries]).

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
          ({cluster_compat_version, _}) ->
              %% fake_chronicle_kv keeps one snapshot for every rsm, so the
              %% version the tests set turns up in this one as well
              ok;
          (_) ->
              ?assert(false)
      end, maps:to_list(Snapshot)).

test_set(Key, Val, Rev, Recursive) ->
    test_set(Key, Val, Rev, Recursive, undefined).

test_set(Key, Val, Rev, Recursive, Sensitive) ->
    Ret = set(Key, Val, Rev, Recursive, Sensitive),
    check_integrity(),
    Ret.

test_set_multiple(List, Recursive) ->
    test_set_multiple_sensitive([{K, {V, R, undefined}} ||
                                    {K, {V, R}} <- List], Recursive).

test_set_multiple_sensitive(List, Recursive) ->
    Ret = set_multiple(List, Recursive),
    check_integrity(),
    Ret.

stored_value(Key) ->
    {ok, {Stored, _}} = chronicle_kv:get(metakv, {leaf, Key}),
    Stored.

test_mkdir(Dir, Recursive) ->
    Ret = mkdir(Dir, Recursive),
    check_integrity(),
    Ret.

test_delete(Dir) ->
    Ret = delete(Dir),
    check_integrity(),
    Ret.

test_delete_dir(Dir, Recursive) ->
    Ret = delete_dir(Dir, Recursive),
    check_integrity(),
    Ret.

cas_testing(Fun, Create) ->
    Key = [key0, subkey0, root],
    %% new key, non recursive, do not check revision
    ?assertEqual({error, {not_found, [subkey0, root]}},
                 Fun(Key, v1, undefined, false)),

    %% new key, recursive, do not check revision
    Ret = Fun(Key, v1, undefined, true),
    ?assertMatch({ok, _, Create}, Ret),
    {ok, OldRev, _} = Ret,

    %% update, recursive, do not check revision
    ?assertMatch({ok, _, update}, Fun(Key, v2, undefined, true)),
    %% update, non recursive, do not check revision
    Ret1 = Fun(Key, v3, undefined, false),
    ?assertMatch({ok, _, update}, Ret1),
    {ok, LatestRev, _} = Ret1,

    %% update, recursive, old revision
    ?assertEqual({error, {cas, Key, LatestRev}}, Fun(Key, v2, OldRev, true)),
    %% update, non recursive, old revision
    ?assertEqual({error, {cas, Key, LatestRev}}, Fun(Key, v2, OldRev, false)),

    Ret2 = ?MODULE:get(Key),
    ?assertMatch({ok, {v3, LatestRev}}, Ret2),

    %% update, non recursive, new revision
    Ret3 = Fun(Key, v2, LatestRev, false),
    ?assertMatch({ok, _, update}, Ret3),
    {ok, NewRev, _} = Ret3,

    %% update, recursive, new revision
    Ret4 = Fun(Key, v4, NewRev, true),
    ?assertMatch({ok, _, update}, Ret4),
    {ok, NewRev1, _} = Ret4,

    %% update, recursive, expect add on existing key
    ?assertEqual({error, {cas, Key, NewRev1}}, Fun(Key, v5, new, true)),

    %% update, non recursive, expect add on existing key
    ?assertEqual({error, {cas, Key, NewRev1}}, Fun(Key, v5, new, false)),

    %% update, recursive, expect add on non existing key
    ?assertMatch({ok, _, Create}, Fun([key1, subkey1, root], v5, new, true)),

    %% update, non recursive, expect add on non existing key
    ?assertMatch({ok, _, Create}, Fun([key2, subkey1, root], v5, new, false)),

    %% update, recursive, expect revision on non existing key
    ?assertEqual({error, {cas, [key6, subkey6, root], undefined}},
                 Fun([key6, subkey6, root], v5, NewRev1, true)).

basic_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [{"set, get",
       fun () ->
               ?assertEqual({error, not_found},
                            ?MODULE:get([key1, subkey1, root])),
               ?assertEqual({error, {not_found, [subkey1, root]}},
                            test_set([key1, subkey1, root], v1,
                                     undefined, false)),
               ?assertMatch({ok, _, create},
                            test_set([key1, subkey1, root], v1, new, true)),
               ?assertMatch({ok, _, create},
                            test_set([key2, subkey1, root], v2, undefined,
                                     true)),
               ?assertMatch({ok, {v1, _}},
                            ?MODULE:get([key1, subkey1, root])),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [key2, subkey1, root] => v2},
                            get_dir_content([root])),
               ?assertMatch({ok, _, create},
                            test_set([key3, subkey1, root], v3,
                                     new, false)),
               ?assertMatch({ok, {v2, _}},
                            ?MODULE:get([key2, subkey1, root])),
               ?assertEqual(
                  #{[key1, subkey1, root] => v1,
                    [key2, subkey1, root] => v2,
                    [key3, subkey1, root] => v3},
                  get_dir_content([root])),
               ?assertMatch({error, {wrong_type, [subkey1, root]}},
                            test_set([subkey1, root], v2,
                                     new, true)),
               ?assertEqual({error, {top_level_leaf, [topLevelLeaf]}},
                            test_set([topLevelLeaf], v1, undefined, false)),
               ?assertEqual({error, {top_level_leaf, [topLevelLeaf]}},
                            test_set([topLevelLeaf], v1, undefined, true))
       end},
      {"get_dir",
       fun () ->
               ?assertEqual({error, not_found}, get_dir_content([root]), false),
               ?assertEqual({error, not_found}, get_dir_content([root]), true),
               ?assertMatch({ok, _, create},
                            test_set([key1, subkey1, root], v1, new, true)),
               ?assertMatch({ok, _, create},
                            test_set([key1, subkey2, subkey1, root],
                                     v2, new, true)),
               ?assertEqual(#{}, get_dir_content([root], false)),
               ?assertEqual(#{[key1, subkey1, root] => v1},
                            get_dir_content([subkey1, root], false)),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [key1, subkey2, subkey1, root] => v2},
                            get_dir_content([subkey1, root], true)),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [subkey2, subkey1, root] => dir},
                            get_dir_content([subkey1, root], true, 1)),
               ?assertEqual(#{[subkey1, root] => dir},
                            get_dir_content([root], true, 1)),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [subkey2, subkey1, root] => dir},
                            get_dir_content([root], true, 2)),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [key1, subkey2, subkey1, root] => v2},
                            get_dir_content([root], true, 3))
       end},
      {"get_snapshot",
       fun () ->
               ?assertMatch({ok, _, create}, test_set([key1, subkey1, root], v1,
                                                      new, true)),
               ?assertMatch({ok, _, create}, test_set([key3, subkey1, root], v3,
                                                      new, true)),
               ?assertMatch({ok, _, create}, test_set([key2, subkey2, root], v2,
                                                      new, true)),
               ?assertMatch({ok, _, create}, test_set([key4, subkey2, root], v4,
                                                      new, true)),
               ?assertEqual(#{[key1, subkey1, root] => v1,
                              [key2, subkey2, root] => v2,
                              [key3, subkey1, root] => v3},
                            snapshot_to_map(get_snapshot(
                                              [[key1, subkey1, root],
                                               [key3, subkey1, root],
                                               [key2, subkey2, root],
                                               [key3, subkey3, root]])))
       end},
      {"mkdir",
       fun () ->
               ?assertEqual({error, {not_found, [root]}},
                            test_mkdir([subdir1, root], false)),
               ?assertMatch({ok, _, create},
                            test_mkdir([subdir1, root], true)),
               ?assertMatch({ok, _, create},
                            test_mkdir([subdir2, subdir2, root], true)),
               ?assertMatch({ok, _, create},
                            test_set([key1, subdir2, subdir2, root],
                                     v1, new, false)),
               ?assertMatch({error, {exists, [subdir2, subdir2, root], _}},
                            test_mkdir([subdir2, subdir2, root], true)),
               ?assertEqual(
                  {error, {wrong_type, [key1, subdir2, subdir2, root]}},
                  test_mkdir([key1, subdir2, subdir2, root], true)),
               ?assertEqual(
                  {error, {wrong_type, [key1, subdir2, subdir2, root]}},
                  test_mkdir([key1, subdir2, subdir2, root], false)),
               %% creating top level dirs
               ?assertMatch({ok, _, create}, test_mkdir([root1], false)),
               ?assertMatch({ok, _, create}, test_mkdir([root2], true))
       end},
      {"set, revision handling",
       fun () ->
               cas_testing(fun test_set/4, create)
       end},
      {"set_multiple, revision handling",
       fun () ->
               cas_testing(fun (Key, Val, Rev, Recursive) ->
                                   test_set_multiple([{Key, {Val, Rev}}],
                                                     Recursive)
                           end, update)
       end},
      {"set_multiple, revision handling (with other keys)",
       fun () ->
               ?assertMatch({ok, _, create},
                            test_set([key2, subkey2, root], v4, new, true)),
               cas_testing(
                 fun (Key, Val, Rev, Recursive) ->
                         test_set_multiple(
                           [{Key, {Val, Rev}},
                            {[key2, subkey2, root], {v8, undefined}}],
                           Recursive)
                 end, update)
       end},
      {"set_multiple, other errors",
       fun () ->
               ?assertEqual(
                  {error, duplicate_keys},
                  test_set_multiple(
                    [{[key1, subkey1, root], {v1, new}},
                     {[key2, subkey2, root], {v2, new}},
                     {[key1, subkey1, root], {v3, new}}], true)),
               ?assertEqual({error, {top_level_leaf, [topLevelLeaf]}},
                            test_set_multiple(
                              [{[topLevelLeaf], {v1, undefined}},
                               {[key1, subkey1, root], {v1, new}}], true)),
               ?assertEqual({error, {top_level_leaf, [topLevelLeaf]}},
                            test_set_multiple(
                              [{[topLevelLeaf], {v1, undefined}},
                               {[key1, subkey1, root], {v1, new}}], false)),
               RV = test_set_multiple(
                      [{[topLevelLeaf1], {v1, undefined}},
                       {[topLevelLeaf2], {v2, undefined}},
                       {[key1, subkey1, root], {v1, new}}], false),
               ?assertMatch({error, {top_level_leaf, [_]}}, RV),
               {error, {top_level_leaf, [Key]}} = RV,
               ?assert(lists:member(Key, [topLevelLeaf1, topLevelLeaf2]))
       end},
      {"not changed",
       fun () ->
               ?assertMatch({ok, _, create},
                            test_set([key2, subkey2, root], v4, new, true)),
               Ret = test_set([key1, subkey1, root], v0, new, true),
               ?assertMatch({ok, _, create}, Ret),
               {ok, Rev, _} = Ret,
               ?assertEqual({error, {not_changed, [key1, subkey1, root], Rev}},
                            test_set([key1, subkey1, root], v0,
                                     undefined, true)),
               ?assertEqual({error, {not_changed, [key1, subkey1, root], Rev}},
                            test_set([key1, subkey1, root], v0, Rev, false)),
               ?assertEqual({error, not_changed},
                            test_set_multiple(
                              [{[key1, subkey1, root], {v0, Rev}}], false)),
               ?assertEqual({error, not_changed},
                            test_set_multiple(
                              [{[key1, subkey1, root], {v0, Rev}},
                               {[key2, subkey2, root], {v4, undefined}}],
                              false)),
               ?assertMatch({ok, _, update},
                            test_set_multiple(
                              [{[key1, subkey1, root], {v1, Rev}},
                               {[key2, subkey2, root], {v4, undefined}}],
                              false))
       end},
      {"delete",
       fun () ->
               ?assertEqual({error, not_found},
                            test_delete([key1, subkey1, root])),
               ?assertMatch({ok, _, create},
                            test_set([key1, subkey1, root], v0, new, true)),
               ?assertMatch({ok, _}, test_delete([key1, subkey1, root])),
               ?assertEqual({error, not_found},
                            ?MODULE:get([key1, subkey1, root]))
       end},
      {"delete_dir",
       fun () ->
               %% no parent dir
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], false)),
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], true)),

               %% dir not found
               ?assertMatch({ok, _, create}, test_mkdir([root], true)),
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], false)),
               ?assertEqual({error, not_found},
                            test_delete_dir([subkey1, root], true)),

               %% attempt to non recursively delete non empty dir
               ?assertMatch({ok, _, create},
                            test_set([key1, subkey1, root], v0, new, true)),
               ?assertMatch({ok, _, create},
                            test_set([key2, subkey3, subkey2, subkey1, root],
                                     v1, new, true)),
               ?assertEqual({error, not_empty},
                            test_delete_dir([subkey1, root], false)),

               %% non recursive delete of empty dir
               ?assertMatch({ok, _, create}, test_mkdir([subkey2, root], true)),
               ?assertMatch({ok, _}, test_delete_dir([subkey2, root], false)),

               %% recursive delete of non empty dir
               ?assertMatch({ok, _}, test_delete_dir([subkey1, root], true)),

               ?assertEqual({error, not_found},
                            get_dir([subkey1, root], false)),
               ?assertEqual({error, not_found},
                            get_dir([subkey2, root], false)),
               ?assertMatch({ok, {{[root], {[], _}}, _}},
                            get_dir([root], true)),

               %% non recursive delete of empty root dir
               ?assertMatch({ok, _}, test_delete_dir([root], false)),
               ?assertEqual({error, not_found}, get_dir([root], false)),

               %% recursive delete of non empty root dir
               ?assertMatch({ok, _, create},
                            test_set([key1, subkey1, root], v0, new, true)),
               ?assertMatch({ok, _}, test_delete_dir([root], true)),
               ?assertEqual({error, not_found}, get_dir([root], false))
       end},
      {"sensitive leaves are stored tagged and read back bare",
       fun () ->
               Key = [key1, subkey1, root],
               Plain = [key2, subkey1, root],
               ?assertMatch({ok, _, create},
                            test_set(Key, v1, new, true, true)),
               ?assertMatch({ok, _, create},
                            test_set(Plain, v1, new, true, false)),

               ?assertEqual({?METAKV2_SENSITIVE, v1}, stored_value(Key)),
               ?assertEqual(v1, stored_value(Plain)),

               %% the tag is stripped on every read path, and none of them
               %% but the directory listing reports sensitivity at all
               ?assertMatch({ok, {v1, _}}, ?MODULE:get(Key)),
               ?assertMatch({ok, {v1, _}}, ?MODULE:get(Plain)),
               ?assertEqual(#{Key => v1, Plain => v1},
                            snapshot_to_map(get_snapshot([Key, Plain]))),
               ?assertEqual(#{Key => v1, Plain => v1},
                            get_dir_content([root])),
               ?assertEqual([{Key, true}, {Plain, false}],
                            dir_sensitivity([subkey1, root]))
       end},
      {"an update that does not state the flag carries it forward",
       fun () ->
               Key = [key1, subkey1, root],
               Plain = [key2, subkey1, root],
               ?assertMatch({ok, _, create},
                            test_set(Key, v1, new, true, true)),
               ?assertMatch({ok, _, create},
                            test_set(Plain, v1, new, true, false)),

               ?assertMatch({ok, _, update},
                            test_set(Key, v2, undefined, false, undefined)),
               ?assertEqual({?METAKV2_SENSITIVE, v2}, stored_value(Key)),
               ?assertEqual([{Key, true}, {Plain, false}],
                            dir_sensitivity([subkey1, root])),

               ?assertMatch({ok, _, update},
                            test_set(Plain, v2, undefined, false, undefined)),
               ?assertEqual(v2, stored_value(Plain)),

               ?assertMatch({ok, _, update},
                            test_set_multiple_sensitive(
                              [{Key, {v3, undefined, undefined}},
                               {Plain, {v3, undefined, undefined}}], false)),
               ?assertEqual({?METAKV2_SENSITIVE, v3}, stored_value(Key)),
               ?assertEqual(v3, stored_value(Plain)),

               %% restating the flag it already has is accepted
               ?assertMatch({ok, _, update},
                            test_set(Key, v4, undefined, false, true)),
               ?assertEqual({?METAKV2_SENSITIVE, v4}, stored_value(Key)),
               ?assertMatch({ok, _, update},
                            test_set(Plain, v4, undefined, false, false)),
               ?assertEqual(v4, stored_value(Plain))
       end},
      {"an update that asks to change the flag is refused",
       fun () ->
               Key = [key1, subkey1, root],
               Plain = [key2, subkey1, root],
               ?assertMatch({ok, _, create},
                            test_set(Key, v1, new, true, true)),
               ?assertMatch({ok, _, create},
                            test_set(Plain, v1, new, true, false)),

               %% asking to protect a key that is not protected is the
               %% dangerous direction, since dropping it silently would leave
               %% the caller thinking the value was safe
               ?assertEqual({error, {sensitive_mismatch, Plain}},
                            test_set(Plain, v2, undefined, false, true)),
               ?assertEqual(v1, stored_value(Plain)),

               %% and the other direction is refused too
               ?assertEqual({error, {sensitive_mismatch, Key}},
                            test_set(Key, v2, undefined, false, false)),
               ?assertEqual({?METAKV2_SENSITIVE, v1}, stored_value(Key)),

               %% a value that happens to be unchanged must not let the
               %% refusal slip through as not_changed
               ?assertEqual({error, {sensitive_mismatch, Plain}},
                            test_set(Plain, v1, undefined, false, true)),
               ?assertEqual({error, {sensitive_mismatch, Key}},
                            test_set(Key, v1, undefined, false, false)),

               %% one bad entry aborts the whole transaction
               ?assertEqual({error, {sensitive_mismatch, Plain}},
                            test_set_multiple_sensitive(
                              [{Key, {v9, undefined, undefined}},
                               {Plain, {v9, undefined, true}}], false)),
               ?assertEqual({?METAKV2_SENSITIVE, v1}, stored_value(Key)),
               ?assertEqual(v1, stored_value(Plain)),

               %% and the same when the entry's value is unchanged
               ?assertEqual({error, {sensitive_mismatch, Plain}},
                            test_set_multiple_sensitive(
                              [{Plain, {v1, undefined, true}}], false)),

               %% recreating the key is the only way to change it
               ?assertMatch({ok, _}, test_delete(Plain)),
               ?assertMatch({ok, _, create},
                            test_set(Plain, v2, new, false, true)),
               ?assertEqual({?METAKV2_SENSITIVE, v2}, stored_value(Plain))
       end},
      {"not changed is detected through the tag",
       fun () ->
               Key = [key1, subkey1, root],
               Ret = test_set(Key, v1, new, true, true),
               ?assertMatch({ok, _, create}, Ret),
               {ok, Rev, _} = Ret,

               %% the stored value is wrapped, so comparing it against the
               %% incoming bare value has to strip the tag first
               ?assertEqual({error, {not_changed, Key, Rev}},
                            test_set(Key, v1, undefined, false, true)),
               ?assertEqual({error, {not_changed, Key, Rev}},
                            test_set(Key, v1, undefined, false, undefined)),
               ?assertEqual({error, not_changed},
                            test_set_multiple_sensitive(
                              [{Key, {v1, undefined, undefined}}], false))
       end},
      {"a sensitive leaf is refused until the cluster is upgraded",
       fun () ->
               Key = [key1, subkey1, root],
               fake_chronicle_kv:setup_cluster_compat_version(?VERSION_80),

               ?assertEqual({error, {sensitive_unsupported, Key}},
                            test_set(Key, v1, new, true, true)),
               ?assertEqual({error, not_found}, ?MODULE:get(Key)),
               ?assertEqual({error, {sensitive_unsupported, Key}},
                            test_set_multiple_sensitive(
                              [{Key, {v1, new, true}}], true)),
               ?assertEqual({error, not_found}, ?MODULE:get(Key)),

               %% a write that does not ask for the flag is unaffected, and so
               %% is one that asks for the flag to be off, since neither
               %% stores anything an older node cannot read
               ?assertMatch({ok, _, create},
                            test_set(Key, v1, new, true, false)),
               ?assertEqual(v1, stored_value(Key)),

               %% and the flag is taken once the cluster is upgraded
               fake_chronicle_kv:setup_cluster_compat_version(?VERSION_TOTORO),
               Key2 = [key2, subkey1, root],
               ?assertMatch({ok, _, create},
                            test_set(Key2, v1, new, true, true)),
               ?assertEqual({?METAKV2_SENSITIVE, v1}, stored_value(Key2))
       end}]}.

-endif.
