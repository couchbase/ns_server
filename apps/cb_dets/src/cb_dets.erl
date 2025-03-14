%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 1996-2022. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%

%%
%% Oct 31, 2024 - Added ability to use custom term_to_binary and binary_to_term
%%                functions (by Couchbase <info@couchbase.com>)
%%
-module(cb_dets).

%% Disk based linear hashing lookup dictionary.

%% Public.
-export([all/0,
	 bchunk/2,
         close/1,
         delete/2,
         delete_all_objects/1,
         delete_object/2,
         first/1,
         foldl/3,
         foldr/3,
         from_ets/2,
         info/1,
         info/2,
         init_table/2,
	 init_table/3,
         insert/2,
         insert_new/2,
         is_compatible_bchunk_format/2,
	 is_cb_dets_file/1,
         lookup/2,
         match/1,
         match/2,
         match/3,
         match_delete/2,
         match_object/1,
         match_object/2,
         match_object/3,
         member/2,
         next/2,
         open_file/1,
         open_file/2,
         pid2name/1,
         repair_continuation/2,
         safe_fixtable/2,
         select/1,
         select/2,
         select/3,
         select_delete/2,
         slot/2,
         sync/1,
         table/1,
         table/2,
         to_ets/2,
         traverse/2,
         update_counter/3]).

%% Server export.
-export([start/0, stop/0]).

%% Internal exports.
-export([istart_link/1, init/2, internal_open/3, add_user/3, 
         internal_close/1, remove_user/2,
	 system_continue/3, system_terminate/4, system_code_change/4]).

%% Debug.
-export([file_info/1,
	 fsck/1,
         fsck/2,
	 get_head_field/2,
	 view/1,
	 where/2,
	 verbose/0,
	 verbose/1
	]).

%% Not documented, or not ready for publication.
-export([lookup_keys/2]).

-export_type([bindings_cont/0, cont/0, object_cont/0, select_cont/0,
              tab_name/0]).

-compile({inline, [{einval,2},{badarg,2},{undefined,1},
                   {badarg_exit,2},{lookup_reply,2},
                   {pidof,1},{resp,2}]}).

-include_lib("kernel/include/file.hrl").

-include("cb_dets.hrl").

%%% This is the implementation of the mnesia file storage. Each (non
%%% ram-copy) table is maintained in a corresponding .DAT file. The
%%% dat file is organized as a segmented linear hashlist. The head of
%%% the file with the split indicator, size etc is held in ram by the
%%% server at all times.
%%%

%%  The method of hashing is the so called linear hashing algorithm
%%  with segments. 
%%
%%  Linear hashing:
%%
%%         - n indicates next bucket to split (initially zero); 
%%         - m is the size of the hash table 
%%         - initially next = m and n = 0
%%  
%%         - to insert: 
%%                - hash = key mod m 
%%                - if hash < n then hash = key mod 2m 
%%                - when the number of objects exceeds the initial size
%%                  of the hash table, each insertion of an object
%%                  causes bucket n to be split:
%%                      - add a new bucket to the end of the table 
%%                      - redistribute the contents of bucket n 
%%                        using hash = key mod 2m 
%%                      - increment n 
%%                      - if n = m then m = 2m, n = 0 
%%         - to search: 
%%                hash = key mod m 
%%                if hash < n then hash = key mod 2m 
%%                do linear scan of the bucket 
%%  

%%% If a file error occurs on a working cb_dets file, update_mode is set
%%% to the error tuple. When in 'error' mode, the free lists are not
%%% written, and a repair is forced next time the file is opened.

-record(cb_dets_cont, {
          what :: 'undefined' | 'bchunk' | 'bindings' | 'object' | 'select',
          no_objs :: 'default' | pos_integer(), % requested number of objects
          bin :: 'eof' | binary(), % small chunk not consumed,
                                  % or 'eof' at end-of-file
          alloc :: binary() % the part of the file not yet scanned
                 | {From :: non_neg_integer(),
                    To :: non_neg_integer,
                    binary()},
          tab :: tab_name(),
          proc :: 'undefined' | pid(), % the pid of the Dets process
          match_program :: 'true'
                         | 'undefined'
                         | {'match_spec', ets:compiled_match_spec()}
	 }).

-record(open_args, {
          file :: list(),
          type :: type(),
          keypos :: keypos(),
          repair :: 'force' | boolean(),
          min_no_slots :: no_slots(),
	  max_no_slots :: no_slots(),
          ram_file :: boolean(),
          delayed_write :: cache_parms(),
          auto_save :: auto_save(),
          access :: access(),
          debug :: boolean()
         }).

-define(PATTERN_TO_OBJECT_MATCH_SPEC(Pat), [{Pat,[],['$_']}]).
-define(PATTERN_TO_BINDINGS_MATCH_SPEC(Pat), [{Pat,[],['$$']}]).
-define(PATTERN_TO_TRUE_MATCH_SPEC(Pat), [{Pat,[],[true]}]).

%%-define(DEBUGM(X, Y), io:format(X, Y)).
-define(DEBUGM(X, Y), true).

%%-define(DEBUGF(X,Y), io:format(X, Y)).
-define(DEBUGF(X,Y), void).

%%-define(PROFILE(C), C).
-define(PROFILE(C), void).

-opaque bindings_cont() :: #cb_dets_cont{}.
-opaque cont()    :: #cb_dets_cont{}.
-type match_spec()  :: ets:match_spec().
-type object()    :: tuple().
-opaque object_cont() :: #cb_dets_cont{}.
-type pattern()   :: atom() | tuple().
-opaque select_cont() :: #cb_dets_cont{}.

%%% Some further debug code was added in R12B-1 (stdlib-1.15.1):
%%% - there is a new open_file() option 'debug';
%%% - there is a new OS environment variable 'DETS_DEBUG';
%%% - verbose(true) implies that info messages are written onto
%%%   the error log whenever an unsafe traversal is started.
%%% The 'debug' mode (set by the open_file() option 'debug' or
%%% by os:putenv("DETS_DEBUG", "true")) implies that the results of
%%% calling pwrite() and pread() are tested to some extent. It also
%%% means a considerable overhead when it comes to RAM usage. The
%%% operation of Dets is also slowed down a bit. Note that in debug
%%% mode terms will be output on the error logger.

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

add_user(Pid, Tab, Args) ->
    req(Pid, {add_user, Tab, Args}).

-spec all() -> [tab_name()].

all() ->
    cb_dets_server:all().

-spec bchunk(Name, Continuation) ->
    {Continuation2, Data} | '$end_of_table' | {'error', Reason} when
      Name :: tab_name(),
      Continuation :: 'start' | cont(),
      Continuation2 :: cont(),
      Data :: binary() | tuple(),
      Reason :: term().

bchunk(Tab, start) ->
    badarg(treq(Tab, {bchunk_init, Tab}), [Tab, start]);
bchunk(Tab, #cb_dets_cont{what = bchunk, tab = Tab} = State) ->
    badarg(treq(Tab, {bchunk, State}), [Tab, State]);
bchunk(Tab, Term) ->
    erlang:error(badarg, [Tab, Term]).

-spec close(Name) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      Reason :: term().

close(Tab) ->  
    case cb_dets_server:close(Tab) of
        badarg -> % Should not happen.
	    {error, not_owner}; % Backwards compatibility...
        Reply ->
            Reply
    end.

-spec delete(Name, Key) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      Key :: term(),
      Reason :: term().

delete(Tab, Key) ->
    badarg(treq(Tab, {delete_key, [Key]}), [Tab, Key]).

-spec delete_all_objects(Name) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      Reason :: term().

delete_all_objects(Tab) ->
    case treq(Tab, delete_all_objects) of
	badarg ->
	    erlang:error(badarg, [Tab]);
	fixed ->
	    match_delete(Tab, '_');
	Reply ->
	    Reply
    end.

-spec delete_object(Name, Object) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      Object :: object(),
      Reason :: term().

delete_object(Tab, O) ->
    badarg(treq(Tab, {delete_object, [O]}), [Tab, O]).

%% Backwards compatibility.
fsck(Fname, _Version) ->
    fsck(Fname).

%% Given a filename, fsck it. Debug.
fsck(Fname) ->
    catch begin
      {ok, Fd, FH} = read_file_header(Fname, read, false),
      ?DEBUGF("FileHeader: ~p~n", [FH]),	    
      case cb_dets_v9:check_file_header(FH, Fd) of
          {error, not_closed} ->
              fsck(Fd, make_ref(), Fname, FH, default, default);
          {ok, _Head} ->
              fsck(Fd, make_ref(), Fname, FH, default, default);
          Error ->
              Error
      end
    end.

-spec first(Name) -> Key | '$end_of_table' when
      Name :: tab_name(),
      Key :: term().

first(Tab) ->
    badarg_exit(treq(Tab, first), [Tab]).

-spec foldr(Function, Acc0, Name) -> Acc | {'error', Reason} when
      Name :: tab_name(),
      Function :: fun((Object :: object(), AccIn) -> AccOut),
      Acc0 :: term(),
      Acc :: term(),
      AccIn :: term(),
      AccOut :: term(),
      Reason :: term().

foldr(Fun, Acc, Tab) ->
    foldl(Fun, Acc, Tab).

-spec foldl(Function, Acc0, Name) -> Acc | {'error', Reason} when
      Name :: tab_name(),
      Function :: fun((Object :: object(), AccIn) -> AccOut),
      Acc0 :: term(),
      Acc :: term(),
      AccIn :: term(),
      AccOut :: term(),
      Reason :: term().

foldl(Fun, Acc, Tab) ->
    Ref = make_ref(),
    badarg(do_traverse(Fun, Acc, Tab, Ref), [Fun, Acc, Tab]).

-spec from_ets(Name, EtsTab) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      EtsTab :: ets:table(),
      Reason :: term().

from_ets(DTab, ETab) ->
    ets:safe_fixtable(ETab, true),
    Spec = ?PATTERN_TO_OBJECT_MATCH_SPEC('_'),
    LC = ets:select(ETab, Spec, 100),
    InitFun = from_ets_fun(LC, ETab),
    Reply = treq(DTab, {initialize, InitFun, term, default}),
    ets:safe_fixtable(ETab, false),
    case Reply of 
        {thrown, Thrown} -> throw(Thrown);
        Else -> badarg(Else, [DTab, ETab])
    end.

from_ets_fun(LC, ETab) ->
    fun(close) ->
            ok;
       (read) when LC =:= '$end_of_table' ->
            end_of_input;
       (read) ->
            {L, C} = LC,
            {L, from_ets_fun(ets:select(C), ETab)}
    end.

-spec info(Name) -> InfoList | 'undefined' when
      Name :: tab_name(),
      InfoList :: [InfoTuple],
      InfoTuple :: {'file_size', non_neg_integer()}
                 | {'filename', file:name()}
                 | {'keypos', keypos()}
                 | {'size', non_neg_integer()}
                 | {'type', type()}.

info(Tab) ->
    case catch cb_dets_server:get_pid(Tab) of
	{'EXIT', _Reason} ->
	    undefined;
	Pid ->
	    undefined(req(Pid, info))
    end.

-spec info(Name, Item) -> Value | 'undefined' when
      Name :: tab_name(),
      Item :: 'access' | 'auto_save' | 'bchunk_format'
            | 'hash' | 'file_size' | 'filename' | 'keypos' | 'memory'
            | 'no_keys' | 'no_objects' | 'no_slots' | 'owner' | 'ram_file'
            | 'safe_fixed' | 'safe_fixed_monotonic_time' | 'size' | 'type',
      Value :: term().

info(Tab, owner) ->
    case catch cb_dets_server:get_pid(Tab) of
	Pid when is_pid(Pid) ->
	    Pid;
	_ ->
	    undefined
    end;
info(Tab, users) -> % undocumented
    case cb_dets_server:users(Tab) of
	[] ->
	    undefined;
	Users ->
	    Users
    end;
info(Tab, Tag) ->
    case catch cb_dets_server:get_pid(Tab) of
	{'EXIT', _Reason} ->
	    undefined;
	Pid ->
	    undefined(req(Pid, {info, Tag}))
    end.

-spec init_table(Name, InitFun) -> ok | {'error', Reason} when
      Name :: tab_name(),
      InitFun :: fun((Arg) -> Res),
      Arg :: read | close,
      Res :: end_of_input | {[object()], InitFun} | {Data, InitFun} | term(),
      Reason :: term(),
      Data :: binary() | tuple().

init_table(Tab, InitFun) ->
    init_table(Tab, InitFun, []).

-spec init_table(Name, InitFun, Options) -> ok | {'error', Reason} when
      Name :: tab_name(),
      InitFun :: fun((Arg) -> Res),
      Arg :: read | close,
      Res :: end_of_input | {[object()], InitFun} | {Data, InitFun} | term(),
      Options :: Option | [Option],
      Option :: {min_no_slots,no_slots()} | {format,term | bchunk},
      Reason :: term(),
      Data :: binary() | tuple().

init_table(Tab, InitFun, Options) when is_function(InitFun) ->
    case options(Options, [format, min_no_slots]) of
	{badarg,_} -> 
	    erlang:error(badarg, [Tab, InitFun, Options]);
	[Format, MinNoSlots] ->
	    case treq(Tab, {initialize, InitFun, Format, MinNoSlots}) of
		{thrown, Thrown} -> throw(Thrown);
		Else -> badarg(Else, [Tab, InitFun, Options])
	    end
    end;
init_table(Tab, InitFun, Options) ->
    erlang:error(badarg, [Tab, InitFun, Options]).

-spec insert(Name, Objects) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      Objects :: object() | [object()],
      Reason :: term().

insert(Tab, Objs) when is_list(Objs) ->
    badarg(treq(Tab, {insert, Objs}), [Tab, Objs]);
insert(Tab, Obj) ->
    badarg(treq(Tab, {insert, [Obj]}), [Tab, Obj]).

-spec insert_new(Name, Objects) -> boolean() | {'error', Reason} when
      Name :: tab_name(),
      Objects :: object() | [object()],
      Reason :: term().

insert_new(Tab, Objs) when is_list(Objs) ->
    badarg(treq(Tab, {insert_new, Objs}), [Tab, Objs]);
insert_new(Tab, Obj) ->
    badarg(treq(Tab, {insert_new, [Obj]}), [Tab, Obj]).

internal_close(Pid) ->
    req(Pid, close).

internal_open(Pid, Ref, Args) ->
    req(Pid, {internal_open, Ref, Args}).

-spec is_compatible_bchunk_format(Name, BchunkFormat) -> boolean() when
      Name :: tab_name(),
      BchunkFormat :: binary().

is_compatible_bchunk_format(Tab, Term) ->
    badarg(treq(Tab, {is_compatible_bchunk_format, Term}), [Tab, Term]).

-spec is_cb_dets_file(Filename) -> boolean() | {'error', Reason} when
      Filename :: file:name(),
      Reason :: term().

is_cb_dets_file(FileName) ->
    case catch read_file_header(FileName, read, false) of
	{ok, Fd, FH} ->
	    _ = file:close(Fd),
	    FH#fileheader.cookie =:= ?MAGIC;
	{error, {tooshort, _}} ->
	    false;
	{error, {not_a_cb_dets_file, _}} ->
	    false;
	Other ->
	    Other
    end.

-spec lookup(Name, Key) -> Objects | {'error', Reason} when
      Name :: tab_name(),
      Key :: term(),
      Objects :: [object()],
      Reason :: term().

lookup(Tab, Key) ->
    badarg(treq(Tab, {lookup_keys, [Key]}), [Tab, Key]).

%% Not public.
lookup_keys(Tab, Keys) ->
    case catch lists:usort(Keys) of
	UKeys when is_list(UKeys), UKeys =/= [] ->
	    badarg(treq(Tab, {lookup_keys, UKeys}), [Tab, Keys]);
	_Else ->
	    erlang:error(badarg, [Tab, Keys])
    end.

-spec match(Name, Pattern) -> [Match] | {'error', Reason} when
      Name :: tab_name(),
      Pattern :: pattern(),
      Match :: [term()],
      Reason :: term().

match(Tab, Pat) ->
    badarg(safe_match(Tab, Pat, bindings), [Tab, Pat]).

-spec match(Name, Pattern, N) ->
          {[Match], Continuation} | '$end_of_table' | {'error', Reason} when
      Name :: tab_name(),
      Pattern :: pattern(),
      N :: 'default' | non_neg_integer(),
      Continuation :: bindings_cont(),
      Match :: [term()],
      Reason :: term().

match(Tab, Pat, N) ->
    badarg(init_chunk_match(Tab, Pat, bindings, N, no_safe), [Tab, Pat, N]).
    
-spec match(Continuation) ->
          {[Match], Continuation2} | '$end_of_table' | {'error', Reason} when
      Continuation :: bindings_cont(),
      Continuation2 :: bindings_cont(),
      Match :: [term()],
      Reason :: term().

match(State) when State#cb_dets_cont.what =:= bindings ->
    badarg(chunk_match(State, no_safe), [State]);
match(Term) ->
    erlang:error(badarg, [Term]).

-spec match_delete(Name, Pattern) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      Pattern :: pattern(),
      Reason :: term().

match_delete(Tab, Pat) ->
    badarg(match_delete(Tab, Pat, delete), [Tab, Pat]).

match_delete(Tab, Pat, What) ->
    case compile_match_spec(What, Pat) of
	{Spec, MP} ->
            case catch cb_dets_server:get_pid(Tab) of
                {'EXIT', _Reason} ->
                    badarg;
                Proc ->
                    R = req(Proc, {match_delete_init, MP, Spec}),
                    do_match_delete(Proc, R, What, 0)
            end;
	badarg ->
	    badarg
    end.

do_match_delete(_Proc, {done, N1}, select, N) ->
    N + N1;
do_match_delete(_Proc, {done, _N1}, _What, _N) ->
    ok;
do_match_delete(Proc, {cont, State, N1}, What, N) ->
    do_match_delete(Proc, req(Proc, {match_delete, State}), What, N+N1);
do_match_delete(_Proc, Error, _What, _N) ->
    Error.

-spec match_object(Name, Pattern) -> Objects | {'error', Reason} when
      Name :: tab_name(),
      Pattern :: pattern(),
      Objects :: [object()],
      Reason :: term().

match_object(Tab, Pat) ->
    badarg(safe_match(Tab, Pat, object), [Tab, Pat]).

-spec match_object(Name, Pattern, N) ->
           {Objects, Continuation} | '$end_of_table' | {'error', Reason} when
      Name :: tab_name(),
      Pattern :: pattern(),
      N :: 'default' | non_neg_integer(),
      Continuation :: object_cont(),
      Objects :: [object()],
      Reason :: term().

match_object(Tab, Pat, N) ->
    badarg(init_chunk_match(Tab, Pat, object, N, no_safe), [Tab, Pat, N]).
    
-spec match_object(Continuation) ->
           {Objects, Continuation2} | '$end_of_table' | {'error', Reason} when
      Continuation :: object_cont(),
      Continuation2 :: object_cont(),
      Objects :: [object()],
      Reason :: term().

match_object(State) when State#cb_dets_cont.what =:= object ->
    badarg(chunk_match(State, no_safe), [State]);
match_object(Term) ->
    erlang:error(badarg, [Term]).

-spec member(Name, Key) -> boolean() | {'error', Reason} when
      Name :: tab_name(),
      Key :: term(),
      Reason :: term().

member(Tab, Key) ->
    badarg(treq(Tab, {member, Key}), [Tab, Key]).    

-spec next(Name, Key1) -> Key2 | '$end_of_table' when
      Name :: tab_name(),
      Key1 :: term(),
      Key2 :: term().

next(Tab, Key) ->
    badarg_exit(treq(Tab, {next, Key}), [Tab, Key]).

-spec open_file(Filename) -> {'ok', Reference} | {'error', Reason} when
      Filename :: file:name(),
      Reference :: reference(),
      Reason :: term().

%% Assuming that a file already exists, open it with the
%% parameters as already specified in the file itself.
%% Return a ref leading to the file.
open_file(File0) ->
    File = to_list(File0),
    case is_list(File) of
        true ->
            case cb_dets_server:open_file(File) of
                badarg -> % Should not happen.
                    erlang:error(cb_dets_process_died, [File]);
                Reply ->
                    einval(Reply, [File])
            end;
        false ->
	    erlang:error(badarg, [File0])
    end.

-spec open_file(Name, Args) -> {'ok', Name} | {'error', Reason} when
      Name :: tab_name(),
      Args :: [OpenArg],
      OpenArg  :: {'access', access()}
                | {'auto_save', auto_save()}
                | {'estimated_no_objects', non_neg_integer()}
                | {'file', file:name()}
                | {'max_no_slots', no_slots()}
                | {'min_no_slots', no_slots()}
                | {'keypos', keypos()}
                | {'ram_file', boolean()}
                | {'repair', boolean() | 'force'}
                | {'type', type()},
      Reason :: term().

open_file(Tab, Args) when is_list(Args) ->
    case catch defaults(Tab, Args) of
        OpenArgs when is_record(OpenArgs, open_args) ->
            case cb_dets_server:open_file(Tab, OpenArgs) of
                badarg -> % Should not happen.
                    erlang:error(cb_dets_process_died, [Tab, Args]);
                Reply -> 
                    einval(Reply, [Tab, Args])
            end;
	_ ->
	    erlang:error(badarg, [Tab, Args])
    end;
open_file(Tab, Arg) ->
    open_file(Tab, [Arg]).

-spec pid2name(Pid) -> {'ok', Name} | 'undefined' when
      Pid :: pid(),
      Name :: tab_name().

pid2name(Pid) ->
    cb_dets_server:pid2name(Pid).

remove_user(Pid, From) ->
    req(Pid, {close, From}).

-spec repair_continuation(Continuation, MatchSpec) -> Continuation2 when
      Continuation :: select_cont(),
      Continuation2 :: select_cont(),
      MatchSpec :: match_spec().

repair_continuation(#cb_dets_cont{match_program = {match_spec, B}}=Cont, MS) ->
    case ets:is_compiled_ms(B) of
	true ->
	    Cont;
	false ->
            Cont#cb_dets_cont{match_program = {match_spec,
                                            ets:match_spec_compile(MS)}}
    end;
repair_continuation(#cb_dets_cont{}=Cont, _MS) ->
    Cont;
repair_continuation(T, MS) ->
    erlang:error(badarg, [T, MS]).

-spec safe_fixtable(Name, Fix) -> 'ok' when
      Name :: tab_name(),
      Fix :: boolean().

safe_fixtable(Tab, Bool) when Bool; not Bool ->
    badarg(treq(Tab, {safe_fixtable, Bool}), [Tab, Bool]);
safe_fixtable(Tab, Term) ->
    erlang:error(badarg, [Tab, Term]).

-spec select(Name, MatchSpec) -> Selection | {'error', Reason} when
      Name :: tab_name(),
      MatchSpec :: match_spec(),
      Selection :: [term()],
      Reason :: term().

select(Tab, Pat) ->
    badarg(safe_match(Tab, Pat, select), [Tab, Pat]).

-spec select(Name, MatchSpec, N) ->
          {Selection, Continuation} | '$end_of_table' | {'error', Reason} when
      Name :: tab_name(),
      MatchSpec :: match_spec(),
      N :: 'default' | non_neg_integer(),
      Continuation :: select_cont(),
      Selection :: [term()],
      Reason :: term().

select(Tab, Pat, N) ->
    badarg(init_chunk_match(Tab, Pat, select, N, no_safe), [Tab, Pat, N]).
    
-spec select(Continuation) ->
          {Selection, Continuation2} | '$end_of_table' | {'error', Reason} when
      Continuation :: select_cont(),
      Continuation2 :: select_cont(),
      Selection :: [term()],
      Reason :: term().

select(State) when State#cb_dets_cont.what =:= select ->
    badarg(chunk_match(State, no_safe), [State]);
select(Term) ->
    erlang:error(badarg, [Term]).

-spec select_delete(Name, MatchSpec) -> N | {'error', Reason} when
      Name :: tab_name(),
      MatchSpec :: match_spec(),
      N :: non_neg_integer(),
      Reason :: term().

select_delete(Tab, Pat) ->
    badarg(match_delete(Tab, Pat, select), [Tab, Pat]).

-spec slot(Name, I) -> '$end_of_table' | Objects | {'error', Reason} when
      Name :: tab_name(),
      I :: non_neg_integer(),
      Objects :: [object()],
      Reason :: term().

slot(Tab, Slot) when is_integer(Slot), Slot >= 0 ->
    badarg(treq(Tab, {slot, Slot}), [Tab, Slot]);
slot(Tab, Term) ->
    erlang:error(badarg, [Tab, Term]).

start() ->
    cb_dets_server:start().

stop() ->
    cb_dets_server:stop().

istart_link(Server) ->
    {ok, proc_lib:spawn_link(cb_dets, init, [self(), Server])}.

-spec sync(Name) -> 'ok' | {'error', Reason} when
      Name :: tab_name(),
      Reason :: term().

sync(Tab) ->
    badarg(treq(Tab, sync), [Tab]).

-spec table(Name) -> QueryHandle when
      Name :: tab_name(),
      QueryHandle :: qlc:query_handle().

table(Tab) ->
    table(Tab, []).

-spec table(Name, Options) -> QueryHandle when
      Name :: tab_name(),
      Options :: Option | [Option],
      Option :: {'n_objects', Limit}
              | {'traverse', TraverseMethod},
      Limit :: 'default' | pos_integer(),
      TraverseMethod :: 'first_next' | 'select' | {'select', match_spec()},
      QueryHandle :: qlc:query_handle().

table(Tab, Opts) ->
    case options(Opts, [traverse, n_objects]) of
        {badarg,_} ->
            erlang:error(badarg, [Tab, Opts]);
        [Traverse, NObjs] ->
            TF = case Traverse of
                     first_next -> 
                         fun() -> qlc_next(Tab, first(Tab)) end;
                     select -> 
                         fun(MS) -> qlc_select(select(Tab, MS, NObjs)) end;
                     {select, MS} ->
                         fun() -> qlc_select(select(Tab, MS, NObjs)) end
                 end,
            PreFun = fun(_) -> safe_fixtable(Tab, true) end,
            PostFun = fun() -> safe_fixtable(Tab, false) end,
            InfoFun = fun(Tag) -> table_info(Tab, Tag) end,
            %% lookup_keys is not public, but convenient
            LookupFun = 
                case Traverse of
                    {select, _MS} -> 
                        undefined;
                    _ -> 
                        fun(_KeyPos, [K]) -> lookup(Tab, K);
                           (_KeyPos, Ks) -> lookup_keys(Tab, Ks) 
                        end
                end,
            FormatFun = 
                fun({all, _NElements, _ElementFun}) ->
                        As = [Tab | [Opts || _ <- [[]], Opts =/= []]],
                        {?MODULE, table, As};
                   ({match_spec, MS}) ->
                        {?MODULE, table, [Tab, [{traverse, {select, MS}} | 
                                                listify(Opts)]]};
                   ({lookup, _KeyPos, [Value], _NElements, ElementFun}) ->
                        io_lib:format("~w:lookup(~w, ~w)", 
                                      [?MODULE, Tab, ElementFun(Value)]);
                   ({lookup, _KeyPos, Values, _NElements, ElementFun}) ->
                        Vals = [ElementFun(V) || V <- Values],
                        io_lib:format("lists:flatmap(fun(V) -> "
                                      "~w:lookup(~w, V) end, ~w)", 
                                      [?MODULE, Tab, Vals])
                end,
            qlc:table(TF, [{pre_fun, PreFun}, {post_fun, PostFun}, 
                           {info_fun, InfoFun}, {format_fun, FormatFun},
                           {key_equality, '=:='},
                           {lookup_fun, LookupFun}])
    end.
         
qlc_next(_Tab, '$end_of_table') ->
    [];
qlc_next(Tab, Key) ->
    case lookup(Tab, Key) of
        Objects when is_list(Objects) ->
            Objects ++ fun() -> qlc_next(Tab, next(Tab, Key)) end;
        Error ->
            %% Do what first and next do.
            exit(Error)
    end.

qlc_select('$end_of_table') -> 
    [];
qlc_select({Objects, Cont}) when is_list(Objects) -> 
    Objects ++ fun() -> qlc_select(select(Cont)) end;
qlc_select(Error) ->
    Error.

table_info(Tab, num_of_objects) ->
    info(Tab, size);
table_info(Tab, keypos) ->
    info(Tab, keypos);
table_info(Tab, is_unique_objects) ->
    info(Tab, type) =/= duplicate_bag;
table_info(_Tab, _) ->
    undefined.

%% End of table/2.

-spec to_ets(Name, EtsTab) -> EtsTab | {'error', Reason} when
      Name :: tab_name(),
      EtsTab :: ets:table(),
      Reason :: term().

to_ets(DTab, ETab) ->
    case ets:info(ETab, protection) of
	undefined ->
	    erlang:error(badarg, [DTab, ETab]);
        _ ->
	    Fun = fun(X, T) -> true = ets:insert(T, X), T end,
	    foldl(Fun, ETab, DTab)
    end.

-spec traverse(Name, Fun) -> Return | {'error', Reason} when
      Name :: tab_name(),
      Fun :: fun((Object) -> FunReturn),
      Object :: object(),
      FunReturn :: 'continue'
                 | {'continue', Val}
                 | {'done', Value}
                 | OtherValue,
      Return :: [term()] | OtherValue,
      Val :: term(),
      Value :: term(),
      OtherValue :: term(),
      Reason :: term().

traverse(Tab, Fun) ->
    Ref = make_ref(),
    TFun = 
	fun(O, Acc) ->
		case Fun(O) of
		    continue  ->
			Acc;
		    {continue, Val} ->
			[Val | Acc];
		    {done, Value} ->
			throw({Ref, [Value | Acc]});
		    Other ->
			throw({Ref, Other})
		end
	end,
    badarg(do_traverse(TFun, [], Tab, Ref), [Tab, Fun]).

-spec update_counter(Name, Key, Increment) -> Result when
      Name :: tab_name(),
      Key :: term(),
      Increment :: {Pos, Incr} | Incr,
      Pos :: integer(),
      Incr :: integer(),
      Result :: integer().

update_counter(Tab, Key, C) ->
    badarg(treq(Tab, {update_counter, Key, C}), [Tab, Key, C]).

verbose() ->           
    verbose(true).

verbose(What) ->
    ok = cb_dets_server:verbose(What),
    All = cb_dets_server:all(),
    Fun = fun(Tab) -> treq(Tab, {set_verbose, What}) end,
    lists:foreach(Fun, All),
    All.

%% Where in the (open) table is Object located? 
%% The address of the first matching object is returned.
%% Format 9 returns the address of the object collection.
%% -> {ok, Address} | false
where(Tab, Object) ->
    badarg(treq(Tab, {where, Object}), [Tab, Object]).

do_traverse(Fun, Acc, Tab, Ref) ->
    case catch cb_dets_server:get_pid(Tab) of
        {'EXIT', _Reason} ->
            badarg;
        Proc ->
            try
                do_trav(Proc, Acc, Fun)
            catch {Ref, Result} ->
                Result
            end
    end.

do_trav(Proc, Acc, Fun) ->
    {Spec, MP} = compile_match_spec(object, '_'),
    %% MP not used
    case req(Proc, {match, MP, Spec, default, safe}) of
	{cont, State} ->
	    do_trav(State, Proc, Acc, Fun);
	Error ->
	    Error
    end.
    
do_trav(State, Proc, Acc, Fun) ->
    case req(Proc, {match_init, State, safe}) of
        '$end_of_table'->
            Acc;
	{cont, {Bins, NewState}} ->
	    do_trav_bins(NewState, Proc, Acc, Fun, lists:reverse(Bins));
	Error ->
	    Error
    end.

do_trav_bins(State, Proc, Acc, Fun, []) ->
    do_trav(State, Proc, Acc, Fun);
do_trav_bins(State, Proc, Acc, Fun, [Bin | Bins]) ->
    %% Unpack one binary at a time, using the client's heap.
    case catch cb_dets_utils:binary_to_term_callback(Bin) of
	{'EXIT', _} ->
	    req(Proc, {corrupt, cb_dets_utils:bad_object(do_trav_bins, Bin)});
	Term ->
	    NewAcc = Fun(Term, Acc),
	    do_trav_bins(State, Proc, NewAcc, Fun, Bins)
    end.

safe_match(Tab, Pat, What) ->
    do_safe_match(init_chunk_match(Tab, Pat, What, default, safe), []).
    
do_safe_match({error, Error}, _L) ->
    {error, Error};
do_safe_match({L, C}, LL) ->
    do_safe_match(chunk_match(C, safe), L++LL);
do_safe_match('$end_of_table', L) ->
    L;
do_safe_match(badarg, _L) ->
    badarg.

%% What = object | bindings | select
init_chunk_match(Tab, Pat, What, N, Safe) when is_integer(N), N >= 0;
                                               N =:= default ->
    case compile_match_spec(What, Pat) of
	{Spec, MP} ->
            case catch cb_dets_server:get_pid(Tab) of
                {'EXIT', _Reason} ->
                    badarg;
                Proc ->
                    case req(Proc, {match, MP, Spec, N, Safe}) of
                        {done, L} ->
                            {L, #cb_dets_cont{tab = Tab, proc = Proc,
                                           what = What, bin = eof,
                                           no_objs = default,
                                           alloc = <<>>}};
                        {cont, State} ->
                            chunk_match(State#cb_dets_cont{what = What,
                                                        tab = Tab,
                                                        proc = Proc},
                                       Safe);
                        Error ->
                            Error
                    end
	    end;
	badarg ->
	    badarg
    end;
init_chunk_match(_Tab, _Pat, _What, _N, _Safe) ->
    badarg.

chunk_match(#cb_dets_cont{proc = Proc}=State, Safe) ->
    case req(Proc, {match_init, State, Safe}) of
        '$end_of_table'=Reply ->
            Reply;
        {cont, {Bins, NewState}} ->
            MP = NewState#cb_dets_cont.match_program,
            case catch do_foldl_bins(Bins, MP) of
                {'EXIT', _} ->
                    case ets:is_compiled_ms(MP) of
                        true ->
                            Bad = cb_dets_utils:bad_object(chunk_match, Bins),
                            req(Proc, {corrupt, Bad});
                        false ->
                            badarg
                    end;
                [] ->
                    chunk_match(NewState, Safe);
                Terms ->
                    {Terms, NewState}
            end;
        Error ->
            Error
    end.

do_foldl_bins(Bins, true) ->
    foldl_bins(Bins, []);
do_foldl_bins(Bins, {match_spec, MP}) ->
    foldl_bins(Bins, MP, []).

foldl_bins([], Terms) ->
    %% Preserve time order.
    Terms;
foldl_bins([Bin | Bins], Terms) ->    
    foldl_bins(Bins, [cb_dets_utils:binary_to_term_callback(Bin) | Terms]).

foldl_bins([], _MP, Terms) ->
    %% Preserve time order.
    Terms;
foldl_bins([Bin | Bins], MP, Terms) ->
    Term = cb_dets_utils:binary_to_term_callback(Bin),
    case ets:match_spec_run([Term], MP) of
	[] ->
	    foldl_bins(Bins, MP, Terms);
	[Result] ->
	    foldl_bins(Bins, MP, [Result | Terms])
    end.

%% -> {Spec, binary()} | badarg
compile_match_spec(select, ?PATTERN_TO_OBJECT_MATCH_SPEC('_') = Spec) ->
    {Spec, true};
compile_match_spec(select, Spec) ->
    try {Spec, {match_spec, ets:match_spec_compile(Spec)}}
    catch error:_ -> badarg
    end;
compile_match_spec(object, Pat) ->
    compile_match_spec(select, ?PATTERN_TO_OBJECT_MATCH_SPEC(Pat));
compile_match_spec(bindings, Pat) ->
    compile_match_spec(select, ?PATTERN_TO_BINDINGS_MATCH_SPEC(Pat));
compile_match_spec(delete, Pat) ->
    compile_match_spec(select, ?PATTERN_TO_TRUE_MATCH_SPEC(Pat)).

%% Process the args list as provided to open_file/2.
defaults(Tab, Args) ->
    Defaults0 = #open_args{file = to_list(Tab),
                           type = set,
                           keypos = 1,
                           repair = true, 
                           min_no_slots = default,
                           max_no_slots = default,
                           ram_file = false,
                           delayed_write = ?DEFAULT_CACHE,
                           auto_save = timer:minutes(?DEFAULT_AUTOSAVE),
                           access = read_write,
                           debug = false},
    Fun = fun repl/2,
    Defaults = lists:foldl(Fun, Defaults0, Args),
    true = is_list(Defaults#open_args.file),
    is_comp_min_max(Defaults).

to_list(T) when is_atom(T) -> atom_to_list(T);
to_list(T) -> T.

repl({access, A}, Defs) ->
    mem(A, [read, read_write]),
    Defs#open_args{access = A};
repl({auto_save, Int}, Defs) when is_integer(Int), Int >= 0 ->
    Defs#open_args{auto_save = Int};
repl({auto_save, infinity}, Defs) ->
    Defs#open_args{auto_save =infinity};
repl({cache_size, Int}, Defs) when is_integer(Int), Int >= 0 ->
    %% Recognized, but ignored.
    Defs;
repl({cache_size, infinity}, Defs) ->
    Defs;
repl({delayed_write, default}, Defs) ->
    Defs#open_args{delayed_write = ?DEFAULT_CACHE};
repl({delayed_write, {Delay,Size} = C}, Defs) 
          when is_integer(Delay), Delay >= 0, is_integer(Size), Size >= 0 ->
    Defs#open_args{delayed_write = C};
repl({estimated_no_objects, I}, Defs)  ->
    repl({min_no_slots, I}, Defs);
repl({file, File}, Defs) ->
    Defs#open_args{file = to_list(File)};
repl({keypos, P}, Defs) when is_integer(P), P > 0 ->
    Defs#open_args{keypos =P};
repl({max_no_slots, I}, Defs)  ->
    MaxSlots = is_max_no_slots(I),
    Defs#open_args{max_no_slots = MaxSlots};
repl({min_no_slots, I}, Defs)  ->
    MinSlots = is_min_no_slots(I),
    Defs#open_args{min_no_slots = MinSlots};
repl({ram_file, Bool}, Defs) ->
    mem(Bool, [true, false]),
    Defs#open_args{ram_file = Bool};
repl({repair, T}, Defs) ->
    mem(T, [true, false, force]),
    Defs#open_args{repair = T};
repl({type, T}, Defs) ->
    mem(T, [set, bag, duplicate_bag]),
    Defs#open_args{type =T};
repl({version, Version}, Defs) ->
    %% Backwards compatibility.
    is_version(Version),
    Defs;
repl({debug, Bool}, Defs) ->
    %% Not documented.
    mem(Bool, [true, false]),
    Defs#open_args{debug = Bool};
repl({_, _}, _) ->
    exit(badarg).

is_min_no_slots(default) -> default;
is_min_no_slots(I) when is_integer(I), I >= ?DEFAULT_MIN_NO_SLOTS -> I;
is_min_no_slots(I) when is_integer(I), I >= 0 -> ?DEFAULT_MIN_NO_SLOTS.

is_max_no_slots(default) -> default;
is_max_no_slots(I) when is_integer(I), I > 0, I < 1 bsl 31 -> I.

is_comp_min_max(Defs) ->
    #open_args{max_no_slots = Max, min_no_slots = Min} = Defs,
    if
        Min =:= default -> Defs;
	Max =:= default -> Defs;
	true -> true = Min =< Max, Defs
    end.

is_version(default) -> true;
is_version(9) -> true.

mem(X, L) ->
    case lists:member(X, L) of
	true -> true;
	false -> exit(badarg)
    end.

options(Options, Keys) when is_list(Options) ->
    options(Options, Keys, []);
options(Option, Keys) ->
    options([Option], Keys, []).

options(Options, [Key | Keys], L) when is_list(Options) ->
    V = case lists:keysearch(Key, 1, Options) of
	    {value, {format, Format}} when Format =:= term; 
                                           Format =:= bchunk ->
		{ok, Format};
	    {value, {min_no_slots, I}} ->
		case catch is_min_no_slots(I) of
		    {'EXIT', _} -> badarg;
		    MinNoSlots -> {ok, MinNoSlots}
		end;
            {value, {n_objects, default}} ->
                {ok, default_option(Key)};
            {value, {n_objects, NObjs}} when is_integer(NObjs),
                                             NObjs >= 1 ->
                {ok, NObjs};
            {value, {traverse, select}} ->
                {ok, select};
            {value, {traverse, {select, MS}}} ->
                {ok, {select, MS}};
            {value, {traverse, first_next}} ->
                {ok, first_next};
	    {value, {Key, _}} ->
		badarg;
	    false ->
		Default = default_option(Key),
		{ok, Default}
	end,
    case V of
	badarg ->
	    {badarg, Key};
	{ok, Value} ->
	    NewOptions = lists:keydelete(Key, 1, Options),
	    options(NewOptions, Keys, [Value | L])
    end;
options([], [], L) ->
    lists:reverse(L);
options(Options, _, _L) ->
    {badarg,Options}.

default_option(format) -> term;
default_option(min_no_slots) -> default;
default_option(traverse) -> select;
default_option(n_objects) -> default.

listify(L) when is_list(L) ->
    L;
listify(T) ->
    [T].

treq(Tab, R) ->
    case catch cb_dets_server:get_pid(Tab) of
	Pid when is_pid(Pid) ->
	    req(Pid, R);
	_ ->
	    badarg
    end.

req(Proc, R) ->
    Ref = erlang:monitor(process, Proc),
    Proc ! ?DETS_CALL({self(), Ref}, R),
    receive 
	{'DOWN', Ref, process, Proc, _Info} ->
            badarg;
	{Ref, Reply} ->
	    erlang:demonitor(Ref, [flush]),
	    Reply
    end.

%% Inlined.
pidof({Pid, _Tag}) ->
    Pid.

%% Inlined.
resp({Pid, Tag} = _From, Message) ->
    Pid ! {Tag, Message},
    ok.

%% Inlined.
einval({error, {file_error, _, einval}}, A) ->
    erlang:error(badarg, A);
einval({error, {file_error, _, badarg}}, A) ->
    erlang:error(badarg, A);
einval(Reply, _A) ->
    Reply.

%% Inlined.
badarg(badarg, A) ->
    erlang:error(badarg, A);
badarg(Reply, _A) ->
    Reply.

%% Inlined.
undefined(badarg) ->
    undefined;
undefined(Reply) ->
    Reply.

%% Inlined.
badarg_exit(badarg, A) ->
    erlang:error(badarg, A);
badarg_exit({ok, Reply}, _A) ->
    Reply;
badarg_exit(Reply, _A) ->
    exit(Reply).

%%%-----------------------------------------------------------------
%%% Server functions
%%%-----------------------------------------------------------------

init(Parent, Server) ->
    process_flag(trap_exit, true),
    %% The Dets server pretends the file is open before
    %% internal_open() has been called, which means that unless the
    %% internal_open message is applied first, other processes can
    %% find the pid by calling cb_dets_server:get_pid() and do things
    %% before Head has been initialized properly.
    receive
        ?DETS_CALL(From, {internal_open, Ref, Args}=Op) ->
            try do_internal_open(Parent, Server, From, Ref, Args) of
                Head ->
                    open_file_loop(Head, 0)
            catch
                exit:normal ->
                    exit(normal);
                _:Bad:Stacktrace ->
                    bug_found(no_name, Op, Bad, Stacktrace, From),
                    exit(Bad) % give up
            end
    end.

open_file_loop(Head, N) when element(1, Head#head.update_mode) =:= error ->
    open_file_loop2(Head, N);
open_file_loop(Head, N) ->
    receive 
        %% When the table is fixed it can be assumed that at least one
        %% traversal is in progress. To speed the traversal up three
        %% things have been done:
        %% - prioritize match_init, bchunk, next, and match_delete_init;
        %% - do not peek the message queue for updates;
        %% - wait 1 ms after each update.
        %% next is normally followed by lookup, but since lookup is also
        %% used when not traversing the table, it is not prioritized.
        ?DETS_CALL(From, {match_init, _State, _Safe} = Op) ->
            do_apply_op(Op, From, Head, N);
        ?DETS_CALL(From, {bchunk, _State} = Op) ->
            do_apply_op(Op, From, Head, N);
        ?DETS_CALL(From, {next, _Key} = Op) ->
            do_apply_op(Op, From, Head, N);            
        ?DETS_CALL(From, {match_delete_init, _MP, _Spec} = Op) ->
            do_apply_op(Op, From, Head, N);
        {'EXIT', Pid, Reason} when Pid =:= Head#head.parent ->
            %% Parent orders shutdown.
            _NewHead = do_stop(Head),
            exit(Reason);
        {'EXIT', Pid, Reason} when Pid =:= Head#head.server ->
            %% The server is gone.
            _NewHead = do_stop(Head),
            exit(Reason);
        {'EXIT', Pid, _Reason} ->
            %% A process fixing the table exits.
            H2 = remove_fix(Head, Pid, close),
            open_file_loop(H2, N);
        {system, From, Req} ->
            sys:handle_system_msg(Req, From, Head#head.parent, 
                                  ?MODULE, [], Head)
    after 0 ->
            open_file_loop2(Head, N)
    end.

open_file_loop2(Head, N) ->
    receive
        ?DETS_CALL(From, Op) ->
            do_apply_op(Op, From, Head, N);
        {'EXIT', Pid, Reason} when Pid =:= Head#head.parent ->
            %% Parent orders shutdown.
            _NewHead = do_stop(Head),
            exit(Reason);
        {'EXIT', Pid, Reason} when Pid =:= Head#head.server ->
            %% The server is gone.
            _NewHead = do_stop(Head),
            exit(Reason);
        {'EXIT', Pid, _Reason} ->
            %% A process fixing the table exits.
            H2 = remove_fix(Head, Pid, close),
            open_file_loop(H2, N);
        {system, From, Req} ->
            sys:handle_system_msg(Req, From, Head#head.parent, 
                                  ?MODULE, [], Head);
        Message ->
            error_logger:format("** cb_dets: unexpected message"
                                "(ignored): ~tw~n", [Message]),
            open_file_loop(Head, N)
    end.

do_apply_op(Op, From, Head, N) ->
    try apply_op(Op, From, Head, N) of
        ok -> 
            open_file_loop(Head, N);
        {N2, H2} when is_record(H2, head), is_integer(N2) ->
            open_file_loop(H2, N2);
        H2 when is_record(H2, head) ->
            open_file_loop(H2, N);
        {{more,From1,Op1,N1}, NewHead} ->
            do_apply_op(Op1, From1, NewHead, N1)
    catch 
        exit:normal -> 
            exit(normal);
        _:Bad:Stacktrace -> 
            bug_found(Head#head.name, Op, Bad, Stacktrace, From),
            open_file_loop(Head, N)
    end.

apply_op(Op, From, Head, N) ->
    case Op of
	{add_user, Tab, OpenArgs}->
            #open_args{file = Fname, type = Type, keypos = Keypos, 
                       ram_file = Ram, access = Access} = OpenArgs,
	    %% min_no_slots and max_no_slots are not tested
	    Res = if
		      Tab =:= Head#head.name,
		      Head#head.keypos =:= Keypos,
		      Head#head.type =:= Type,
		      Head#head.ram_file =:= Ram,
		      Head#head.access =:= Access,
		      Fname =:= Head#head.filename ->
			  ok;
		      true ->
			  err({error, incompatible_arguments})
		  end,
	    resp(From, Res),
	    ok;
	auto_save ->
	    case Head#head.update_mode of
		saved ->
		    Head;
		{error, _Reason} ->
		    Head;
		_Dirty when N =:= 0 -> % dirty or new_dirty
		    %% The updates seems to have declined
		    cb_dets_utils:vformat("** cb_dets: Auto save of ~tp\n",
                                       [Head#head.name]), 
		    {NewHead, _Res} = perform_save(Head, true),
		    erlang:garbage_collect(),
		    {0, NewHead};
		dirty -> 
		    %% Reset counter and try later
		    start_auto_save_timer(Head),
		    {0, Head}
	    end;
	close  ->
	    resp(From, fclose(Head)),
	    _NewHead = unlink_fixing_procs(Head),
	    ?PROFILE(ep:done()),
	    exit(normal);
	{close, Pid} -> 
	    %% Used from cb_dets_server when Pid has closed the table,
	    %% but the table is still opened by some process.
	    NewHead = remove_fix(Head, Pid, close),
	    resp(From, status(NewHead)),
	    NewHead;
	{corrupt, Reason} ->
	    {H2, Error} = cb_dets_utils:corrupt_reason(Head, Reason),
	    resp(From, Error),
	    H2;
	{delayed_write, WrTime} ->
	    delayed_write(Head, WrTime);
	info ->
	    {H2, Res} = finfo(Head),
	    resp(From, Res),
	    H2;
	{info, Tag} ->
	    {H2, Res} = finfo(Head, Tag),
	    resp(From, Res),
	    H2;
        {is_compatible_bchunk_format, Term} ->
            Res = test_bchunk_format(Head, Term),
            resp(From, Res),
            ok;
	{internal_open, Ref, Args} ->
            do_internal_open(Head#head.parent, Head#head.server, From,
                             Ref, Args);
	may_grow when Head#head.update_mode =/= saved ->
	    if
		Head#head.update_mode =:= dirty ->
		    %% Won't grow more if the table is full.
		    {H2, _Res} = 
			cb_dets_v9:may_grow(Head, 0, many_times),
		    {N + 1, H2};
		true -> 
		    ok
	    end;
	{set_verbose, What} ->
	    set_verbose(What), 
	    resp(From, ok),
	    ok;
	{where, Object} ->
	    {H2, Res} = where_is_object(Head, Object),
	    resp(From, Res),
	    H2;
	_Message when element(1, Head#head.update_mode) =:= error ->
	    resp(From, status(Head)),
	    ok;
	%% The following messages assume that the status of the table is OK.
	{bchunk_init, Tab} ->
	    {H2, Res} = do_bchunk_init(Head, Tab),
	    resp(From, Res),
	    H2;
	{bchunk, State} ->
	    {H2, Res} = do_bchunk(Head, State),
	    resp(From, Res),
	    H2;
	delete_all_objects ->
	    {H2, Res} = fdelete_all_objects(Head),
	    resp(From, Res),
	    erlang:garbage_collect(),
	    {0, H2};
	{delete_key, _Keys} when Head#head.update_mode =:= dirty ->
            stream_op(Op, From, [], Head, N);
	{delete_object, Objs} when Head#head.update_mode =:= dirty ->
	    case check_objects(Objs, Head#head.keypos) of
		true ->
		    stream_op(Op, From, [], Head, N);
		false ->
		    resp(From, badarg),
		    ok
	    end;
	first ->
	    {H2, Res} = ffirst(Head),
	    resp(From, Res),
	    H2;
        {initialize, InitFun, Format, MinNoSlots} ->
            {H2, Res} = finit(Head, InitFun, Format, MinNoSlots),
            resp(From, Res),
	    erlang:garbage_collect(),
            H2;
	{insert, Objs} when Head#head.update_mode =:= dirty ->
	    case check_objects(Objs, Head#head.keypos) of
		true ->
		    stream_op(Op, From, [], Head, N);
		false ->
		    resp(From, badarg),
		    ok
	    end;
	{insert_new, Objs} when Head#head.update_mode =:= dirty ->
            {H2, Res} = finsert_new(Head, Objs),
            resp(From, Res),
            {N + 1, H2};
	{lookup_keys, _Keys} ->
	    stream_op(Op, From, [], Head, N);
	{match_init, State, Safe} ->
	    {H1, Res} = fmatch_init(Head, State),
            H2 = case Res of
                     {cont,_} -> H1;
                     _ when Safe =:= no_safe-> H1;
                     _ when Safe =:= safe -> do_safe_fixtable(H1, pidof(From), false)
                 end,
	    resp(From, Res),
	    H2;
	{match, MP, Spec, NObjs, Safe} ->
	    {H2, Res} = fmatch(Head, MP, Spec, NObjs, Safe, From),
	    resp(From, Res),
	    H2;
	{member, _Key} = Op ->
	    stream_op(Op, From, [], Head, N);
	{next, Key} ->
	    {H2, Res} = fnext(Head, Key),
	    resp(From, Res),
	    H2;
	{match_delete, State} when Head#head.update_mode =:= dirty ->
	    {H1, Res} = fmatch_delete(Head, State),
            H2 = case Res of
                     {cont,_S,_N} -> H1;
                     _ -> do_safe_fixtable(H1, pidof(From), false)
                 end,
	    resp(From, Res),
	    {N + 1, H2};
	{match_delete_init, MP, Spec} when Head#head.update_mode =:= dirty ->
	    {H2, Res} = fmatch_delete_init(Head, MP, Spec, From),
	    resp(From, Res),
	    {N + 1, H2};
	{safe_fixtable, Bool} ->
	    NewHead = do_safe_fixtable(Head, pidof(From), Bool),
	    resp(From, ok),
	    NewHead;
	{slot, Slot} ->
	    {H2, Res} = fslot(Head, Slot),
	    resp(From, Res),
	    H2;
	sync ->
	    {NewHead, Res} = perform_save(Head, true),
	    resp(From, Res),
	    erlang:garbage_collect(),
	    {0, NewHead};
	{update_counter, Key, Incr} when Head#head.update_mode =:= dirty ->
	    {NewHead, Res} = do_update_counter(Head, Key, Incr),
	    resp(From, Res),
	    {N + 1, NewHead};
	WriteOp when Head#head.update_mode =:= new_dirty ->
	    H2 = Head#head{update_mode = dirty},
	    apply_op(WriteOp, From, H2, 0);
	WriteOp when Head#head.access =:= read_write,
		     Head#head.update_mode =:= saved ->
	    case catch cb_dets_v9:mark_dirty(Head) of
		ok ->
		    start_auto_save_timer(Head),
		    H2 = Head#head{update_mode = dirty},
		    apply_op(WriteOp, From, H2, 0);
		{NewHead, Error} when is_record(NewHead, head) ->
		    resp(From, Error),
		    NewHead
	    end;
	WriteOp when is_tuple(WriteOp), Head#head.access =:= read ->
	    Reason = {access_mode, Head#head.filename},
	    resp(From, err({error, Reason})),
	    ok
    end.

bug_found(Name, Op, Bad, Stacktrace, From) ->
    case cb_dets_utils:debug_mode() of
        true ->
            %% If stream_op/5 found more requests, this is not
            %% the last operation.
            error_logger:format
              ("** cb_dets: Bug was found when accessing table ~tw,~n"
               "** cb_dets: operation was ~tp and reply was ~tw.~n"
               "** cb_dets: Stacktrace: ~tw~n",
               [Name, Op, Bad, Stacktrace]);
        false ->
            error_logger:format
              ("** cb_dets: Bug was found when accessing table ~tw~n",
               [Name])
    end,
    if
        From =/= self() ->
            resp(From, {error, {cb_dets_bug, Name, Op, Bad}}),
            ok;
        true -> % auto_save | may_grow | {delayed_write, _}
            ok
    end.

do_internal_open(Parent, Server, From, Ref, Args) ->
    ?PROFILE(ep:do()),
    case do_open_file(Args, Parent, Server, Ref) of
        {ok, Head} ->
            resp(From, ok),
            Head;
        Error ->
            resp(From, Error),
            exit(normal)
    end.

start_auto_save_timer(Head) when Head#head.auto_save =:= infinity ->
    ok;
start_auto_save_timer(Head) ->
    Millis = Head#head.auto_save,
    _Ref = erlang:send_after(Millis, self(), ?DETS_CALL(self(), auto_save)),
    ok.

%% Peek the message queue and try to evaluate several
%% lookup requests in parallel. Evalute delete_object, delete and
%% insert as well.
stream_op(Op, Pid, Pids, Head, N) ->
    #head{fixed = Fxd, update_mode = M} = Head, 
    stream_op(Head, Pids, [], N, Pid, Op, Fxd, M).

stream_loop(Head, Pids, C, N, false = Fxd, M) ->
    receive
	?DETS_CALL(From, Message) ->
	    stream_op(Head, Pids, C, N, From, Message, Fxd, M)
    after 0 ->
	    stream_end(Head, Pids, C, N, no_more)
    end;
stream_loop(Head, Pids, C, N, _Fxd, _M) ->
    stream_end(Head, Pids, C, N, no_more).

stream_op(Head, Pids, C, N, Pid, {lookup_keys,Keys}, Fxd, M) ->
    NC = [{{lookup,Pid},Keys} | C],
    stream_loop(Head, Pids, NC, N, Fxd, M);
stream_op(Head, Pids, C, N, Pid, {insert, _Objects} = Op, Fxd, dirty = M) ->
    NC = [Op | C],
    stream_loop(Head, [Pid | Pids], NC, N, Fxd, M);
stream_op(Head, Pids, C, N, Pid, {delete_key, _Keys} = Op, Fxd, dirty = M) ->
    NC = [Op | C],
    stream_loop(Head, [Pid | Pids], NC, N, Fxd, M);
stream_op(Head, Pids, C, N, Pid, {delete_object, _Os} = Op, Fxd, dirty = M) ->
    NC = [Op | C],
    stream_loop(Head, [Pid | Pids], NC, N, Fxd, M);
stream_op(Head, Pids, C, N, Pid, {member, Key}, Fxd, M) ->
    NC = [{{lookup,[Pid]},[Key]} | C],
    stream_loop(Head, Pids, NC, N, Fxd, M);
stream_op(Head, Pids, C, N, Pid, Op, _Fxd, _M) ->
    stream_end(Head, Pids, C, N, {Pid,Op}).

stream_end(Head, Pids0, C, N, Next) ->
    case catch update_cache(Head, lists:reverse(C)) of
	{Head1, [], PwriteList} ->
	    stream_end1(Pids0, Next, N, C, Head1, PwriteList);
	{Head1, Found, PwriteList} ->
	    %% Possibly an optimization: reply to lookup requests
	    %% first, then write stuff. This makes it possible for
	    %% clients to continue while the disk is accessed.
	    %% (Replies to lookup requests are sent earlier than
	    %%  replies to delete and insert requests even if the
	    %%  latter requests were made before the lookup requests,
	    %%  which can be confusing.)
	    _ = lookup_replies(Found),
	    stream_end1(Pids0, Next, N, C, Head1, PwriteList);
	Head1 when is_record(Head1, head) ->
	    stream_end2(Pids0, Pids0, Next, N, C, Head1, ok);	    
	{Head1, Error} when is_record(Head1, head) ->
	    %% Dig out the processes that did lookup or member.
	    Fun = fun({{lookup,[Pid]},_Keys}, L) -> [Pid | L];
		     ({{lookup,Pid},_Keys}, L) -> [Pid | L];
		     (_, L) -> L
		  end,
	    LPs0 = lists:foldl(Fun, [], C),
	    LPs = lists:usort(lists:flatten(LPs0)),
	    stream_end2(Pids0 ++ LPs, Pids0, Next, N, C, Head1, Error);
        DetsError ->
            throw(DetsError)
    end.

stream_end1(Pids, Next, N, C, Head, []) ->
    stream_end2(Pids, Pids, Next, N, C, Head, ok);
stream_end1(Pids, Next, N, C, Head, PwriteList) ->
    {Head1, PR} = (catch cb_dets_utils:pwrite(Head, PwriteList)),
    stream_end2(Pids, Pids, Next, N, C, Head1, PR).

stream_end2([Pid | Pids], Ps, Next, N, C, Head, Reply) ->
    resp(Pid, Reply),
    stream_end2(Pids, Ps, Next, N+1, C, Head, Reply);
stream_end2([], Ps, no_more, N, C, Head, _Reply) ->
    penalty(Head, Ps, C),
    {N, Head};
stream_end2([], _Ps, {From, Op}, N, _C, Head, _Reply) ->
    {{more,From,Op,N},Head}.

penalty(H, _Ps, _C) when H#head.fixed =:= false ->
    ok;
penalty(_H, _Ps, [{{lookup,_Pids},_Keys}]) ->
    ok;
penalty(#head{fixed = {_,[{Pid, _}]}}, [{Pid, _Tag} = _From], _C) ->
    ok;
penalty(_H, _Ps, _C) ->
    timer:sleep(1).

lookup_replies([{P,O}]) ->
    lookup_reply(P, O);
lookup_replies(Q) ->
    [{P,O} | L] = cb_dets_utils:family(Q),
    lookup_replies(P, lists:append(O), L).

lookup_replies(P, O, []) ->
    lookup_reply(P, O);
lookup_replies(P, O, [{P2,O2} | L]) ->
    _ = lookup_reply(P, O),
    lookup_replies(P2, lists:append(O2), L).

%% If a list of Pid then op was {member, Key}. Inlined.
lookup_reply([P], O) ->
    resp(P, O =/= []);
lookup_reply(P, O) ->
    resp(P, O).

%%-----------------------------------------------------------------
%% Callback functions for system messages handling.
%%-----------------------------------------------------------------
system_continue(_Parent, _, Head) ->
    open_file_loop(Head, 0).

system_terminate(Reason, _Parent, _, Head) ->
    _NewHead = do_stop(Head),
    exit(Reason).

%%-----------------------------------------------------------------
%% Code for upgrade.
%%-----------------------------------------------------------------
system_code_change(State, _Module, _OldVsn, _Extra) ->
    {ok, State}.


%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------

%% -> {ok, Fd, fileheader()} | throw(Error)
read_file_header(FileName, Access, RamFile) ->
    BF = if
	     RamFile ->
		 case file:read_file(FileName) of
		     {ok, B} -> B;
		     Err -> cb_dets_utils:file_error(FileName, Err)
		 end;
	     true ->
		 FileName
	 end,
    {ok, Fd} = cb_dets_utils:open(BF, open_args(Access, RamFile)),
    {ok, <<Version:32>>} = 
        cb_dets_utils:pread_close(Fd, FileName, ?FILE_FORMAT_VERSION_POS, 4),
    if 
        Version =< 8 ->
            _ = file:close(Fd),
            throw({error, {format_8_no_longer_supported, FileName}});
        Version =:= 9 ->
            cb_dets_v9:read_file_header(Fd, FileName);
        true ->
            _ = file:close(Fd),
            throw({error, {not_a_cb_dets_file, FileName}})
    end.

fclose(Head) ->
    {Head1, Res} = perform_save(Head, false),
    case Head1#head.ram_file of
	true -> 
            Res;
	false -> 
            cb_dets_utils:stop_disk_map(),
	    Res2 = file:close(Head1#head.fptr),
            if
                Res2 =:= ok -> Res;
                true -> Res2
            end
    end.

%% -> {NewHead, Res}
perform_save(Head, DoSync) when Head#head.update_mode =:= dirty;
				Head#head.update_mode =:= new_dirty ->
    case catch begin
                   {Head1, []} = write_cache(Head),
                   {Head2, ok} = cb_dets_v9:do_perform_save(Head1),
                   ok = ensure_written(Head2, DoSync),
                   {Head2#head{update_mode = saved}, ok}
               end of
        {NewHead, _} = Reply when is_record(NewHead, head) ->
            Reply
    end;
perform_save(Head, _DoSync) ->
    {Head, status(Head)}.

ensure_written(Head, DoSync) when Head#head.ram_file ->
    {ok, EOF} = cb_dets_utils:position(Head, eof),
    {ok, Bin} = cb_dets_utils:pread(Head, 0, EOF, 0),
    if
	DoSync ->
	    cb_dets_utils:write_file(Head, Bin);
	not DoSync ->
            case file:write_file(Head#head.filename, Bin) of
                ok -> 
                    ok;
                Error -> 
                    cb_dets_utils:corrupt_file(Head, Error)
            end
    end;
ensure_written(Head, true) when not Head#head.ram_file ->
    cb_dets_utils:sync(Head);
ensure_written(Head, false) when not Head#head.ram_file ->
    ok.

%% -> {NewHead, {cont(), [binary()]}} | {NewHead, Error}
do_bchunk_init(Head, Tab) ->
    case catch write_cache(Head) of
	{H2, []} ->
	    case cb_dets_v9:table_parameters(H2) of
		undefined ->
		    {H2, {error, old_version}};
		Parms ->
                    L = cb_dets_utils:all_allocated(H2),
                    Bin = if
                              L =:= <<>> -> eof;
                              true -> <<>>
                          end,
		    BinParms = cb_dets_utils:term_to_binary_callback(Parms),
		    {H2, {#cb_dets_cont{no_objs = default, bin = Bin, alloc = L,
                                     tab = Tab, proc = self(),what = bchunk},
                          [BinParms]}}
	    end;
	{NewHead, _} = HeadError when is_record(NewHead, head) ->
	    HeadError
    end.

%% -> {NewHead, {cont(), [binary()]}} | {NewHead, Error}
do_bchunk(Head, #cb_dets_cont{proc = Proc}) when Proc =/= self() ->
    {Head, badarg};
do_bchunk(Head, #cb_dets_cont{bin = eof}) ->
    {Head, '$end_of_table'};
do_bchunk(Head, State) ->
    case cb_dets_v9:read_bchunks(Head, State#cb_dets_cont.alloc) of
	{error, Reason} ->
	    cb_dets_utils:corrupt_reason(Head, Reason);
	{finished, Bins} ->
	    {Head, {State#cb_dets_cont{bin = eof}, Bins}};
	{Bins, NewL} ->
	    {Head, {State#cb_dets_cont{alloc = NewL}, Bins}}
    end.

%% -> {NewHead, Result}
fdelete_all_objects(Head) when Head#head.fixed =:= false ->
    case catch do_delete_all_objects(Head) of
	{ok, NewHead} ->
	    start_auto_save_timer(NewHead),
	    {NewHead, ok};
	{error, Reason} ->
	    cb_dets_utils:corrupt_reason(Head, Reason)
    end;
fdelete_all_objects(Head) ->
    {Head, fixed}.

do_delete_all_objects(Head) ->
    #head{fptr = Fd, name = Tab, filename = Fname, type = Type, keypos = Kp, 
	  ram_file = Ram, auto_save = Auto, min_no_slots = MinSlots,
	  max_no_slots = MaxSlots, cache = Cache} = Head, 
    CacheSz = cb_dets_utils:cache_size(Cache),
    ok = cb_dets_utils:truncate(Fd, Fname, bof),
    cb_dets_v9:initiate_file(Fd, Tab, Fname, Type, Kp, MinSlots, MaxSlots,
                          Ram, CacheSz, Auto, true).

ffirst(H) ->
    Ref = make_ref(),
    case catch {Ref, ffirst1(H)} of
	{Ref, {NH, R}} -> 
	    {NH, {ok, R}};
	{NH, R} when is_record(NH, head) -> 
	    {NH, {error, R}}
    end.

ffirst1(H) ->
    check_safe_fixtable(H),
    {NH, []} = write_cache(H),
    ffirst(NH, 0).

ffirst(H, Slot) ->
    case cb_dets_v9:slot_objs(H, Slot) of
	'$end_of_table' -> {H, '$end_of_table'};
	[] -> ffirst(H, Slot+1);
	[X|_] -> {H, element(H#head.keypos, X)}
    end.

%% -> {NewHead, Reply}, Reply = ok | badarg | Error.
finsert(Head, Objects) ->
    case catch update_cache(Head, Objects, insert) of
	{NewHead, []} ->
	    {NewHead, ok};
	{NewHead, _} = HeadError when is_record(NewHead, head) ->
	    HeadError
    end.

%% -> {NewHead, Reply}, Reply = ok | badarg | Error.
finsert_new(Head, Objects) ->
    KeyPos = Head#head.keypos,
    case catch lists:map(fun(Obj) -> element(KeyPos, Obj) end, Objects) of
        Keys when is_list(Keys) ->
            case catch update_cache(Head, Keys, {lookup, nopid}) of
                {Head1, PidObjs} when is_list(PidObjs) ->
                    case lists:all(fun({_P,OL}) -> OL =:= [] end, PidObjs) of
                        true ->
                            case catch update_cache(Head1, Objects, insert) of
                                {NewHead, []} ->
                                    {NewHead, true};
                                {NewHead, Error} when is_record(NewHead, head) ->
                                    {NewHead, Error}
                            end;
                        false=Reply ->
                            {Head1, Reply}
                    end;
                {NewHead, _} = HeadError when is_record(NewHead, head) ->
                    HeadError
            end;
        _ ->
            {Head, badarg}
    end.

do_safe_fixtable(Head, Pid, true) ->
    case Head#head.fixed of 
	false -> 
	    link(Pid),
	    MonTime = erlang:monotonic_time(),
	    TimeOffset = erlang:time_offset(),
	    Fixed = {{MonTime, TimeOffset}, [{Pid, 1}]},
	    Ftab = cb_dets_utils:get_freelists(Head),
	    Head#head{fixed = Fixed, freelists = {Ftab, Ftab}};
	{TimeStamp, Counters} ->
	    case lists:keysearch(Pid, 1, Counters) of
		{value, {Pid, Counter}} -> % when Counter > 1
		    NewCounters = lists:keyreplace(Pid, 1, Counters, 
						   {Pid, Counter+1}),
		    Head#head{fixed = {TimeStamp, NewCounters}};
		false ->
		    link(Pid),
		    Fixed = {TimeStamp, [{Pid, 1} | Counters]},
		    Head#head{fixed = Fixed}
	    end
    end;
do_safe_fixtable(Head, Pid, false) ->
    remove_fix(Head, Pid, false).

remove_fix(Head, Pid, How) ->
    case Head#head.fixed of 
	false -> 
	    Head;
	{TimeStamp, Counters} ->
	    case lists:keysearch(Pid, 1, Counters) of
		%% How =:= close when Pid closes the table.
		{value, {Pid, Counter}} when Counter =:= 1; How =:= close ->
		    unlink(Pid),
		    case lists:keydelete(Pid, 1, Counters) of
			[] -> 
			    check_growth(Head),
			    erlang:garbage_collect(),
			    Head#head{fixed = false, 
				  freelists = cb_dets_utils:get_freelists(Head)};
			NewCounters ->
			    Head#head{fixed = {TimeStamp, NewCounters}}
		    end;
		{value, {Pid, Counter}} ->
		    NewCounters = lists:keyreplace(Pid, 1, Counters, 
						   {Pid, Counter-1}),
		    Head#head{fixed = {TimeStamp, NewCounters}};
		false ->
		    Head
	    end
    end.

do_stop(Head) ->
    _NewHead = unlink_fixing_procs(Head),
    fclose(Head).

unlink_fixing_procs(Head) ->
    case Head#head.fixed of
	false ->
	    Head;
	{_, Counters} ->
	    lists:foreach(fun({Pid, _Counter}) -> unlink(Pid) end, Counters),
	    Head#head{fixed = false, 
		      freelists = cb_dets_utils:get_freelists(Head)}
    end.

check_growth(#head{access = read}) ->
    ok;
check_growth(Head) ->
    NoThings = no_things(Head),
    if
	NoThings > Head#head.next ->
	    _Ref = erlang:send_after
                     (200, self(), ?DETS_CALL(self(), may_grow)), % Catch up.
            ok;
	true ->
	    ok
    end.

finfo(H) -> 
    case catch write_cache(H) of
	{H2, []} ->
	    Info = (catch [{type, H2#head.type}, 
			   {keypos, H2#head.keypos}, 
			   {size, H2#head.no_objects},
			   {file_size, 
			    file_size(H2#head.fptr, H2#head.filename)},
			   {filename, H2#head.filename}]),
	    {H2, Info};
	{H2, _} = HeadError when is_record(H2, head) ->
	    HeadError
    end.

finfo(H, access) -> {H, H#head.access};
finfo(H, auto_save) -> {H, H#head.auto_save};
finfo(H, bchunk_format) -> 
    case catch write_cache(H) of
        {H2, []} ->
            case cb_dets_v9:table_parameters(H2) of
                undefined = Undef ->
                    {H2, Undef};
                Parms ->
                    {H2, cb_dets_utils:term_to_binary_callback(Parms)}
            end;
        {H2, _} = HeadError when is_record(H2, head) ->
            HeadError
    end;
finfo(H, delayed_write) -> % undocumented
    {H, cb_dets_utils:cache_size(H#head.cache)};
finfo(H, filename) -> {H, H#head.filename};
finfo(H, file_size) ->
    case catch write_cache(H) of
	{H2, []} ->
	    {H2, catch file_size(H#head.fptr, H#head.filename)};
	{H2, _} = HeadError when is_record(H2, head) ->
	    HeadError
    end;
finfo(H, fixed) -> 
    %% true if fixtable/2 has been called
    {H, not (H#head.fixed =:= false)}; 
finfo(H, hash) -> {H, H#head.hash_bif};
finfo(H, keypos) -> {H, H#head.keypos};
finfo(H, memory) -> finfo(H, file_size);
finfo(H, no_objects) -> finfo(H, size);
finfo(H, no_keys) ->
    case catch write_cache(H) of
	{H2, []} ->
	    {H2, H2#head.no_keys};
	{H2, _} = HeadError when is_record(H2, head) ->
	    HeadError
    end;
finfo(H, no_slots) -> {H, cb_dets_v9:no_slots(H)};
finfo(H, pid) -> {H, self()};
finfo(H, ram_file) -> {H, H#head.ram_file};
finfo(H, safe_fixed) ->
    {H,
     case H#head.fixed of
	 false ->
	     false;
	 {{FixMonTime, TimeOffset}, RefList} ->
	     {make_timestamp(FixMonTime, TimeOffset), RefList}
     end};
finfo(H, safe_fixed_monotonic_time) ->
    {H,
     case H#head.fixed of
	 false ->
	     false;
	 {{FixMonTime, _TimeOffset}, RefList} ->
	     {FixMonTime, RefList}
     end};
finfo(H, size) -> 
    case catch write_cache(H) of
	{H2, []} ->
	    {H2, H2#head.no_objects};
	{H2, _} = HeadError when is_record(H2, head) ->
	    HeadError
    end;
finfo(H, type) -> {H, H#head.type};
finfo(H, version) -> {H, 9};
finfo(H, _) -> {H, undefined}.

file_size(Fd, FileName) -> 
    {ok, Pos} = cb_dets_utils:position(Fd, FileName, eof),
    Pos.

test_bchunk_format(_Head, undefined) ->
    false;
test_bchunk_format(Head, Term) ->
    cb_dets_v9:try_bchunk_header(Term, Head) =/= not_ok.

do_open_file([Fname, Verbose], Parent, Server, Ref) ->
    case catch fopen2(Fname, Ref) of
	{error, {tooshort, _}} ->
            err({error, {not_a_cb_dets_file, Fname}});
	{error, _Reason} = Error ->
	    err(Error);
	{ok, Head} ->
	    maybe_put(verbose, Verbose),
	    {ok, Head#head{parent = Parent, server = Server}};
	{'EXIT', _Reason} = Error ->
	    Error;
	Bad ->
	    error_logger:format
	      ("** cb_dets: Bug was found in open_file/1, reply was ~tw.~n",
	       [Bad]),
	    {error, {cb_dets_bug, Fname, Bad}}
    end;
do_open_file([Tab, OpenArgs, Verb], Parent, Server, _Ref) ->
    case catch fopen3(Tab, OpenArgs) of
	{error, {tooshort, _}} ->
            err({error, {not_a_cb_dets_file, OpenArgs#open_args.file}});
	{error, _Reason} = Error ->
	    err(Error);
	{ok, Head} ->
	    maybe_put(verbose, Verb),
	    {ok, Head#head{parent = Parent, server = Server}};
	{'EXIT', _Reason} = Error ->
	    Error;
	Bad ->
	    error_logger:format
	      ("** cb_dets: Bug was found in open_file/2, arguments were~n"
	       "** cb_dets: ~tw and reply was ~tw.~n",
	       [OpenArgs, Bad]),
	    {error, {cb_dets_bug, Tab, {open_file, OpenArgs}, Bad}}
    end.

maybe_put(_, undefined) ->
    ignore;
maybe_put(K, V) ->
    put(K, V).

%% -> {Head, Result}, Result = ok | Error | {thrown, Error} | badarg
finit(Head, InitFun, _Format, _NoSlots) when Head#head.access =:= read ->
    _ = (catch InitFun(close)),
    {Head, {error, {access_mode, Head#head.filename}}};
finit(Head, InitFun, _Format, _NoSlots) when Head#head.fixed =/= false ->
    _ = (catch InitFun(close)),
    {Head, {error, {fixed_table, Head#head.name}}};
finit(Head, InitFun, Format, NoSlots) ->
    case catch do_finit(Head, InitFun, Format, NoSlots) of
	{ok, NewHead} ->
	    check_growth(NewHead),
	    start_auto_save_timer(NewHead),
	    {NewHead, ok};
	badarg ->
	    {Head, badarg};
	Error ->
	    cb_dets_utils:corrupt(Head, Error)
    end.

%% -> {ok, NewHead} | throw(badarg) | throw(Error)
do_finit(Head, Init, Format, NoSlots) ->
    #head{fptr = Fd, type = Type, keypos = Kp, auto_save = Auto,
          cache = Cache, filename = Fname, ram_file = Ram,
	  min_no_slots = MinSlots0, max_no_slots = MaxSlots,
          name = Tab, update_mode = UpdateMode} = Head,
    CacheSz = cb_dets_utils:cache_size(Cache),
    {How, Head1} =
	case Format of
	    term when is_integer(NoSlots), NoSlots > MaxSlots ->
		throw(badarg);
	    term ->
		MinSlots = choose_no_slots(NoSlots, MinSlots0),
		if 
		    UpdateMode =:= new_dirty, MinSlots =:= MinSlots0 ->
			{general_init, Head};
		    true ->
			ok = cb_dets_utils:truncate(Fd, Fname, bof),
			{ok, H} =
                            cb_dets_v9:initiate_file(Fd, Tab, Fname, Type, Kp,
                                                  MinSlots, MaxSlots, Ram,
                                                  CacheSz, Auto, false),
			{general_init, H}
		end;
	    bchunk ->
		ok = cb_dets_utils:truncate(Fd, Fname, bof),
		{bchunk_init, Head}
	end,
    case How of
	bchunk_init -> 
	    case cb_dets_v9:bchunk_init(Head1, Init) of
		{ok, NewHead} ->
		    {ok, NewHead#head{update_mode = dirty}};
		Error ->
		    Error
	    end;
	general_init ->
	    Cntrs = ets:new(cb_dets_init, []),
	    Input = cb_dets_v9:bulk_input(Head1, Init, Cntrs),
	    SlotNumbers = {Head1#head.min_no_slots, bulk_init, MaxSlots},
	    {Reply, SizeData} = 
		do_sort(Head1, SlotNumbers, Input, Cntrs, Fname),
	    Bulk = true,
	    case Reply of 
		{ok, NoDups, H1} ->
		    fsck_copy(SizeData, H1, Bulk, NoDups);
		Else ->
		    close_files(Bulk, SizeData, Head1),
		    Else
	    end
    end.

%% -> {NewHead, [LookedUpObject]} | {NewHead, Error}
flookup_keys(Head, Keys) ->
    case catch update_cache(Head, Keys, {lookup, nopid}) of
	{NewHead, [{_NoPid,Objs}]} -> 
	    {NewHead, Objs};
	{NewHead, L} when is_list(L) ->
	    {NewHead, lists:flatmap(fun({_Pid,OL}) -> OL end, L)};
	{NewHead, _} = HeadError when is_record(NewHead, head) ->
	    HeadError
    end.

%% -> {NewHead, Result}
fmatch_init(Head, #cb_dets_cont{bin = eof}) ->
    {Head, '$end_of_table'};
fmatch_init(Head, C) ->
    case scan(Head, C) of
	{scan_error, Reason} ->
	    cb_dets_utils:corrupt_reason(Head, Reason);
	{Ts, NC} ->
	    {Head, {cont, {Ts, NC}}}
    end.

%% -> {NewHead, Result}
fmatch(Head, MP, Spec, N, Safe, From) ->
    KeyPos = Head#head.keypos,
    case find_all_keys(Spec, KeyPos, []) of
	[] -> 
	    %% Complete match
	    case catch write_cache(Head) of
		{Head1, []} ->
                    NewHead =
                        case Safe of
                            safe -> do_safe_fixtable(Head1, pidof(From), true);
                            no_safe -> Head1
                        end,
		    C0 = init_scan(NewHead, N),
		    {NewHead, {cont, C0#cb_dets_cont{match_program = MP}}};
		{NewHead, _} = HeadError when is_record(NewHead, head) ->
		    HeadError
	    end;
	List ->
	    Keys = lists:usort(List),
	    {NewHead, Reply} = flookup_keys(Head, Keys),
	    case Reply of
		Objs when is_list(Objs) ->
                    {match_spec, MS} = MP,
		    MatchingObjs = ets:match_spec_run(Objs, MS),
		    {NewHead, {done, MatchingObjs}};
		Error ->
		    {NewHead, Error}
	    end
    end.

find_all_keys([], _, Ks) ->
    Ks;
find_all_keys([{H,_,_} | T], KeyPos, Ks) when is_tuple(H) ->
    case tuple_size(H) of
	Enough when Enough >= KeyPos ->
	    Key = element(KeyPos, H),
	    case contains_variable(Key) of
		true -> 
		    [];
		false ->
		    find_all_keys(T, KeyPos, [Key | Ks])
	    end;
	_ ->
	    find_all_keys(T, KeyPos, Ks)
    end;
find_all_keys(_, _, _) ->
    [].

contains_variable('_') ->
    true;
contains_variable(A) when is_atom(A) ->
    case atom_to_list(A) of
	[$$ | T] ->
	    case (catch list_to_integer(T)) of
		{'EXIT', _} ->
		    false;
		_ ->
		    true
	    end;
	_ ->
	    false
    end;
contains_variable(T) when is_tuple(T) ->
    contains_variable(tuple_to_list(T));
contains_variable([]) ->
    false;
contains_variable([H|T]) ->
    case contains_variable(H) of
	true ->
	    true;
	false ->
	    contains_variable(T)
    end;
contains_variable(_) ->
    false.

%% -> {NewHead, Res}
fmatch_delete_init(Head, MP, Spec, From) ->
    KeyPos = Head#head.keypos,
    case catch 
        case find_all_keys(Spec, KeyPos, []) of
            [] -> 
                do_fmatch_delete_var_keys(Head, MP, Spec, From);
            List ->
                Keys = lists:usort(List),
                do_fmatch_constant_keys(Head, Keys, MP)
        end of
        {NewHead, _} = Reply when is_record(NewHead, head) ->
            Reply            
    end.

%% A note: If deleted objects reside in a bucket with other objects
%% that are not deleted, the bucket is moved. If the address of the
%% moved bucket is greater than original bucket address the kept
%% objects will be read once again later on. 
%% -> {NewHead, Res}
fmatch_delete(Head, C) ->
    case scan(Head, C) of
	{scan_error, Reason} ->
	    cb_dets_utils:corrupt_reason(Head, Reason);
	{[], _} ->
	    {Head, {done, 0}};
	{RTs, NC} ->
	    {match_spec, MP} = C#cb_dets_cont.match_program,
	    case catch filter_binary_terms(RTs, MP, []) of
		{'EXIT', _} ->
                    Bad = cb_dets_utils:bad_object(fmatch_delete, RTs),
		    cb_dets_utils:corrupt_reason(Head, Bad);
		Terms -> 
		    do_fmatch_delete(Head, Terms, NC)
	    end
    end.

do_fmatch_delete_var_keys(Head, _MP, ?PATTERN_TO_TRUE_MATCH_SPEC('_'), _From)
            when Head#head.fixed =:= false ->
    %% Handle the case where the file is emptied efficiently.
    %% Empty the cache just to get the number of objects right.
    {Head1, []} = write_cache(Head),
    N = Head1#head.no_objects,
    case fdelete_all_objects(Head1) of
	{NewHead, ok} ->
	    {NewHead, {done, N}};
	Reply ->
	    Reply
    end;
do_fmatch_delete_var_keys(Head, MP, _Spec, From) ->
    Head1 = do_safe_fixtable(Head, pidof(From), true),
    {NewHead, []} = write_cache(Head1),
    C0 = init_scan(NewHead, default),
    {NewHead, {cont, C0#cb_dets_cont{match_program = MP}, 0}}.

do_fmatch_constant_keys(Head, Keys, {match_spec, MP}) ->
    case flookup_keys(Head, Keys) of
	{NewHead, ReadTerms} when is_list(ReadTerms) ->
	    Terms = filter_terms(ReadTerms, MP, []),
	    do_fmatch_delete(NewHead, Terms, fixed);
	Reply ->
	    Reply
    end.

filter_binary_terms([Bin | Bins], MP, L) ->
    Term = cb_dets_utils:binary_to_term_callback(Bin),
    case ets:match_spec_run([Term], MP) of
	[true] -> 
	    filter_binary_terms(Bins, MP, [Term | L]);
	_ ->
	    filter_binary_terms(Bins, MP, L)
    end;
filter_binary_terms([], _MP, L) ->
    L.

filter_terms([Term | Terms], MP, L) ->
    case ets:match_spec_run([Term], MP) of
	[true] -> 
	    filter_terms(Terms, MP, [Term | L]);
	_ ->
	    filter_terms(Terms, MP, L)
    end;
filter_terms([], _MP, L) ->
    L.

do_fmatch_delete(Head, Terms, What) ->
    N = length(Terms),
    case do_delete(Head, Terms, delete_object) of
	{NewHead, ok} when What =:= fixed ->
	    {NewHead, {done, N}};
	{NewHead, ok} ->
	    {NewHead, {cont, What, N}};
	Reply ->
	    Reply
    end.

do_delete(Head, Things, What) ->
    case catch update_cache(Head, Things, What) of
	{NewHead, []} ->
	    {NewHead, ok};
	{NewHead, _} = HeadError when is_record(NewHead, head) ->
	    HeadError
    end.

fnext(Head, Key) ->
    Slot = cb_dets_v9:db_hash(Key, Head),
    Ref = make_ref(),
    case catch {Ref, fnext(Head, Key, Slot)} of
	{Ref, {H, R}} -> 
	    {H, {ok, R}};
	{NewHead, _} = HeadError when is_record(NewHead, head) ->
	    HeadError
    end.

fnext(H, Key, Slot) ->
    {NH, []} = write_cache(H),
    case cb_dets_v9:slot_objs(NH, Slot) of
	'$end_of_table' -> {NH, '$end_of_table'};
	L -> fnext_search(NH, Key, Slot, L)
    end.

fnext_search(H, K, Slot, L) ->
    Kp = H#head.keypos,
    case beyond_key(K, Kp, L) of
	[] -> fnext_slot(H, K, Slot+1);
	L2 -> {H, element(H#head.keypos, hd(L2))}
    end.

%% We've got to continue to search for the next key in the next slot
fnext_slot(H, K, Slot) ->
    case cb_dets_v9:slot_objs(H, Slot) of
	'$end_of_table' -> {H, '$end_of_table'};
	[] -> fnext_slot(H, K, Slot+1);
	L -> {H, element(H#head.keypos, hd(L))}
    end.

beyond_key(_K, _Kp, []) -> [];
beyond_key(K, Kp, [H|T]) ->
    case cb_dets_utils:cmp(element(Kp, H), K) of
        0 -> beyond_key2(K, Kp, T);
        _ -> beyond_key(K, Kp, T)
    end.

beyond_key2(_K, _Kp, []) -> [];
beyond_key2(K, Kp, [H|T]=L) ->
    case cb_dets_utils:cmp(element(Kp, H), K) of
        0 -> beyond_key2(K, Kp, T);
        _ -> L
    end.

%% Open an already existing file, no arguments
%% -> {ok, head()} | throw(Error)
fopen2(Fname, Tab) ->
    case file:read_file_info(Fname) of
	{ok, _} ->
	    Acc = read_write,
	    Ram = false, 
	    {ok, Fd, FH} = read_file_header(Fname, Acc, Ram),
            Do = case cb_dets_v9:check_file_header(FH, Fd) of
                     {ok, Head1} ->
                         Head2 = Head1#head{filename = Fname},
                         try {ok, cb_dets_v9:init_freelist(Head2)}
                         catch
                             throw:_ ->
                                 {repair, " has bad free lists, repairing ..."}
                         end;
                     {error, not_closed} ->
                         M = " not properly closed, repairing ...",
                         {repair, M};
                     Else ->
                         Else
                 end,
            case Do of
		{repair, Mess} ->
                    io:format(user, "cb_dets: file ~tp~s~n", [Fname, Mess]),
                    case fsck(Fd, Tab, Fname, FH, default, default) of
                        ok ->
                            fopen2(Fname, Tab);
                        Error ->
                            throw(Error)
                    end;
		{ok, Head} ->
		    open_final(Head, Fname, Acc, Ram, ?DEFAULT_CACHE, 
			       Tab, false);
		{error, Reason} ->
		    throw({error, {Reason, Fname}})
	    end;
	Error ->
	    cb_dets_utils:file_error(Fname, Error)
    end.

%% Open and possibly create and initialize a file
%% -> {ok, head()} | throw(Error)
fopen3(Tab, OpenArgs) ->
    FileName = OpenArgs#open_args.file,
    case file:read_file_info(FileName) of
	{ok, _} ->
	    fopen_existing_file(Tab, OpenArgs);
	Error when OpenArgs#open_args.access =:= read ->
	    cb_dets_utils:file_error(FileName, Error);
	_Error ->
	    fopen_init_file(Tab, OpenArgs)
    end.

fopen_existing_file(Tab, OpenArgs) ->
    #open_args{file = Fname, type = Type, keypos = Kp, repair = Rep,
               min_no_slots = MinSlots, max_no_slots = MaxSlots,
               ram_file = Ram, delayed_write = CacheSz, auto_save =
               Auto, access = Acc, debug = Debug} =
        OpenArgs,
    {ok, Fd, FH} = read_file_header(Fname, Acc, Ram),
    MinF = (MinSlots =:= default) or (MinSlots =:= FH#fileheader.min_no_slots),
    MaxF = (MaxSlots =:= default) or (MaxSlots =:= FH#fileheader.max_no_slots),
    Wh = case cb_dets_v9:check_file_header(FH, Fd) of
	     {ok, Head} when Rep =:= force, Acc =:= read_write,
                             FH#fileheader.no_colls =/= undefined,
                             MinF, MaxF ->
	         {compact, Head};
             {ok, _Head} when Rep =:= force, Acc =:= read ->
                 throw({error, {access_mode, Fname}});
	     {ok, _Head} when Rep =:= force ->
		 M = ", repair forced.",
		 {repair, M};
	     {ok, Head} ->
		 {final, Head};
	     {error, not_closed} when Rep =:= force, Acc =:= read_write ->
		 M = ", repair forced.",
		 {repair, M};
	     {error, not_closed} when Rep =:= true, Acc =:= read_write ->
		 M = " not properly closed, repairing ...",
		 {repair, M};
	     {error, not_closed} when Rep =:= false ->
		 throw({error, {needs_repair, Fname}});
	     {error, Reason} ->
		 throw({error, {Reason, Fname}})
	 end,
    Do = case Wh of
             {Tag, Hd} when Tag =:= final; Tag =:= compact ->
                 Hd1 = Hd#head{filename = Fname},
                 try {Tag, cb_dets_v9:init_freelist(Hd1)}
                 catch
                     throw:_ ->
                         {repair, " has bad free lists, repairing ..."}
                 end;
             Else ->
                 Else
         end,
    case Do of
	_ when FH#fileheader.type =/= Type ->
	    throw({error, {type_mismatch, Fname}});
	_ when FH#fileheader.keypos =/= Kp ->
	    throw({error, {keypos_mismatch, Fname}});
	{compact, SourceHead} ->
	    io:format(user, "cb_dets: file ~tp is now compacted ...~n", [Fname]),
	    {ok, NewSourceHead} = open_final(SourceHead, Fname, read, false,
					     ?DEFAULT_CACHE, Tab, Debug),
	    case catch compact(NewSourceHead) of
		ok ->
		    erlang:garbage_collect(),
		    fopen3(Tab, OpenArgs#open_args{repair = false});
		_Err ->
                    _ = file:close(Fd),
                    cb_dets_utils:stop_disk_map(),
		    io:format(user, "cb_dets: compaction of file ~tp failed, "
			      "now repairing ...~n", [Fname]),
                    {ok, Fd2, _FH} = read_file_header(Fname, Acc, Ram),
                    do_repair(Fd2, Tab, Fname, FH, MinSlots, MaxSlots, 
			      OpenArgs)
	    end;
	{repair, Mess} ->
	    io:format(user, "cb_dets: file ~tp~s~n", [Fname, Mess]),
            do_repair(Fd, Tab, Fname, FH, MinSlots, MaxSlots, 
		      OpenArgs);
	{final, H} ->
	    H1 = H#head{auto_save = Auto},
	    open_final(H1, Fname, Acc, Ram, CacheSz, Tab, Debug)
    end.

do_repair(Fd, Tab, Fname, FH, MinSlots, MaxSlots, OpenArgs) ->
    case fsck(Fd, Tab, Fname, FH, MinSlots, MaxSlots) of
	ok ->
	    erlang:garbage_collect(),
	    fopen3(Tab, OpenArgs#open_args{repair = false});
	Error ->
	    throw(Error)
    end.

%% -> {ok, head()} | throw(Error)
open_final(Head, Fname, Acc, Ram, CacheSz, Tab, Debug) ->
    Head1 = Head#head{access = Acc,
		      ram_file = Ram,
		      filename = Fname,
		      name = Tab,
		      cache = cb_dets_utils:new_cache(CacheSz)},
    init_disk_map(Tab, Debug),
    cb_dets_v9:cache_segps(Head1#head.fptr, Fname, Head1#head.next),
    check_growth(Head1),
    {ok, Head1}.

%% -> {ok, head()} | throw(Error)
fopen_init_file(Tab, OpenArgs) ->
    #open_args{file = Fname, type = Type, keypos = Kp, 
               min_no_slots = MinSlotsArg, max_no_slots = MaxSlotsArg, 
	       ram_file = Ram, delayed_write = CacheSz, auto_save = Auto, 
               debug = Debug} = OpenArgs,
    MinSlots = choose_no_slots(MinSlotsArg, ?DEFAULT_MIN_NO_SLOTS),
    MaxSlots = choose_no_slots(MaxSlotsArg, ?DEFAULT_MAX_NO_SLOTS),
    FileSpec = if
		   Ram -> [];
		   true -> Fname
	       end,
    {ok, Fd} = cb_dets_utils:open(FileSpec, open_args(read_write, Ram)),
    %% No need to truncate an empty file.
    init_disk_map(Tab, Debug),
    case catch cb_dets_v9:initiate_file(Fd, Tab, Fname, Type, Kp,
                                     MinSlots, MaxSlots,
                                     Ram, CacheSz, Auto, true) of
	{error, Reason} when Ram ->
	    _ = file:close(Fd),
	    throw({error, Reason});
	{error, Reason} ->
	    _ = file:close(Fd),
	    _ = file:delete(Fname),
	    throw({error, Reason});
	{ok, Head} ->
	    start_auto_save_timer(Head),
	    %% init_table does not need to truncate and write header
	    {ok, Head#head{update_mode = new_dirty}}
    end.

%% Debug.
init_disk_map(Name, Debug) ->
    case Debug orelse cb_dets_utils:debug_mode() of
        true -> 
            cb_dets_utils:init_disk_map(Name);
        false ->
            ok
    end.

open_args(Access, RamFile) ->
    A1 = case Access of
	     read -> [];
	     read_write -> [write]
	 end,
    A2 = case RamFile of
	     true -> [ram];
	     false -> [raw]
	   end,
    A1 ++ A2 ++ [binary, read].

%% -> ok | throw(Error) 
compact(SourceHead) ->
    #head{name = Tab, filename = Fname, fptr = SFd, type = Type, keypos = Kp,
	  ram_file = Ram, auto_save = Auto} = SourceHead,
    Tmp = tempfile(Fname),
    TblParms = cb_dets_v9:table_parameters(SourceHead),
    {ok, Fd} = cb_dets_utils:open(Tmp, open_args(read_write, false)),
    CacheSz = ?DEFAULT_CACHE,
    %% It is normally not possible to have two open tables in the same
    %% process since the process dictionary is used for caching
    %% segment pointers, but here is works anyway--when reading a file
    %% serially the pointers do not need to be used.
    Head = case catch cb_dets_v9:prep_table_copy(Fd, Tab, Tmp, Type, Kp, Ram, 
					      CacheSz, Auto, TblParms) of
	       {ok, H} ->
		   H;
	       Error ->
		   _ = file:close(Fd),
                   _ = file:delete(Tmp),
		   throw(Error)
	   end,

    case cb_dets_v9:compact_init(SourceHead, Head, TblParms) of
	{ok, NewHead} ->
	    R = case fclose(NewHead) of
		    ok ->
                        ok = file:close(SFd),
			%% Save (rename) Fname first?
			cb_dets_utils:rename(Tmp, Fname);
		    E ->
			E
		end,
	    if 
		R =:= ok -> ok;
		true ->
		    _ = file:delete(Tmp),
		    throw(R)
	    end;
	Err ->
	    _ = file:close(Fd),
            _ = file:delete(Tmp),
	    throw(Err)
    end.
	    
%% -> ok | Error
%% Closes Fd.
fsck(Fd, Tab, Fname, FH, MinSlotsArg, MaxSlotsArg) ->
    %% MinSlots and MaxSlots are the option values.
    #fileheader{min_no_slots = MinSlotsFile, 
                max_no_slots = MaxSlotsFile} = FH,
    EstNoSlots0 = file_no_things(FH),
    MinSlots = choose_no_slots(MinSlotsArg, MinSlotsFile),
    MaxSlots = choose_no_slots(MaxSlotsArg, MaxSlotsFile),
    EstNoSlots = erlang:min(MaxSlots, erlang:max(MinSlots, EstNoSlots0)),
    SlotNumbers = {MinSlots, EstNoSlots, MaxSlots},
    %% When repairing: We first try and sort on slots using MinSlots.
    %% If the number of objects (keys) turns out to be significantly
    %% different from NoSlots, we try again with the correct number of
    %% objects (keys).
    case fsck_try(Fd, Tab, FH, Fname, SlotNumbers) of
        {try_again, BetterNoSlots} ->
	    BetterSlotNumbers = {MinSlots, BetterNoSlots, MaxSlots},
            case fsck_try(Fd, Tab, FH, Fname, BetterSlotNumbers) of
                {try_again, _} ->
                    _ = file:close(Fd),
                    {error, {cannot_repair, Fname}};
                Else ->
                    Else
            end;
        Else ->
            Else
    end.

choose_no_slots(default, NoSlots) -> NoSlots;
choose_no_slots(NoSlots, _) -> NoSlots.

%% -> ok | {try_again, integer()} | Error
%% Closes Fd unless {try_again, _} is returned.
%% Initiating a table using a fun and repairing (or converting) a
%% file are completely different things, but nevertheless the same
%% method is used in both cases...
fsck_try(Fd, Tab, FH, Fname, SlotNumbers) ->
    Tmp = tempfile(Fname),
    #fileheader{type = Type, keypos = KeyPos} = FH,
    {_MinSlots, EstNoSlots, MaxSlots} = SlotNumbers,
    OpenArgs = #open_args{file = Tmp, type = Type, keypos = KeyPos, 
                          repair = false, min_no_slots = EstNoSlots,
			  max_no_slots = MaxSlots,
                          ram_file = false, delayed_write = ?DEFAULT_CACHE,
                          auto_save = infinity, access = read_write,
                          debug = false},
    case catch fopen3(Tab, OpenArgs) of
	{ok, Head} ->
            case fsck_try_est(Head, Fd, Fname, SlotNumbers, FH) of
                {ok, NewHead} ->
                    R = case fclose(NewHead) of
                            ok ->
				%% Save (rename) Fname first?
				cb_dets_utils:rename(Tmp, Fname);
                            Error ->
                                Error
                        end,
                    if 
			R =:= ok -> ok;
			true ->
			    _ = file:delete(Tmp),
			    R
		    end;
		TryAgainOrError ->
                    _ = file:delete(Tmp),
                    TryAgainOrError
            end;
	Error -> 
	    _ = file:close(Fd),
	    Error
    end.

tempfile(Fname) ->
    Tmp = lists:concat([Fname, ".TMP"]),
    case file:delete(Tmp) of
        {error, _Reason} -> % typically enoent
            ok;
        ok ->
            assure_no_file(Tmp)
    end,
    Tmp.

assure_no_file(File) ->
    case file:read_file_info(File) of
        {ok, _FileInfo} ->
            %% Wait for some other process to close the file:
            timer:sleep(100),
            assure_no_file(File);
        {error, _} ->
            ok
    end.

%% -> {ok, NewHead} | {try_again, integer()} | Error
fsck_try_est(Head, Fd, Fname, SlotNumbers, FH) ->
    %% Mod is the module to use for reading input when repairing.
    Cntrs = ets:new(cb_dets_repair, []),
    Input = cb_dets_v9:fsck_input(Head, Fd, Cntrs, FH),
    {Reply, SizeData} = do_sort(Head, SlotNumbers, Input, Cntrs, Fname),
    Bulk = false,
    case Reply of 
        {ok, NoDups, H1} ->
            _ = file:close(Fd),
            fsck_copy(SizeData, H1, Bulk, NoDups);
        {try_again, _} = Return ->
            close_files(Bulk, SizeData, Head),
            Return;
        Else ->
            _ = file:close(Fd),
            close_files(Bulk, SizeData, Head),
	    Else
    end.

do_sort(Head, SlotNumbers, Input, Cntrs, Fname) ->
    %% output_objs/4 replaces {LogSize,NoObjects} in Cntrs by
    %% {LogSize,Position,Data,NoObjects | NoCollections}.
    %% Data = {FileName,FileDescriptor} | [object()]
    %% For small tables Data can be a list of objects which is more
    %% efficient since no temporary files are created.
    Output = cb_dets_v9:output_objs(Head, SlotNumbers, Cntrs),
    TmpDir = filename:dirname(Fname),
    Reply = (catch file_sorter:sort(Input, Output, 
				    [{format, binary},{tmpdir, TmpDir}])),
    L = ets:tab2list(Cntrs),
    ets:delete(Cntrs),
    {Reply, lists:reverse(lists:keysort(1, L))}.

fsck_copy([{_LogSz, Pos, Bins, _NoObjects} | SizeData], Head, _Bulk, NoDups)
   when is_list(Bins) ->
    true = NoDups =:= 0,
    PWs = [{Pos,Bins} | lists:map(fun({_, P, B, _}) -> {P, B} end, SizeData)],
    #head{fptr = Fd, filename = FileName} = Head,
    cb_dets_utils:pwrite(Fd, FileName, PWs),
    {ok, Head#head{update_mode = dirty}};
fsck_copy(SizeData, Head, Bulk, NoDups) ->
    catch fsck_copy1(SizeData, Head, Bulk, NoDups).

fsck_copy1([SzData | L], Head, Bulk, NoDups) ->
    Out = Head#head.fptr,
    {LogSz, Pos, {FileName, Fd}, NoObjects} = SzData,
    Size = if NoObjects =:= 0 -> 0; true -> ?POW(LogSz-1) end,
    ExpectedSize = Size * NoObjects,
    case close_tmp(Fd) of
        ok -> ok;
        Err ->
	    close_files(Bulk, L, Head),
	    cb_dets_utils:file_error(FileName, Err)
    end,
    case file:position(Out, Pos) of
        {ok, Pos} -> ok;
        Err2 ->
	    close_files(Bulk, L, Head),
	    cb_dets_utils:file_error(Head#head.filename, Err2)
        end,
    CR = file:copy({FileName, [raw,binary]}, Out),
    _ = file:delete(FileName),
    case CR of 
	{ok, Copied} when Copied =:= ExpectedSize;
			  NoObjects =:= 0 -> % the segments
	    fsck_copy1(L, Head, Bulk, NoDups);
	{ok, _Copied} -> % should never happen
	    close_files(Bulk, L, Head),
	    Reason = if Bulk -> initialization_failed; 
			true -> repair_failed end,
            {error, {Reason, Head#head.filename}};
	FError ->
	    close_files(Bulk, L, Head),
	    cb_dets_utils:file_error(FileName, FError)
    end;
fsck_copy1([], Head, _Bulk, NoDups) when NoDups =/= 0 ->
    {error, {initialization_failed, Head#head.filename}};
fsck_copy1([], Head, _Bulk, _NoDups) ->
    {ok, Head#head{update_mode = dirty}}. 

close_files(false, SizeData, Head) ->
    _ = file:close(Head#head.fptr),
    close_files(true, SizeData, Head);
close_files(true, SizeData, _Head) ->
    Fun = fun({_Size, _Pos, {FileName, Fd}, _No}) ->
		  _ = close_tmp(Fd),
		  file:delete(FileName);
	     (_) ->
		  ok
	  end,
    lists:foreach(Fun, SizeData).

close_tmp(Fd) ->
    file:close(Fd).

fslot(H, Slot) ->
    case catch begin
                   {NH, []} = write_cache(H),
                   Objs = cb_dets_v9:slot_objs(NH, Slot),
                   {NH, Objs}
               end of
        {NewHead, _Objects} = Reply when is_record(NewHead, head) ->
            Reply
    end.

do_update_counter(Head, _Key, _Incr) when Head#head.type =/= set ->
    {Head, badarg};
do_update_counter(Head, Key, Incr) ->
    case flookup_keys(Head, [Key]) of
	{H1, [O]} ->
	    Kp = H1#head.keypos,
	    case catch try_update_tuple(O, Kp, Incr) of
		{'EXIT', _} ->
		    {H1, badarg};
		{New, Term} ->
		    case finsert(H1, [Term]) of
			{H2, ok} -> 
			    {H2, New};
			Reply -> 
			    Reply
		    end
	    end;
	{H1, []} ->
	    {H1, badarg};
	HeadError ->
	    HeadError
    end.
    
try_update_tuple(O, _Kp, {Pos, Incr}) ->
    try_update_tuple2(O, Pos, Incr);
try_update_tuple(O, Kp, Incr) ->
    try_update_tuple2(O, Kp+1, Incr).

try_update_tuple2(O, Pos, Incr) ->
    New = element(Pos, O) + Incr,
    {New, setelement(Pos, O, New)}.

set_verbose(true) ->
    put(verbose, yes);
set_verbose(_) ->
    erase(verbose).

where_is_object(Head, Object) ->
    Keypos = Head#head.keypos,
    case check_objects([Object], Keypos) of
	true ->
	    case catch write_cache(Head) of
		{NewHead, []} ->
		    {NewHead, cb_dets_v9:find_object(NewHead, Object)};
		{NewHead, _} = HeadError when is_record(NewHead, head) ->
		    HeadError
	    end;
	false ->
	    {Head, badarg}
    end.

check_objects([T | Ts], Kp) when tuple_size(T) >= Kp ->
    check_objects(Ts, Kp);
check_objects(L, _Kp) ->
    L =:= [].

no_things(Head) ->
    Head#head.no_keys.

file_no_things(FH) ->
    FH#fileheader.no_keys.

%%% The write cache is list of {Key, [Item]} where Item is one of
%%% {Seq, delete_key}, {Seq, {lookup,Pid}}, {Seq, {delete_object,object()}}, 
%%% or {Seq, {insert,object()}}. Seq is a number that increases
%%% monotonically for each item put in the cache. The purpose is to
%%% make sure that items are sorted correctly. Sequences of delete and
%%% insert operations are inserted in the cache without doing any file
%%% operations. When the cache is considered full, a lookup operation
%%% is requested, or after some delay, the contents of the cache are
%%% written to the file, and the cache emptied.
%%%
%%% Data is not allowed to linger more than 'delay' milliseconds in
%%% the write cache. A delayed_write message is received when some
%%% datum has become too old. If 'wrtime' is equal to 'undefined',
%%% then the cache is empty and no such delayed_write message has been
%%% scheduled. Otherwise there is a delayed_write message scheduled,
%%% and the value of 'wrtime' is the time when the cache was last
%%% written, or when it was first updated after the cache was last
%%% written.

update_cache(Head, KeysOrObjects, What) ->
    {Head1, LU, PwriteList} = update_cache(Head, [{What,KeysOrObjects}]),
    {NewHead, ok} = cb_dets_utils:pwrite(Head1, PwriteList),
    {NewHead, LU}.

%% -> {NewHead, [object()], pwrite_list()} | throw({Head, Error})
update_cache(Head, ToAdd) ->
    Cache = Head#head.cache,
    #cache{cache = C, csize = Size0, inserts = Ins} = Cache,
    NewSize = Size0 + erlang:external_size(ToAdd),
    %% The size is used as a sequence number here; it increases monotonically.
    {NewC, NewIns, Lookup, Found} = 
	cache_binary(Head, ToAdd, C, Size0, Ins, false, []),
    NewCache = Cache#cache{cache = NewC, csize = NewSize, inserts = NewIns},
    Head1 = Head#head{cache = NewCache},
    if 
	Lookup; NewSize >= Cache#cache.tsize ->
	    %% The cache is considered full, or some lookup.
	    {NewHead, LU, PwriteList} = cb_dets_v9:write_cache(Head1),
	    {NewHead, Found ++ LU, PwriteList};
	NewC =:= [] ->
	    {Head1, Found, []};
	Cache#cache.wrtime =:= undefined ->
	    %% Empty cache. Schedule a delayed write.
	    Now = time_now(), Me = self(),
	    Call = ?DETS_CALL(Me, {delayed_write, Now}),
	    erlang:send_after(Cache#cache.delay, Me, Call),
	    {Head1#head{cache = NewCache#cache{wrtime = Now}}, Found, []};
	Size0 =:= 0 ->
	    %% Empty cache that has been written after the
	    %% currently scheduled delayed write.
	    {Head1#head{cache = NewCache#cache{wrtime = time_now()}}, Found, []};
	true ->
	    %% Cache is not empty, delayed write has been scheduled.
	    {Head1, Found, []}
    end.

cache_binary(Head, [{Q,Os} | L], C, Seq, Ins, Lu,F) when Q =:= delete_object ->
    cache_obj_op(Head, L, C, Seq, Ins, Lu, F, Os, Head#head.keypos, Q);
cache_binary(Head, [{Q,Os} | L], C, Seq, Ins, Lu, F) when Q =:= insert ->
    NewIns = Ins + length(Os),
    cache_obj_op(Head, L, C, Seq, NewIns, Lu, F, Os, Head#head.keypos, Q);
cache_binary(Head, [{Q,Ks} | L], C, Seq, Ins, Lu, F) when Q =:= delete_key ->
    cache_key_op(Head, L, C, Seq, Ins, Lu, F, Ks, Q);
cache_binary(Head, [{Q,Ks} | L], C, Seq, Ins, _Lu, F) when C =:= [] -> % lookup
    cache_key_op(Head, L, C, Seq, Ins, true, F, Ks, Q);
cache_binary(Head, [{Q,Ks} | L], C, Seq, Ins, Lu, F) -> % lookup
    case cb_dets_utils:cache_lookup(Head#head.type, Ks, C, []) of
	false ->
	    cache_key_op(Head, L, C, Seq, Ins, true, F, Ks, Q);
	Found ->
	    {lookup,Pid} = Q,
	    cache_binary(Head, L, C, Seq, Ins, Lu, [{Pid,Found} | F])
    end;
cache_binary(_Head, [], C, _Seq, Ins, Lu, F) ->
    {C, Ins, Lu, F}.

cache_key_op(Head, L, C, Seq, Ins, Lu, F, [K | Ks], Q) ->
    E = {K, {Seq, Q}},
    cache_key_op(Head, L, [E | C], Seq+1, Ins, Lu, F, Ks, Q);
cache_key_op(Head, L, C, Seq, Ins, Lu, F, [], _Q) ->
    cache_binary(Head, L, C, Seq, Ins, Lu, F).

cache_obj_op(Head, L, C, Seq, Ins, Lu, F, [O | Os], Kp, Q) ->
    E = {element(Kp, O), {Seq, {Q, O}}},
    cache_obj_op(Head, L, [E | C], Seq+1, Ins, Lu, F, Os, Kp, Q);
cache_obj_op(Head, L, C, Seq, Ins, Lu, F, [], _Kp, _Q) ->
    cache_binary(Head, L, C, Seq, Ins, Lu, F).

%% Called after some delay.
%% -> NewHead
delayed_write(Head, WrTime) ->
    Cache = Head#head.cache,
    LastWrTime = Cache#cache.wrtime,
    if
	LastWrTime =:= WrTime ->
	    %% The cache was not emptied during the last delay.
	    case catch write_cache(Head) of
		{Head2, []} ->
		    NewCache = (Head2#head.cache)#cache{wrtime = undefined},
		    Head2#head{cache = NewCache};
		{NewHead, _Error} -> % Head.update_mode has been updated
		    NewHead
	    end;
	true ->
	    %% The cache was emptied during the delay.
	    %% Has anything been written since then?
	    if 
		Cache#cache.csize =:= 0 ->
		    %% No, further delayed write not needed.
		    NewCache = Cache#cache{wrtime = undefined},
		    Head#head{cache = NewCache};
		true ->
		    %% Yes, schedule a new delayed write.
		    When = round((LastWrTime - WrTime)/1000), Me = self(),
		    Call = ?DETS_CALL(Me, {delayed_write, LastWrTime}),
		    erlang:send_after(When, Me, Call),
		    Head
	    end
    end.

%% -> {NewHead, [LookedUpObject]} | throw({NewHead, Error})
write_cache(Head) ->
    {Head1, LU, PwriteList} = cb_dets_v9:write_cache(Head),
    {NewHead, ok} = cb_dets_utils:pwrite(Head1, PwriteList),
    {NewHead, LU}.

status(Head) ->
    case Head#head.update_mode of
	saved -> ok;
	dirty -> ok;
	new_dirty -> ok;
	Error -> Error
    end.

%%% Scan the file from start to end by reading chunks.

%% -> cb_dets_cont()
init_scan(Head, NoObjs) ->
    check_safe_fixtable(Head),
    FreeLists = cb_dets_utils:get_freelists(Head),
    Base = Head#head.base,
    case cb_dets_utils:find_next_allocated(FreeLists, Base, Base) of
        {From, To} ->
            #cb_dets_cont{no_objs = NoObjs, bin = <<>>, alloc = {From,To,<<>>}};
        none ->
            #cb_dets_cont{no_objs = NoObjs, bin = eof, alloc = <<>>}
    end.

check_safe_fixtable(Head) ->
    case (Head#head.fixed =:= false) andalso 
         ((get(verbose) =:= yes) orelse cb_dets_utils:debug_mode()) of
        true ->
            error_logger:format
              ("** cb_dets: traversal of ~tp needs safe_fixtable~n",
               [Head#head.name]);
        false ->
            ok
    end.

%% -> {[RTerm], cb_dets_cont()} | {scan_error, Reason}
%% RTerm = {Pos, Next, Size, Status, Term}
scan(_Head, #cb_dets_cont{alloc = <<>>}=C) ->
    {[], C};
scan(Head, C) -> % when is_record(C, cb_dets_cont)
    #cb_dets_cont{no_objs = No, alloc = L0, bin = Bin} = C,
    {From, To, L} = L0,
    R = case No of
	    default ->
		0;
	    _ when is_integer(No) ->
		-No-1
	end,
    scan(Bin, Head, From, To, L, [], R, {C, Head#head.type}).

scan(Bin, H, From, To, L, Ts, R, {C0, Type} = C) ->
    case cb_dets_v9:scan_objs(H, Bin, From, To, L, Ts, R, Type) of
        {more, NFrom, NTo, NL, NTs, NR, Sz} ->
            scan_read(H, NFrom, NTo, Sz, NL, NTs, NR, C);
        {stop, <<>>=B, NFrom, NTo, <<>>=NL, NTs} ->
            Ftab = cb_dets_utils:get_freelists(H),
            case cb_dets_utils:find_next_allocated(Ftab, NFrom, H#head.base) of
                none ->
                    {NTs, C0#cb_dets_cont{bin = eof, alloc = B}};
                _ -> 
                    {NTs, C0#cb_dets_cont{bin = B, alloc = {NFrom, NTo, NL}}}
            end;
        {stop, B, NFrom, NTo, NL, NTs} ->
            {NTs, C0#cb_dets_cont{bin = B, alloc = {NFrom, NTo, NL}}};
        bad_object ->
            {scan_error, cb_dets_utils:bad_object(scan, {From, To, Bin})}
    end.

scan_read(_H, From, To, _Min, L0, Ts, 
	  R, {C, _Type}) when R >= ?CHUNK_SIZE ->
    %% We may have read (much) more than CHUNK_SIZE, if there are holes.
    L = {From, To, L0},
    {Ts, C#cb_dets_cont{bin = <<>>, alloc = L}};
scan_read(H, From, _To, Min, _L, Ts, R, C) ->
    Max = if 
	      Min < ?CHUNK_SIZE -> ?CHUNK_SIZE; 
	      true -> Min 
	  end,
    FreeLists = cb_dets_utils:get_freelists(H),
    case cb_dets_utils:find_allocated(FreeLists, From, Max, H#head.base) of
        <<>>=Bin0 ->
            {Cont, _} = C,
            {Ts, Cont#cb_dets_cont{bin = eof, alloc = Bin0}};
        <<From1:32,To1:32,L1/binary>> ->
            case cb_dets_utils:pread_n(H#head.fptr, From1, Max) of
                eof ->
                    {scan_error, premature_eof};
                NewBin ->
                    scan(NewBin, H, From1, To1, L1, Ts, R, C)
            end
    end.

err(Error) ->
    case get(verbose) of
	yes -> 
	    error_logger:format("** cb_dets: failed with ~tw~n", [Error]),
	    Error;
	undefined  ->
	    Error
    end.

-compile({inline, [time_now/0]}).
time_now() ->
    erlang:monotonic_time(1000000).

make_timestamp(MonTime, TimeOffset) ->
    ErlangSystemTime = erlang:convert_time_unit(MonTime+TimeOffset,
						native,
						microsecond),
    MegaSecs = ErlangSystemTime div 1000000000000,
    Secs = ErlangSystemTime div 1000000 - MegaSecs*1000000,
    MicroSecs = ErlangSystemTime rem 1000000,
    {MegaSecs, Secs, MicroSecs}.

%%%%%%%%%%%%%%%%%  DEBUG functions %%%%%%%%%%%%%%%%

file_info(FileName) ->
    case catch read_file_header(FileName, read, false) of
	{ok, Fd, FH} ->
	    _ = file:close(Fd),
            cb_dets_v9:file_info(FH);
	Other ->
	    Other
    end.

get_head_field(Fd, Field) ->
    cb_dets_utils:read_4(Fd, Field).

%% Dump the contents of a DAT file to the tty
%% internal debug function which ignores the closed properly thingie
%% and just tries anyway

view(FileName) ->
    case catch read_file_header(FileName, read, false) of
        {ok, Fd, FH} ->
            try cb_dets_v9:check_file_header(FH, Fd) of
                {ok, H0} ->
                    case cb_dets_v9:check_file_header(FH, Fd) of
                        {ok, H0} ->
                            H = cb_dets_v9:init_freelist(H0),
                            v_free_list(H),
                            cb_dets_v9:v_segments(H),
                            ok;
                        X ->
                            X
                    end
            after _ = file:close(Fd)
            end;
	X -> 
	    X
    end.

v_free_list(Head) ->
    io:format("FREE LIST ...... \n",[]),
    io:format("~p~n", [cb_dets_utils:all_free(Head)]),
    io:format("END OF FREE LIST \n",[]).
