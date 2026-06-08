%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_crl_manager).

-behaviour(gen_server).

-include("ns_common.hrl").
-include_lib("public_key/include/public_key.hrl").

%% public API
-export([start_link/0,
         get_config/0,
         set_config/1,
         reload/0,
         get_status/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(CHRONICLE_KEY, crl_settings).
-define(DEFAULT_POLL_INTERVAL_MS, 60000).
-define(RELOAD_TIMEOUT, ?get_timeout(reload_timeout, 60000)).
-define(STATUS_TIMEOUT, ?get_timeout(status_timeout, 60000)).

%% Per-entry result produced by cb_crl_manager for every CRL block found in a
%% file (a PEM may contain multiple CertificateList entries).
-record(entry_result, {
    result :: ok | {error, term()},
    issuer :: public_key:issuer_name(),
    this_update :: calendar:datetime() | undefined,
    next_update :: calendar:datetime() | undefined,
    der :: binary(),
    crl_number :: non_neg_integer() | undefined
}).
%% Per-entry crl load result (transient — see cb_crl.hrl).
-type entry_result() :: #entry_result{}.

%% Per-load-directory-file reload state (see cb_crl.hrl).  Keyed by the full
%% load-directory path (not the base name) so that files sharing a base name
%% across different directories cannot be confused.  The config/crls copy uses
%% the file's base name.
-record(crl_reload_status, {
    mtime :: file:date_time(), %% mtime of the load-dir file at last attempt
    result :: loaded | failed,
    time :: calendar:datetime(), %% when the last attempt happened
    errors :: [binary()] %% human-readable strings
}).

-type reload_status() :: #crl_reload_status{}.
-type file_state()    :: #{AbsolutePath :: string() => reload_status()}.

%% Map of files currently present in config/crls (the last-known-good set that
%% is loaded into cb_crl_cache and pushed to consumers).  These are exactly the
%% files in crls_dir(), which is flat and fixed, so it is keyed by base name
%% (no ambiguity).  The value is the SHA-256 hex digest of the file content.
-type active_files() :: #{BaseName :: string() => binary()}.

-record(state, {
    poll_directory   :: undefined | file:filename_all(),
    poll_interval_ms :: pos_integer(),
    poll_timer       :: reference() | undefined,
    %% Outcome of the most recent (re)load attempt per load-directory file.
    file_state       :: file_state(),
    %% Files currently held in config/crls (base name => content checksum).
    active           :: active_files()
}).

%%%===================================================================
%%% Public API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Returns the configuration map currently stored in chronicle (or the
%% default if unset / feature disabled).
-spec get_config() -> map().
get_config() ->
    case chronicle_compat:get(?CHRONICLE_KEY, #{default => undefined}) of
        undefined -> default_config();
        Cfg when is_map(Cfg) -> merge_default(Cfg)
    end.

-spec set_config(map()) -> ok | {error, term()}.
set_config(NewCfg0) ->
    Fun =
        fun (Snapshot) ->
                CurrentRaw =
                    case maps:find(?CHRONICLE_KEY, Snapshot) of
                        {ok, {Cfg, _Rev}} -> Cfg;
                        error -> #{}
                    end,
                MergedPPS =
                    maps:merge(
                      maps:get(policy_per_scope, CurrentRaw, #{}),
                      maps:get(policy_per_scope, NewCfg0, #{})),
                Merged0 = maps:merge(CurrentRaw, NewCfg0),
                NewCfg = merge_default(
                           Merged0#{policy_per_scope => MergedPPS}),
                {commit, [{set, ?CHRONICLE_KEY, NewCfg}]}
        end,
    case chronicle_kv:transaction(kv, [?CHRONICLE_KEY], Fun, #{}) of
        {ok, _} -> ok;
        {error, Err} -> {error, Err}
    end.

%% Merge a partial config with defaults.  Performs a deep merge for
%% policy_per_scope so that missing scopes get their default values.
-spec merge_default(map()) -> map().
merge_default(Cfg) ->
    Default = default_config(),
    Merged = maps:merge(Default, Cfg),
    DefaultPPS = maps:get(policy_per_scope, Default),
    CfgPPS = maps:get(policy_per_scope, Cfg, #{}),
    Merged#{policy_per_scope => maps:merge(DefaultPPS, CfgPPS)}.

%% Trigger an immediate, unconditional reload of all CRL files from the
%% configured directory (ignoring mtime-based caching).  Each file is loaded
%% independently and atomically (whole file or nothing): a file is only loaded
%% if it can be read, decoded, and every entry in it is valid.  A file that
%% fails to load never overwrites or removes a previously loaded good copy.
%%
%% Returns {ok, StatusMap} where StatusMap has the same shape as get_status/0
%% (see below).  Returns {error, not_configured} when no CRL source directory
%% has been set.
-spec reload() ->
          {ok, #{file:filename_all() => map()}}
        | {error, not_configured}.
reload() ->
    gen_server:call(?SERVER, reload, ?RELOAD_TIMEOUT).

%% Return the current per-file CRL status for this node.
%%
%% Returns #{LoadDirPath => StatusMap} where each StatusMap is a plain map
%% (no records, RPC-safe) describing both what we are currently *using* and the
%% outcome of the last reload attempt:
%%   status      => active | expired | not_yet_valid | untrusted
%%                  | invalid | not_loaded
%%                  — state of the config/crls copy we currently use, freshly
%%                    re-verified at query time.
%%   entries     => [EntryMap] — per-entry breakdown of that active copy; lets
%%                  callers see which entry is expired/untrusted.  EntryMap has:
%%                    issuer, status, this_update, next_update, checksum.
%%   last_reload => #{result => loaded | failed | not_attempted,
%%                    time   => calendar:datetime() | undefined,
%%                    errors => [binary()]}
%%
%% An empty map is returned when no source is configured or no files exist.
-spec get_status() -> #{file:filename_all() => map()}.
get_status() ->
    gen_server:call(?SERVER, get_status, ?STATUS_TIMEOUT).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Self = self(),
    chronicle_compat_events:subscribe(
      fun (?CHRONICLE_KEY) -> Self ! config_changed;
          (_)              -> ok
      end),
    Cfg = get_config(),
    %% Crash on startup if we cannot create the directory we depend on.
    ok = ensure_crls_dir(),
    %% Seed the cache from the last-known-good copies persisted in config/crls
    %% so revocation checking keeps working from the moment we start, before
    %% (and independently of) any attempt to reload from the load directory.
    Active0 = case maps:get(poll_directory, Cfg) of
                  undefined -> #{};
                  _ -> populate_cache_from_config_crls()
              end,
    State0 = #state{poll_directory   = undefined,
                    poll_interval_ms = ?DEFAULT_POLL_INTERVAL_MS,
                    poll_timer       = undefined,
                    file_state       = #{},
                    active           = Active0},
    State1 = apply_config(Cfg, State0),
    %% Remove any cache entries that were left behind by a previous instance
    %% of this process (e.g. it crashed after a file was deleted from disk).
    ok = purge_stale_cache_entries(State1#state.active),
    {ok, schedule_timer(State1)}.

handle_call(reload, _From, #state{poll_directory = undefined} = State) ->
    {reply, {error, not_configured}, State};
handle_call(reload, _From, #state{poll_directory = Dir} = State) ->
    ?log_debug("CRL manual reload start: ~p", [Dir]),
    ?flush(poll_directory),
    NewState = scan_directory(Dir, State, true),
    ?log_debug("CRL manual reload done: ~p active file(s)",
               [maps:size(NewState#state.active)]),
    {reply, {ok, build_status_map(NewState)}, schedule_timer(NewState)};

handle_call(get_status, _From, State) ->
    {reply, build_status_map(State), State};

handle_call(Req, _From, State) ->
    ?log_error("Received unknown call: ~p", [Req]),
    {reply, {error, unknown_request}, State}.

handle_cast(Msg, State) ->
    ?log_error("Received unknown cast: ~p", [Msg]),
    {noreply, State}.

handle_info(config_changed, State) ->
    Cfg = get_config(),
    State1 = apply_config(Cfg, State),
    {noreply, schedule_timer(State1)};

handle_info(poll_directory, #state{poll_directory = undefined} = State) ->
    %% Poll directory is undefined; nothing to poll
    ?flush(poll_directory),
    {noreply, State};
handle_info(poll_directory, #state{poll_directory = Dir} = State) ->
    ?flush(poll_directory),
    State1 = scan_directory(Dir, State, false),
    {noreply, schedule_timer(State1)};

handle_info(Msg, State) ->
    ?log_error("Received unknown info: ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_, State, _) -> {ok, State}.

%%%===================================================================
%%% Internal helpers
%%%===================================================================

-spec get_crl_number(#'CertificateList'{}) ->
          non_neg_integer() | undefined.
get_crl_number(#'CertificateList'{tbsCertList = TBS}) ->
    Exts = case TBS#'TBSCertList'.crlExtensions of
               asn1_NOVALUE -> [];
               E            -> E
           end,
    case pubkey_cert:select_extension(?'id-ce-cRLNumber', Exts) of
        undefined ->
            undefined;
        #'Extension'{extnValue = V} ->
            try public_key:der_decode('CRLNumber', iolist_to_binary(V))
            catch _:_ -> undefined end
    end.

-spec default_config() -> map().
default_config() ->
    #{poll_directory => default_local_crl_source_dir(),
      policy_per_scope =>
          #{client_auth => disabled,
            node_to_node => disabled},
      delta_crls => false,
      poll_interval_ms => ?DEFAULT_POLL_INTERVAL_MS}.

%% Apply a new configuration to State without creating a window where the
%% cache is empty and without the race where a non-disabled policy is
%% visible in ETS before the corresponding CRL data has been loaded.
%%
%% The function executes three strictly-ordered phases:
%%
%%   Phase 1 — Disable first.
%%     Write 'disabled' to ETS for every scope whose new policy is
%%     'disabled'.  Any concurrent verify_fun call for that scope will
%%     now pass through immediately, so it is safe to modify the cache.
%%
%%   Phase 2 — Load CRL data.
%%     Insert / update / remove CRL files according to the new poll dir.
%%     Three poll dir transitions are handled:
%%       poll dir unchanged  — only interval/policy changed; cache untouched
%%       _ → undefined       — poll dir removed; bulk-remove all CRL records
%%       _ → Dir             — new or changed directory; scan_directory adds
%%                             new files before removing old ones so the cache
%%                             is never empty during the transition
%%
%%   Phase 3 — Enable last.
%%     Write non-disabled policies to ETS only after Phase 2 completes.
%%     Any verify_fun call that now sees a non-disabled policy is guaranteed
%%     to find its CRLs in the cache.
-spec apply_config(map(), #state{}) -> #state{}.
apply_config(Cfg, #state{poll_directory = OldPollDir} = State) ->
    NewPollDir  = maps:get(poll_directory, Cfg),
    NewInterval = maps:get(poll_interval_ms, Cfg),
    NewPolicies = maps:get(policy_per_scope, Cfg),
    State1 = State#state{poll_directory = NewPollDir,
                         poll_interval_ms = NewInterval},

    %% Phase 1: disable scopes whose new policy is 'disabled'.
    maps:foreach(
      fun (Scope, disabled) ->
              cb_crl_cache:set_policy(Scope, disabled);
          (_Scope, _Policy) ->
              ok
      end, NewPolicies),

    %% Phase 2: update CRL data.
    State2 =
        case {OldPollDir, NewPollDir} of
            {Same, Same} ->
                %% Poll dir unchanged; cache already up-to-date.
                State1;
            {_, undefined} ->
                ?log_info(
                   "CRL poll directory cleared; removing ~p loaded CRL file(s)",
                   [maps:size(State#state.active)]),
                cb_crl_cache:remove_all_crls(),
                clear_config_crls(),
                State1#state{file_state = #{}, active = #{}};
            {_, Dir} ->
                ?log_info("CRL poll directory set to ~p", [Dir]),
                scan_directory(Dir, State1, false)
        end,

    %% Phase 3: enable / update scopes whose new policy is not 'disabled'.
    %% CRL data is now in the cache, so the verify_fun will find what it
    %% needs as soon as it reads the new policy from ETS.
    maps:foreach(
      fun (_Scope, disabled) ->
              %% Already written in Phase 1; skip.
              ok;
          (Scope, Policy) ->
              cb_crl_cache:set_policy(Scope, Policy)
      end, NewPolicies),

    State2.

%% Schedule the next poll and return the updated state.
%% No timer is created when there is nothing to poll.
-spec schedule_timer(#state{}) -> #state{}.
schedule_timer(#state{poll_directory = undefined} = State) ->
    cancel_timer(State#state.poll_timer),
    State#state{poll_timer = undefined};
schedule_timer(#state{poll_interval_ms = Ms} = State) ->
    cancel_timer(State#state.poll_timer),
    Ref = erlang:send_after(Ms, self(), poll_directory),
    State#state{poll_timer = Ref}.

-spec cancel_timer(reference() | undefined) -> ok.
cancel_timer(undefined) -> ok;
cancel_timer(Ref) ->
    erlang:cancel_timer(Ref),
    ok.

%% Scan the load directory, (re)loading each file independently into
%% config/crls and the cache, and reconciling files that have disappeared.
%%
%% Per-file rules (whole-file atomic):
%%   * A file is loaded only if it can be read, decoded, and EVERY entry in it
%%     is valid (signature trusted and within its validity window).
%%   * On success the file is copied verbatim (same bytes, same name) into
%%     config/crls and all its entries are inserted into cb_crl_cache.
%%   * On any failure (unreadable, undecodable, or any invalid entry) the
%%     previously loaded good copy — if any — is left untouched in both
%%     config/crls and the cache.  A load never makes things worse.
%%   * A file that has disappeared from the load directory is removed from
%%     config/crls and the cache.
%%
%% When ForceReload is true every present file is re-attempted regardless of
%% mtime (used by the manual-reload endpoint); otherwise files whose mtime is
%% unchanged are skipped.
%%
%% file_state is keyed by the full load-directory path (not the base name) so
%% that files sharing a base name across different directories are never
%% confused.  active is keyed by base name: it mirrors crls_dir(), which is a
%% flat, fixed directory, so there is no ambiguity there.
-spec scan_directory(file:filename_all(), #state{}, ForceReload :: boolean()) ->
          #state{}.
scan_directory(DirBin, State, ForceReload) when is_binary(DirBin) ->
    scan_directory(binary_to_list(DirBin), State, ForceReload);
scan_directory(Dir, State, ForceReload) ->
    maybe
        TrustedCAs = ns_server_cert:trusted_CAs(der),
        TS = calendar:universal_time(),
        {ok, DiskNames} =
            case file:list_dir(Dir) of
                {ok, Names} ->
                    %% Skip dotfiles; no extension filter — try to load
                    %% everything
                    {ok, [N || N <- Names, N =/= [], hd(N) =/= $.]};
                {error, enoent} ->
                    {ok, []};
                {error, Err} ->
                    {error, {list_dir_error, Err}}
            end,

        %% Pass 1: attempt to (re)load each file present in the load directory.
        %% file_state is keyed by full path; active by base name.
        UpdatedState =
            lists:foldl(
            fun (Name, StateAcc) ->
                FullPath = filename:join(Dir, Name),
                maybe_load_from_local_file(Name, FullPath, ForceReload, TS,
                                            TrustedCAs, StateAcc)
            end, State, DiskNames),

        %% Pass 2: reconcile files that have disappeared from the load
        %% directory. active (base names): a vanished file's config/crls copy
        %% and cache entry are removed.  file_state (full paths): stale reload
        %% records are dropped.
        DiskNameSet = sets:from_list(DiskNames),
        DiskPaths = [filename:join(Dir, N) || N <- DiskNames],
        DiskPathSet = sets:from_list(DiskPaths),
        Active2 =
            maps:filter(
            fun (Name, _Checksum) ->
                    case sets:is_element(Name, DiskNameSet) of
                        true  -> true;
                        false -> ok /= remove_from_cache(Name)
                    end
            end, UpdatedState#state.active),
        FS2 = maps:filter(fun (Path, _Status) ->
                                sets:is_element(Path, DiskPathSet)
                        end, UpdatedState#state.file_state),
        UpdatedState#state{file_state = FS2, active = Active2}
    else
        {error, {list_dir_error, Reason}} ->
            ?log_error("Failed to list CRL directory ~p: ~p", [Dir, Reason]),
            State
    end.

%% Attempt to load a single file from the load directory if it has changed
maybe_load_from_local_file(Name, FilePath, ForceReload, TS, TrustedCAs,
                           #state{file_state = FS} = State) ->
    MTime = filelib:last_modified(FilePath),
    case maps:get(FilePath, FS, undefined) of
        #crl_reload_status{mtime = MTime} when not ForceReload ->
            %% mtime unchanged and reload not forced; skip
            State;
        _ ->
            load_from_local_file(Name, FilePath, MTime, TS, TrustedCAs, State)
    end.

%% Attempt to load a single file from the load directory
-spec load_from_local_file(Name         :: file:filename_all(),
                           Path         :: file:filename_all(),
                           FileMTime    :: file:date_time() | 0,
                           CurTS        :: calendar:datetime(),
                           TrustedCAs   :: [binary()],
                           State        :: #state{}) -> #state{}.
load_from_local_file(Name, Path, FileMTime, CurTS, TrustedCAs,
                     #state{file_state = FS, active = Active} = State) ->
    ?log_debug("CRL scan: loading file ~p", [Path]),
    maybe
        {ok, Binary} ?= case file:read_file(Path) of
                            {ok, Bin} -> {ok, Bin};
                            {error, Err} -> {error, {read_error, Err}}
                        end,
        {ok, Results} ?= decode_and_verify_crl(Binary, TrustedCAs),
        Bad = [R || R <- Results, R#entry_result.result =/= ok],
        ok ?= case Bad of
                    [] -> ok;
                    _  -> {error, {bad_crl_entries, Bad}}
                end,
        {ok, Checksum} ?= add_to_cache(Name, Binary, Results),
        Status = #crl_reload_status{mtime  = FileMTime,
                                    result = loaded,
                                    time   = CurTS,
                                    errors = []},
        State#state{file_state = maps:put(Path, Status, FS),
                    active = maps:put(Name, Checksum, Active)}
    else
        {error, Reason} ->
            BadStatus = #crl_reload_status{mtime  = FileMTime,
                                           result = failed,
                                           time   = CurTS,
                                           errors = format_load_errors(Reason)},
            State#state{file_state = maps:put(Path, BadStatus, FS)}
    end.

%% Copy a fully-valid file verbatim into config/crls and insert its entries
%% into the cache.
-spec add_to_cache(file:filename_all(), binary(), [entry_result()]) ->
          {ok, binary()} | {error, term()}.
add_to_cache(Name, Binary, ValidatedEntries) ->
    FilePath = filename:join(crls_dir(), Name),
    maybe
        ok ?= misc:atomic_write_file(FilePath, Binary),
        Pairs = [{I, D}
                 || #entry_result{issuer = I, der = D} <- ValidatedEntries],
        cb_crl_cache:insert_file(FilePath, Pairs),
        {ok, file_checksum(Binary)}
    else
        {error, Err} ->
            ?log_error("Failed to add CRL file ~p to cache: ~p",
                       [FilePath, Err]),
            {error, Err}
    end.

%% Remove a crl copy and its cache entry.
-spec remove_from_cache(file:filename_all()) -> ok | {error, term()}.
remove_from_cache(Name) ->
    FullPath = filename:join(crls_dir(), Name),
    cb_crl_cache:remove_file(FullPath),
    case file:delete(FullPath) of
        ok ->
            ?log_debug("Deleted CRL file: ~p", [FullPath]),
            ok;
        {error, enoent} ->
            ?log_debug("CRL file already absent: ~p", [FullPath]),
            ok;
        {error, Reason} ->
            ?log_error("Failed to delete CRL file ~p: ~p",
                       [FullPath, Reason]),
            {error, Reason}
    end.

%% Should return a list of errors
format_load_errors({read_error, Reason}) ->
    [misc:format_bin("Failed to read file. Reason: ~p", [Reason])];
format_load_errors({decode_error, Reason}) ->
    ReasonStr = lists:join("; ", format_load_errors(Reason)),
    [misc:format_bin("Failed to decode file. Reason: ~s", [ReasonStr])];
format_load_errors({bad_crl_entries, BadEntries}) ->
    [entry_error_text(R) || R <- BadEntries];
format_load_errors({invalid_crl, _}) ->
    [<<"Invalid CRL">>];
format_load_errors(Other) ->
    [misc:format_bin("Unexpected error. Reason: ~p", [Other])].

%% Remove cache entries whose config/crls file is no longer in the active set.
%% This cleans up stale entries left by a previous instance of this gen_server
%% (e.g. after a crash while a file was being deleted).
-spec purge_stale_cache_entries(active_files()) -> ok.
purge_stale_cache_entries(Active) ->
    CrlsDir = crls_dir(),
    ExpectedPaths =
        sets:from_list(
          [misc:normalize_path(filename:join(CrlsDir, Name))
           || Name <- maps:keys(Active)]),
    lists:foreach(
      fun (CachedPath) ->
              case sets:is_element(misc:normalize_path(CachedPath),
                                   ExpectedPaths) of
                  true  -> ok;
                  false ->
                      ?log_info("Purging stale CRL cache entry: ~p",
                                [CachedPath]),
                      ok = cb_crl_cache:remove_file(CachedPath)
              end
      end, cb_crl_cache:get_all_file_paths()).

%%%===================================================================
%%% config/crls directory helpers
%%%===================================================================

%% Node-local directory that holds the last-known-good CRL copies.  Mirrors the
%% convention used for config/certs in ns_ssl_services_setup.
-spec crls_dir() -> file:filename_all().
crls_dir() ->
    filename:join(path_config:component_path(data, "config"), "crls").

%% misc:mkdir_p/1 returns ok when the directory already exists, so any error
%% here is genuine.  We return it so init/1 crashes the gen_server.
-spec ensure_crls_dir() -> ok | {error, term()}.
ensure_crls_dir() ->
    Dir = crls_dir(),
    case misc:mkdir_p(Dir) of
        ok -> ok;
        {error, Reason} ->
            ?log_error("Failed to create CRL directory ~p: ~p", [Dir, Reason]),
            {error, Reason}
    end.

%% Base names of the files currently present in config/crls.
-spec list_config_crls() -> [file:filename_all()].
list_config_crls() ->
    case file:list_dir(crls_dir()) of
        {ok, Names} -> [N || N <- Names, N =/= [], hd(N) =/= $.];
        {error, _}  -> []
    end.

%% Delete every file in config/crls (used when the poll dir is cleared).
-spec clear_config_crls() -> ok.
clear_config_crls() ->
    CrlsDir = crls_dir(),
    lists:foreach(fun (Name) -> file:delete(filename:join(CrlsDir, Name)) end,
                  list_config_crls()),
    ok.

%% Decode every config/crls file and insert its entries into the cache.
%% Returns the active-files map (base name => content checksum).  Files that
%% fail to read or decode are skipped (and left on disk for diagnosis).
-spec populate_cache_from_config_crls() -> active_files().
populate_cache_from_config_crls() ->
    CrlsDir = crls_dir(),
    lists:foldl(
      fun (Name, Acc) ->
              FilePath = filename:join(CrlsDir, Name),
              case file:read_file(FilePath) of
                  {ok, Binary} ->
                      case decode_crl(Binary) of
                          {ok, Triples} ->
                              Pairs = [{I, D} || {I, _Decoded, D} <- Triples],
                              cb_crl_cache:insert_file(FilePath, Pairs),
                              ?log_debug("CRL seeded from config/crls: ~p",
                                         [FilePath]),
                              maps:put(Name, file_checksum(Binary), Acc);
                          {error, Reason} ->
                              ?log_error("Skipping undecodable crls "
                                         "file ~p: ~p", [FilePath, Reason]),
                              Acc
                      end;
                  {error, Reason} ->
                      ?log_error("Failed to read config/crls file ~p: ~p",
                                 [FilePath, Reason]),
                      Acc
              end
      end, #{}, list_config_crls()).

default_local_crl_source_dir() ->
    filename:join(path_config:component_path(data, "inbox"), "crls").

%%%===================================================================
%%% Status helpers (used by get_status/0)
%%%===================================================================

%% Build the per-file status map for the status / reload endpoints.
%%
%% The reported set of files is the union of the load-dir files we have a
%% reload record for and the files we currently hold in config/crls (the
%% active set).  Each is keyed by its load-directory path.
%%
%% For every file we report two independent things (all values RPC-safe):
%%   status      — the state of the config/crls copy we currently use, freshly
%%                 re-verified now (so expiry is accurate at query time):
%%                 active | expired | not_yet_valid | untrusted | invalid
%%                 | not_loaded
%%   entries     — per-entry breakdown of that active copy (issuer, status,
%%                 this_update, next_update, checksum)
%%   last_reload — outcome of the most recent attempt to load from the load dir
-spec build_status_map(#state{}) -> #{file:filename_all() => map()}.
build_status_map(#state{file_state = FS, active = Active}) ->
    TrustedDerCAs = ns_server_cert:trusted_CAs(der),
    ConfigDir = crls_dir(),
    %% Every active base name has a corresponding file_state full-path entry, so
    %% iterating file_state covers all reported files.
    maps:fold(
      fun (Path, ReloadStatus, Acc) ->
              Name = filename:basename(Path),
              {Status, Entries} =
                  case maps:is_key(Name, Active) of
                      true ->
                          current_status(filename:join(ConfigDir, Name),
                                         TrustedDerCAs);
                      false ->
                          {not_loaded, []}
                  end,
              maps:put(iolist_to_binary(Path),
                       #{status      => Status,
                         entries     => Entries,
                         last_reload => last_reload_map(ReloadStatus)}, Acc)
      end, #{}, FS).

%% Compute the current status of an active CRL by reading DER entries from
%% the cache and re-verifying them now.  Returns {FileStatus, [EntryMap]}.
-spec current_status(file:filename_all(), [binary()]) -> {atom(), [map()]}.
current_status(ConfigPath, TrustedDerCAs) ->
    case cb_crl_cache:get_file_crls(ConfigPath) of
        [] ->
            {not_loaded, []};
        DerCRLs ->
            Results = lists:map(
                        fun (Der) ->
                            case decode_and_verify_crl(Der, TrustedDerCAs) of
                                {ok, [R]} -> entry_to_map(R);
                                {error, _} -> invalid_entry_map()
                            end
                        end, DerCRLs),
            {aggregate_status(Results), Results}
    end.

%% Reduce per-entry results to a single file-level status, worst-first.
-spec aggregate_status([map()]) -> atom().
aggregate_status(Results) ->
    Statuses = [R || #{status := R} <- Results],
    case lists:member(expired, Statuses) of
        true -> expired;
        false ->
            case lists:member(not_yet_valid, Statuses) of
                true -> not_yet_valid;
                false ->
                    case lists:member(untrusted, Statuses) of
                        true -> untrusted;
                        false ->
                            case lists:member(invalid, Statuses) of
                                true  -> invalid;
                                false -> active
                            end
                    end
            end
    end.

%% Convert a per-entry verify result to a plain (RPC-safe) map.
-spec entry_to_map(entry_result()) -> map().
entry_to_map(#entry_result{result = Result,
                           issuer      = Issuer,
                           this_update = ThisUpdate,
                           next_update = NextUpdate,
                           der         = Der}) ->
    Status = case Result of
                 ok -> ok;
                 {error, crl_expired} -> expired;
                 {error, crl_not_yet_valid} -> not_yet_valid;
                 {error, crl_issuer_not_trusted} -> untrusted;
                 {error, _} -> invalid
             end,
    #{issuer      => iolist_to_binary(ns_server_cert:format_name(Issuer)),
      status      => Status,
      this_update => ThisUpdate,
      next_update => NextUpdate,
      checksum    => file_checksum(Der)}.

invalid_entry_map() ->
    #{issuer      => <<"unknown">>,
      status      => invalid,
      this_update => undefined,
      next_update => undefined,
      checksum    => <<>>}.

%% Convert a stored #crl_reload_status{} to a plain (RPC-safe) map.
%% 'undefined' (no attempt recorded yet) maps to a not_attempted result.
-spec last_reload_map(#crl_reload_status{} | undefined) -> map().
last_reload_map(undefined) ->
    #{result => not_attempted, time => undefined, errors => []};
last_reload_map(#crl_reload_status{result = Result, time = Time,
                                   errors = Errors}) ->
    #{result => Result, time => Time, errors => Errors}.

%%%===================================================================
%%% Error-string helpers (used to populate last_reload.errors)
%%%===================================================================

%% Build a human-readable string for a single invalid entry.
-spec entry_error_text(entry_result()) -> binary().
entry_error_text(#entry_result{result = {error, Reason}, issuer = Issuer}) ->
    IssuerStr = iolist_to_binary(ns_server_cert:format_name(Issuer)),
    Detail = reason_string(Reason),
    iolist_to_binary([<<"Entry issued by '">>, IssuerStr, <<"': ">>, Detail]).

-spec reason_string(term()) -> binary().
reason_string(crl_expired)            -> <<"CRL expired">>;
reason_string(crl_not_yet_valid)      -> <<"CRL not yet valid">>;
reason_string(crl_issuer_not_trusted) -> <<"CRL issuer not trusted">>;
reason_string(Other) ->
    iolist_to_binary(io_lib:format("~p", [Other])).

%% Compute a SHA-256 hex digest of raw file content.
-spec file_checksum(binary()) -> binary().
file_checksum(Binary) ->
    Hash = crypto:hash(sha256, Binary),
    iolist_to_binary([io_lib:format("~2.16.0b", [B]) || <<B>> <= Hash]).

%% Try PEM first; public_key:pem_decode/1 returns [] for non-PEM input so
%% calling it on a DER binary is safe.
-spec decode_crl(binary()) ->
          {ok, [{public_key:issuer_name(), #'CertificateList'{}, binary()}]} |
          {error, term()}.
decode_crl(Binary) ->
    case public_key:pem_decode(Binary) of
        [_ | _] = Entries ->
            HandleEntry =
                fun ({'CertificateList', Der, not_encrypted}) ->
                        case decode_der_crl(Der) of
                            {ok, Issuer, Decoded} ->
                                {true, {Issuer, Decoded, Der}};
                            {error, Reason} ->
                                throw({error, Reason})
                        end;
                    ({'CertificateList', _, _}) ->
                        throw({error, encrypted_crl});
                    ({EntryType, _, _}) ->
                        ?log_debug("Ignoring entry '~p' which doesn't "
                                   "seem to be a CRL entry", [EntryType]),
                        false
                end,
            try lists:filtermap(HandleEntry, Entries) of
                [] ->
                    {error, no_crl_entry_in_pem};
                Triples ->
                    {ok, Triples}
            catch
                throw:{error, R} -> {error, R}
            end;
        [] ->
            case decode_der_crl(Binary) of
                {ok, Issuer, Decoded} -> {ok, [{Issuer, Decoded, Binary}]};
                {error, _} = Err      -> Err
            end
    end.

%% Decode a single DER-encoded CRL and return its raw (non-normalized) issuer
%% together with the decoded record.
%% Issuer normalization is the responsibility of cb_crl_cache:insert_file/3.
-spec decode_der_crl(binary()) ->
          {ok, public_key:issuer_name(), #'CertificateList'{}} |
          {error, term()}.
decode_der_crl(Der) ->
    try public_key:der_decode('CertificateList', Der) of
        #'CertificateList'{
            tbsCertList = #'TBSCertList'{issuer = Issuer}} = Decoded ->
            {ok, Issuer, Decoded}
    catch
        _:Err -> {error, {invalid_crl, Err}}
    end.

%%%===================================================================
%%% CRL verification (RFC 5280 §6.3)
%%%===================================================================

decode_and_verify_crl(Binary, TrustedDerCAs) ->
    maybe
        {ok, Triples} ?= decode_crl(Binary),
        {ok, verify_crls(Triples, TrustedDerCAs)}
    else
        {error, Reason} ->
            {error, {decode_error, Reason}}
    end.

%% Verify every CRL triple against the cluster's trusted CAs and return one
%% entry_result() per entry.  No formatting is done here; callers extract
%% the raw fields they need (see attempt_load/6 and current_status/2).
-spec verify_crls(
        [{public_key:issuer_name(), #'CertificateList'{}, binary()}],
        [binary()]) -> [entry_result()].
verify_crls(CRLTriples, TrustedDerCAs) ->
    [begin
         Result = verify_crl(Decoded, TrustedDerCAs),
         case Result of
             {error, Reason} ->
                 ?log_warning("CRL entry verification failed"
                              " (issuer ~p): ~p", [RawIssuer, Reason]);
             ok -> ok
         end,
         {ThisUpdate, NextUpdate} = crl_times(Decoded),
         #entry_result{result      = Result,
                       issuer      = RawIssuer,
                       this_update = ThisUpdate,
                       next_update = NextUpdate,
                       der         = Der,
                       crl_number  = get_crl_number(Decoded)}
     end || {RawIssuer, Decoded, Der} <- CRLTriples].

%% Extract thisUpdate / nextUpdate from a decoded CRL as calendar:datetime()
%% values.  nextUpdate is optional per the ASN.1 spec and may be undefined.
-spec crl_times(#'CertificateList'{}) ->
          {ThisUpdate :: calendar:datetime() | undefined,
           NextUpdate :: calendar:datetime() | undefined}.
crl_times(#'CertificateList'{tbsCertList = TBS}) ->
    TimeToDatetime =
        fun (Raw) ->
                try
                    Secs = pubkey_cert:time_str_2_gregorian_sec(Raw),
                    calendar:gregorian_seconds_to_datetime(Secs)
                catch _:_ -> undefined
                end
        end,
    ThisUpdate = TimeToDatetime(TBS#'TBSCertList'.thisUpdate),
    NextUpdate = case TBS#'TBSCertList'.nextUpdate of
                     asn1_NOVALUE -> undefined;
                     Raw          -> TimeToDatetime(Raw)
                 end,
    {ThisUpdate, NextUpdate}.

%% Top-level CRL verifier: validity period first, then signature.
-spec verify_crl(#'CertificateList'{}, [binary()]) -> ok | {error, term()}.
verify_crl(CRL, TrustedDerCAs) ->
    case check_crl_validity(CRL) of
        ok  -> verify_crl_signature(CRL, TrustedDerCAs);
        Err -> Err
    end.

%% RFC 5280 §6.3.3 step (a): check thisUpdate ≤ now ≤ nextUpdate.
-spec check_crl_validity(#'CertificateList'{}) -> ok | {error, term()}.
check_crl_validity(Cert) ->
    {ThisUpdate, NextUpdate} = crl_times(Cert),
    Now = calendar:universal_time(),
    maybe
        ok ?= case ThisUpdate of
                  undefined -> ok;
                  _ ->
                      case ThisUpdate > Now of
                          true -> {error, crl_not_yet_valid};
                          false -> ok
                      end
              end,
        ok ?= case NextUpdate of
                  undefined -> ok; %% No expiry — treat as permanently valid
                  _ ->
                    case NextUpdate < Now of
                        true  -> {error, crl_expired};
                        false -> ok
                    end
              end
    end.

%% RFC 5280 §6.3.3 step (f): verify the CRL's signature against the cluster's
%% trusted CAs.
%%
%% Tries public_key:pkix_crl_verify/2 against every trusted CA cert.
%% Returns ok as soon as any cert verifies the signature successfully.
-spec verify_crl_signature(#'CertificateList'{}, [binary()]) ->
          ok | {error, term()}.
verify_crl_signature(CRL, TrustedDerCAs) ->
    case lists:any(
           fun (DerCA) ->
               try
                   public_key:pkix_crl_verify(CRL, DerCA)
               catch
                   C:E:ST ->
                       ?log_error("CRL verify exception ~p:~p~nStacktrace: ~p",
                                  [C, E, ST]),
                       false
               end
           end, TrustedDerCAs) of
        true  -> ok;
        false -> {error, crl_issuer_not_trusted}
    end.
