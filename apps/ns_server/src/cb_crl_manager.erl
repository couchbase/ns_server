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
         sync/0,
         reload/0,
         get_status/0,
         get_push_config/0,
         upload_crl_file/2,
         delete_crl_file/1,
         get_crl_files_metadata/0,
         sync_uploaded_files/0,
         read_uploaded_crl_file/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(CHRONICLE_KEY, crl_settings).
-define(CRL_FILES_KEY, crl_files).
-define(DEFAULT_POLL_INTERVAL_MS, 60000).
-define(DEFAULT_URL_POLL_INTERVAL_MS, 3600000).
-define(RELOAD_TIMEOUT, ?get_timeout(reload_timeout, 60000)).
-define(STATUS_TIMEOUT, ?get_timeout(status_timeout, 60000)).
-define(SYNC_TIMEOUT, ?get_timeout(sync_timeout, 60000)).
-define(GET_PUSH_CONFIG_TIMEOUT, ?get_timeout(get_push_config_timeout, 60000)).
-define(DOWNLOAD_TIMEOUT_MS, ?get_timeout(download_timeout_ms, 30000)).
-define(RECONCILE_RETRY_INTERVAL_MS, ?get_param(retry_interval_ms, 60000)).
-define(URL_FETCH_TIMEOUT_MS, ?get_timeout(url_fetch_timeout_ms, 30000)).
-define(URL_RETRY_INTERVAL_MS, ?get_param(url_retry_interval_ms, 60000)).

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
    mtime :: file:date_time() | undefined, %% mtime of the load-dir file at last
                                           %% attempt, when load from file
    etag :: binary() | undefined, %% etag from the most recent successull URL
                                  %% fetch
    result :: loaded | failed,
    time :: calendar:datetime(), %% when the last attempt happened
    errors :: [binary()] %% human-readable strings
}).

-type reload_status() :: #crl_reload_status{}.
-type file_state()    :: #{AbsolutePath :: string() => reload_status()}.

%% Map of CRL files keyed by base name; value is the SHA-256 hex digest.
%% Used for both loaded_locally (config/crls/local/) and uploaded (config/crls/).
-type active_files() :: #{BaseName :: string() => binary()}.

-record(state, {
    poll_directory   :: undefined | file:filename_all(),
    poll_interval_ms :: pos_integer(),
    poll_timer       :: reference() | undefined,
    %% Outcome of the most recent (re)load attempt per load-directory file.
    file_state       :: file_state(),
    %% Poll-based files held in config/crls/local/ (base name => checksum).
    loaded_locally   :: active_files(),
    %% Files placed in config/crls/ via the upload REST API.
    %% (base name => content checksum)
    uploaded         :: active_files(),
    %% Timer ref for retrying failed uploaded-file downloads.
    retry_timer      :: reference() | undefined,
    %% URL-based CRL files (config/crls/url/).
    %% Keys are the configured URLs; values are the per-URL fetch status
    %% (undefined = not yet attempted).
    url_file_state       :: #{binary() =>
                               reload_status() | undefined},
    %% URL-fetched files held in config/crls/url/ (base name => checksum).
    loaded_from_urls     :: active_files(),
    url_poll_interval_ms :: pos_integer(),
    url_poll_timer       :: reference() | undefined
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

%% Wait for any pending config changes to be fully applied.
%% Call this after set_config/1 to ensure subsequent requests see the new
%% settings.
-spec sync() -> ok.
sync() ->
    chronicle_compat_events:sync(),
    gen_server:call(?SERVER, sync, ?SYNC_TIMEOUT).

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
%% Returns StatusMap which has the same shape as get_status/0 (see below).
-spec reload() -> [map()].
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
-spec get_status() -> [map()].
get_status() ->
    gen_server:call(?SERVER, get_status, ?STATUS_TIMEOUT).

%% Return CRL config data for pushing to memcached and cbauth.
%%
%% Returns a map with:
%%   policy_per_scope => [{crl_scope(), crl_policy()}] — all scopes with their
%%                       policies
%%   files            => binary() — crls file paths to be used by services
%%   version          => integer() -> version of crl configuration
%%
%% This function is the single source of truth for CRL push config. Both
%% memcached_config_mgr and menelaus_cbauth call it.
-spec get_push_config() ->
    #{policy_per_scope => [{crl_scope(), crl_policy()}],
      files => [binary()],
      check_intermediate_certs => boolean(),
      version => integer()}.
get_push_config() ->
    gen_server:call(?SERVER, get_push_config, ?GET_PUSH_CONFIG_TIMEOUT).

%% Upload a CRL file to the cluster.  Validates the file, writes it to
%% config/crls on this node, updates ns_config and chronicle, then
%% synchronously requests other nodes to pull the new file.
-spec upload_crl_file(string(), binary()) -> ok | {error, term()}.
upload_crl_file(Filename, Binary) ->
    ?log_debug("CRL upload request: ~p (~b bytes)", [Filename, byte_size(Binary)]),
    case gen_server:call(?SERVER, {upload_crl_file, Filename, Binary},
                         60000) of
        ok ->
            ?log_debug("CRL upload done: ~p", [Filename]),
            sync_with_active_nodes();
        Error ->
            ?log_debug("CRL upload failed: ~p: ~p", [Filename, Error]),
            Error
    end.

%% Remove an uploaded CRL file from the whole cluster.
-spec delete_crl_file(string()) -> ok | {error, term()}.
delete_crl_file(Filename) ->
    ?log_debug("CRL delete request: ~p", [Filename]),
    case gen_server:call(?SERVER, {delete_crl_file, Filename}, 60000) of
        ok ->
            ?log_debug("CRL delete done: ~p", [Filename]),
            sync_with_active_nodes();
        Error ->
            ?log_debug("CRL delete failed: ~p: ~p", [Filename, Error]),
            Error
    end.

%% Return the current chronicle crl_files map (no gen_server round-trip).
%% Format: #{FilenameBin => #{checksum, upload_timestamp, entries => [...]}}
-spec get_crl_files_metadata() -> #{binary() => map()}.
get_crl_files_metadata() ->
    get_crl_files_metadata(local).

-spec get_crl_files_metadata(local | quorum) -> #{binary() => map()}.
get_crl_files_metadata(RC) ->
    chronicle_compat:get(?CRL_FILES_KEY, #{default => #{},
                                           read_consistency => RC}).

%% Called via RPC from the uploading node after it has written chronicle.
%% Syncs chronicle events and triggers reconciliation on this node.
-spec sync_uploaded_files() -> ok.
sync_uploaded_files() ->
    ns_config_rep:synchronize_local(),
    chronicle_compat_events:sync(),
    gen_server:call(?SERVER, sync_uploaded_files, 60000).

%% Called via RPC by nodes that need to download a CRL file from this node.
-spec read_uploaded_crl_file(string()) ->
    {ok, {compressed, binary()}} | {error, term()}.
read_uploaded_crl_file(Filename) ->
    FilePath = filename:join([crls_dir(), Filename]),
    case file:read_file(FilePath) of
        {ok, B} -> {ok, {compressed, zlib:compress(B)}};
        {error, _} = Error -> Error
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Self = self(),
    chronicle_compat_events:subscribe(
      fun (?CHRONICLE_KEY)   -> Self ! config_changed;
          (?CRL_FILES_KEY)   -> Self ! crl_files_changed;
          (_)                -> ok
      end),
    Cfg = get_config(),
    %% Crash on startup if we cannot create the directories we depend on.
    ok = ensure_dir(crls_dir()),
    ok = ensure_dir(local_crls_dir()),
    ok = ensure_dir(url_crls_dir()),
    %% Seed the cache from every storage directory so revocation checking
    %% is ready before any fetches happen.
    LoadedLocally0  = populate_cache_from_dir(local_crls_dir()),
    Uploaded0       = populate_cache_from_dir(crls_dir()),
    LoadedFromUrls0 = populate_cache_from_dir(url_crls_dir()),
    ChronicleFiles0 = get_crl_files_metadata(),
    State0 = #state{poll_directory       = undefined,
                    poll_interval_ms     = ?DEFAULT_POLL_INTERVAL_MS,
                    poll_timer           = undefined,
                    file_state           = #{},
                    url_file_state       = #{},
                    loaded_locally       = LoadedLocally0,
                    uploaded             = Uploaded0,
                    loaded_from_urls     = LoadedFromUrls0,
                    retry_timer          = undefined,
                    url_poll_interval_ms = ?DEFAULT_URL_POLL_INTERVAL_MS,
                    url_poll_timer       = undefined},
    %% apply_config handles poll_directory and policy changes.
    %% reconcile_url_files (called from apply_config) adds configured URLs,
    %% fetches them using conditional GET, and reads ETags lazily from the
    %% .etag sidecar files on first access.
    State1 = apply_config(Cfg, State0),
    %% Reconcile: remove local uploaded files no longer in chronicle
    %% (deleted while this node was down) and download any files that
    %% are in chronicle but missing or stale locally.
    State2 = reconcile_uploaded_files(ChronicleFiles0, State1),
    %% Remove cache entries not in any of the three active sets.
    ok = purge_stale_cache_entries(State2#state.loaded_locally,
                                   State2#state.uploaded,
                                   State2#state.loaded_from_urls),
    {ok, schedule_poll_dir_timer(schedule_url_timer(State2))}.

handle_call(reload, _From, #state{url_file_state = UrlsState} = State) ->
    Dir = State#state.poll_directory,
    ?log_debug("CRL manual reload start: dir=~p, urls=~b",
               [Dir, maps:size(State#state.url_file_state)]),
    ?flush(poll_directory),
    ?flush(poll_urls),
    State1 = scan_directory(Dir, State, true),
    State2 = reconcile_url_files(maps:keys(UrlsState), true, State1),
    maybe_notify_crl_consumers(State, State2),
    ?log_debug("CRL manual reload done: ~b locally, ~b from URLs",
               [maps:size(State2#state.loaded_locally),
                maps:size(State2#state.loaded_from_urls)]),
    {reply, build_status_map(State2),
     schedule_poll_dir_timer(schedule_url_timer(State2))};

handle_call(get_status, _From, State) ->
    {reply, build_status_map(State), State};

handle_call(sync, _From, State) ->
    {reply, ok, State};

handle_call(get_push_config, _From, State) ->
    Cfg = get_config(),
    PolicyPerScope = maps:to_list(maps:get(policy_per_scope, Cfg)),
    CheckInterm = maps:get(check_intermediate_certs, Cfg, false),
    FileVersions = build_file_versions(State),
    Files = [F || {F, _} <- FileVersions],
    Version = erlang:phash2({PolicyPerScope, lists:sort(FileVersions),
                             CheckInterm}),
    Result = #{policy_per_scope => PolicyPerScope,
               files => Files,
               version => Version,
               check_intermediate_certs => CheckInterm},
    {reply, Result, State};

handle_call({upload_crl_file, Filename, Binary}, _From, State) ->
    case do_upload_crl_file(Filename, Binary, State) of
        {ok, NewState} ->
            notify_crl_consumers(),
            {reply, ok, NewState};
        {error, _} = Err ->
            {reply, Err, State}
    end;

handle_call({delete_crl_file, Filename}, _From, State) ->
    case do_delete_crl_file(Filename, State) of
        {ok, NewState} ->
            notify_crl_consumers(),
            {reply, ok, NewState};
        {error, _} = Err ->
            {reply, Err, State}
    end;

handle_call(sync_uploaded_files, _From, State) ->
    ChronicleFiles = get_crl_files_metadata(quorum),
    NewState = reconcile_uploaded_files(ChronicleFiles, State),
    maybe_notify_crl_consumers(State, NewState),
    {reply, ok, NewState};

handle_call(Req, _From, State) ->
    ?log_error("Received unknown call: ~p", [Req]),
    {reply, {error, unknown_request}, State}.

handle_cast(Msg, State) ->
    ?log_error("Received unknown cast: ~p", [Msg]),
    {noreply, State}.

handle_info(config_changed, State) ->
    Cfg = get_config(),
    State1 = apply_config(Cfg, State),
    notify_crl_consumers(),
    {noreply, schedule_poll_dir_timer(schedule_url_timer(State1))};

handle_info(crl_files_changed, State) ->
    ChronicleFiles = get_crl_files_metadata(),
    NewState = reconcile_uploaded_files(ChronicleFiles, State),
    maybe_notify_crl_consumers(State, NewState),
    {noreply, NewState};

handle_info(retry_reconcile, State) ->
    ?log_debug("CRL uploaded-file reconcile retry", []),
    ?flush(retry_reconcile),
    ChronicleFiles = get_crl_files_metadata(),
    NewState = reconcile_uploaded_files(ChronicleFiles, State),
    maybe_notify_crl_consumers(State, NewState),
    {noreply, NewState};

handle_info(poll_directory, #state{poll_directory = Dir} = State) ->
    ?flush(poll_directory),
    State1 = scan_directory(Dir, State, false),
    %% Only the set of active (good) files matters to consumers; reload-attempt
    %% bookkeeping changing on its own does not warrant a push.
    maybe_notify_crl_consumers(State, State1),
    {noreply, schedule_poll_dir_timer(State1)};

handle_info(poll_urls, #state{url_file_state = URLsState} = State) ->
    ?flush(poll_urls),
    State1 = reconcile_url_files(maps:keys(URLsState), false, State),
    maybe_notify_crl_consumers(State, State1),
    {noreply, schedule_url_timer(State1)};

handle_info(Msg, State) ->
    ?log_error("Received unknown info: ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_, State, _) -> {ok, State}.

%%%===================================================================
%%% Internal helpers — uploaded file management
%%%===================================================================

%% Reconcile local config/crls against the chronicle crl_files list.
%%   - Files in chronicle but missing / stale locally → download.
%%   - Files tracked as uploaded locally but absent from chronicle → remove.
%%
%% Schedules (or cancels) the retry timer internally based on whether
%% any downloads failed.
-spec reconcile_uploaded_files(#{binary() => map()}, #state{}) -> #state{}.
reconcile_uploaded_files(ChronicleFiles, State) ->
    %% Build string-keyed map filename -> expected checksum from chronicle.
    WantedMap = maps:fold(
                  fun (NameBin, #{checksum := C}, Acc) ->
                        maps:put(binary_to_list(NameBin), C, Acc)
                  end, #{}, ChronicleFiles),
    ?log_debug("CRL reconcile: ~b file(s) in chronicle, ~b held locally",
               [maps:size(WantedMap),
                maps:size(State#state.uploaded)]),
    %% Step 1: ensure every wanted file is present with correct checksum.
    %% Use the in-memory uploaded map as the source of truth for what
    %% this node already has — no disk read needed when it matches.
    OldUploaded = State#state.uploaded,
    {NewUploaded, HasPending} =
        maps:fold(
          fun (Name, Checksum, {Acc, Pending}) ->
              case maybe_update_uploaded_file(Name, Checksum, OldUploaded) of
                  ok  -> {maps:put(Name, Checksum, Acc), Pending};
                  {error, _} -> {Acc, true}
              end
          end, {#{}, false}, WantedMap),
    %% Step 2: remove files that are no longer in chronicle.
    maps:foreach(
      fun (Name, _) ->
              case maps:is_key(Name, WantedMap) of
                  true  -> ok;
                  false ->
                      ?log_info(
                         "Removing uploaded CRL file no longer in "
                         "chronicle: ~p", [Name]),
                      remove_uploaded_file_locally(Name)
              end
      end, OldUploaded),
    ?log_debug("CRL reconcile done: ~b file(s) held, pending=~p",
               [maps:size(NewUploaded), HasPending]),
    NewState = State#state{uploaded = NewUploaded},
    case HasPending of
        true  -> schedule_reconcile_retry(NewState);
        false -> cancel_reconcile_retry(NewState)
    end.

%% Check whether an uploaded file is already present with the expected checksum,
%% and if not, download it from another node and install it locally.
maybe_update_uploaded_file(Name, ExpectedChecksum, CurrentlyLoadedMap) ->
    case maps:get(Name, CurrentlyLoadedMap, undefined) of
        ExpectedChecksum ->
            ok;
        _ ->
            maybe
                {ok, Binary} ?= download_missing_file(Name, ExpectedChecksum),
                %% No need to re-verify the CRL as it was already verified by
                %% another node
                {ok, Entries} ?= decode_to_entries(Binary),
                ok ?= write_uploaded_file_locally(Name, Binary, Entries),
                ?log_debug("CRL ~p: installed from remote node", [Name]),
                ok
            else
                {error, not_found_on_any_node} ->
                    %% Not logging error because it may happen during normal
                    %% operation
                    {error, not_found_on_any_node};
                {error, Reason} ->
                    ?log_error("Failed to update CRL ~p: ~p", [Name, Reason]),
                    {error, Reason}
            end
    end.

%% Download a CRL file from another active cluster node.
%% Syncs ns_config first, then iterates a shuffled list of active
%% (currently reachable) nodes looking for one that has the file with
%% the expected checksum.
-spec download_missing_file(string(), binary()) ->
          {ok, binary()} | {error, term()}.
download_missing_file(Filename, ExpectedChecksum) ->
    ns_config:sync(),
    FilenameBin = list_to_binary(Filename),
    Nodes = misc:shuffle(ns_node_disco:nodes_actual_other()),
    ?log_debug("CRL ~p: downloading, ~b candidate node(s)",
               [Filename, length(Nodes)]),
    download_from_nodes(Nodes, FilenameBin, ExpectedChecksum).

-spec download_from_nodes([node()], binary(), binary()) ->
          {ok, binary()} | {error, term()}.
download_from_nodes([], FilenameBin, _Checksum) ->
    ?log_debug("CRL ~p: no node has the file yet", [FilenameBin]),
    {error, not_found_on_any_node};
download_from_nodes([Node | Rest], FilenameBin, ExpectedChecksum) ->
    NodeFiles = ns_config:read_key_fast(
                  {node, Node, crl_files}, []),
    case lists:keyfind(FilenameBin, 1, NodeFiles) of
        {FilenameBin, ExpectedChecksum} ->
            Filename = binary_to_list(FilenameBin),
            ?log_debug("CRL ~p: trying node ~p", [Filename, Node]),
            maybe
                {ok, MaybeCompressed} ?=
                    rpc:call(Node, cb_crl_manager, read_uploaded_crl_file,
                             [Filename], ?DOWNLOAD_TIMEOUT_MS),
                {ok, Binary} ?=
                    case MaybeCompressed of
                        {compressed, B} ->
                            try zlib:uncompress(B) of
                                UB -> {ok, UB}
                            catch
                                _:E -> {error, {uncompress_error, E}}
                            end;
                        %% Support uncompressed just in case future
                        %% versions decide to stop compressing files
                        {uncompressed, B} -> {ok, B};
                        _ -> {error, unexpected_response}
                    end,
                case file_checksum(Binary) of
                    ExpectedChecksum ->
                        ?log_debug("CRL ~p: downloaded from ~p (~b bytes)",
                                   [Filename, Node, byte_size(Binary)]),
                        {ok, Binary};
                    Got ->
                        ?log_warning("CRL ~p downloaded from ~p: checksum "
                                     "mismatch (got ~p expected ~p)",
                                    [Filename, Node, Got, ExpectedChecksum]),
                        download_from_nodes(
                            Rest, FilenameBin, ExpectedChecksum)
                end
            else
                {badrpc, Reason} ->
                    ?log_warning("CRL ~p: RPC to ~p failed: ~p",
                                 [Filename, Node, Reason]),
                    download_from_nodes(Rest, FilenameBin, ExpectedChecksum);
                {error, Err} ->
                    ?log_warning("CRL ~p: read from ~p failed: ~p",
                                 [Filename, Node, Err]),
                    download_from_nodes(Rest, FilenameBin, ExpectedChecksum)
            end;
        _ ->
            ?log_debug("CRL ~p: node ~p does not have the file",
                       [FilenameBin, Node]),
            download_from_nodes(Rest, FilenameBin, ExpectedChecksum)
    end.

%% Execute the upload logic inside the gen_server.
-spec do_upload_crl_file(string(), binary(), #state{}) ->
          {ok, #state{}} | {error, term()}.
do_upload_crl_file(Filename, Binary, State) ->
    TrustedCAs = ns_server_cert:trusted_CAs(der),
    TS = calendar:universal_time(),
    AllowExpired = ?get_param(allow_expired_crls, false),
    case decode_and_verify_crl(Binary, TrustedCAs, AllowExpired) of
        {error, Reason} ->
            ?log_debug("CRL ~p: decode failed: ~p", [Filename, Reason]),
            {error, Reason};
        {ok, Results} ->
            ?log_debug("CRL ~p: decoded ~b entries",
                       [Filename, length(Results)]),
            Bad = [R || #entry_result{result = Res} = R <- Results, Res =/= ok],
            case Bad of
                [_ | _] ->
                    ?log_debug("CRL ~p: ~b invalid entr(y/ies)",
                               [Filename, length(Bad)]),
                    {error, {invalid_entries,
                             [entry_error_text(R) || R <- Bad]}};
                [] ->
                    ?log_debug("CRL ~p: ~b entr(y/ies) valid, uploading",
                               [Filename, length(Results)]),
                    add_uploaded_file(Filename, Binary, TS, Results, State)
            end
    end.

%% Perform the disk write, ns_config update, and chronicle transaction
%% for a validated upload.
-spec add_uploaded_file(string(), binary(), calendar:datetime(),
                        [entry_result()], #state{}) ->
          {ok, #state{}} | {error, term()}.
add_uploaded_file(Filename, Binary, TS, EntryResults, State) ->
    Checksum = file_checksum(Binary),
    FilenameBin = list_to_binary(Filename),
    EntryMetas = [#{issuer => iolist_to_binary(ns_server_cert:format_name(
                                                 R#entry_result.issuer)),
                    this_update => R#entry_result.this_update,
                    next_update => R#entry_result.next_update,
                    crl_number  => R#entry_result.crl_number}
                  || R <- EntryResults],
    FileInfo = #{checksum => Checksum,
                 upload_timestamp => TS,
                 entries => EntryMetas},
    %% We can't write files to disk until after the chronicle transaction
    %% succeeds, because if the transaction fails, we won't be able to recover
    %% the file that we (maybe) overwrote.
    {ok, _} = chronicle_kv:txn(
                kv,
                fun (Txn) ->
                    CurrMap = case chronicle_kv:txn_get(?CRL_FILES_KEY, Txn) of
                                  {ok, {M, _}}       -> M;
                                  {error, not_found} -> #{}
                              end,
                    {commit, [{set, ?CRL_FILES_KEY,
                               maps:put(FilenameBin, FileInfo, CurrMap)}]}
                end),
    case write_uploaded_file_locally(Filename, Binary, EntryResults) of
        ok ->
            ?log_debug("CRL ~p: uploaded and written locally", [Filename]),
            NewUploaded = maps:put(Filename, Checksum, State#state.uploaded),
            {ok, State#state{uploaded = NewUploaded}};
        {error, Reason} ->
            ?log_error("CRL ~p: uploaded but failed to write locally: ~p",
                       [Filename, Reason]),
            %% We could write the file to disk, we have to remove it from
            %% chronicle now because we don't have that file saved anywhere
            catch do_delete_crl_file(Filename, State),
            {error, Reason}
    end.

%% Puts the file on disk and updates the metadata in ns_config, so that other
%% nodes can find and download it.
write_uploaded_file_locally(Filename, Binary, VerifiedEntries) ->
    maybe
        {ok, Checksum} ?= add_to_cache(upload, Filename, Binary,
                                       VerifiedEntries),
        %% Update ns_config node advertisement key.
        OldNodeFiles = ns_config:read_key_fast({node, node(), crl_files}, []),
        FilenameBin = list_to_binary(Filename),
        NewNodeFiles = lists:keystore(FilenameBin, 1, OldNodeFiles,
                                      {FilenameBin, Checksum}),
        ns_config:set({node, node(), crl_files}, NewNodeFiles),
        ok
    end.

remove_uploaded_file_locally(Filename) when is_list(Filename) ->
    FilenameBin = list_to_binary(Filename),
    %% Remove from ns_config node advertisement key.
    OldNodeFiles = ns_config:read_key_fast({node, node(), crl_files}, []),
    NewNodeFiles = lists:keydelete(FilenameBin, 1, OldNodeFiles),
    ns_config:set({node, node(), crl_files}, NewNodeFiles),
    %% Remove local file and cache entry.
    remove_from_cache(upload, Filename).

%% Execute the delete logic inside the gen_server.
-spec do_delete_crl_file(string(), #state{}) ->
          {ok, #state{}} | {error, term()}.
do_delete_crl_file(Filename, State) ->
    FilenameBin = list_to_binary(Filename),
    case maps:is_key(FilenameBin, get_crl_files_metadata()) of
        false ->
            ?log_debug("CRL delete ~p: not found in chronicle",
                       [Filename]),
            {error, not_found};
        true ->
            ?log_debug("CRL delete ~p: removing from chronicle, "
                       "ns_config, and disk", [Filename]),
            %% Remove from chronicle.
            {ok, _} = chronicle_kv:txn(
                        kv,
                        fun (Txn) ->
                            CurrMap = case chronicle_kv:txn_get(
                                             ?CRL_FILES_KEY, Txn) of
                                          {ok, {M, _}}       -> M;
                                          {error, not_found} -> #{}
                                      end,
                            {commit, [{set, ?CRL_FILES_KEY,
                                       maps:remove(FilenameBin, CurrMap)}]}
                        end),
            NewUploaded = %% Don't remove the file from "uploaded" list
                          %% if we could not delete it from disk
                          %% This way we will retry deleting it later
                case remove_uploaded_file_locally(Filename) of
                    ok -> maps:remove(Filename, State#state.uploaded);
                    {error, _} -> State#state.uploaded
                end,
            {ok, State#state{uploaded = NewUploaded}}
    end.

%% Request sync_uploaded_files/0 on every currently active node.
%% Errors are logged but do not fail the calling operation — the
%% chronicle subscription on each remote node will reconcile eventually.
-spec sync_with_active_nodes() -> ok.
sync_with_active_nodes() ->
    ns_config_rep:ensure_config_pushed(),
    Nodes = ns_node_disco:nodes_actual_other(),
    ?log_debug("CRL sync: notifying ~b active node(s)", [length(Nodes)]),
    Timeout = 30000,
    misc:parallel_map(
      fun (N) ->
              case rpc:call(N, cb_crl_manager,
                            sync_uploaded_files, [], Timeout) of
                  ok ->
                      ?log_debug("CRL sync: node ~p done", [N]);
                  Err ->
                      ?log_warning(
                         "CRL file sync to node ~p failed: ~p",
                         [N, Err])
              end
      end, Nodes, Timeout + 1000),
    ok.

-spec schedule_reconcile_retry(#state{}) -> #state{}.
schedule_reconcile_retry(State) ->
    State1 = cancel_reconcile_retry(State),
    Ref = erlang:send_after(?RECONCILE_RETRY_INTERVAL_MS, self(),
                            retry_reconcile),
    State1#state{retry_timer = Ref}.

-spec cancel_reconcile_retry(#state{}) -> #state{}.
cancel_reconcile_retry(#state{retry_timer = undefined} = State) ->
    State;
cancel_reconcile_retry(#state{retry_timer = Ref} = State) ->
    catch erlang:cancel_timer(Ref),
    State#state{retry_timer = undefined}.

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

maybe_notify_crl_consumers(StateBefore, StateCurrent) ->
    %% Only call notify_crl_consumers when the set of CRL files changes
    %% It doesn't check if policies have changed !!!
    case (StateBefore#state.loaded_locally =:=
              StateCurrent#state.loaded_locally) andalso
         (StateBefore#state.uploaded =:=
              StateCurrent#state.uploaded) andalso
         (StateBefore#state.loaded_from_urls =:=
              StateCurrent#state.loaded_from_urls) of
        true  -> ok;
        false -> notify_crl_consumers()
    end.

%% Notify memcached and cbauth that CRL data has changed.
%% Called after config changes, manual reload, and poll when files changed.
-spec notify_crl_consumers() -> ok.
notify_crl_consumers() ->
    memcached_config_mgr:trigger_tls_config_push(),
    menelaus_cbauth:notify_crl_change(),
    ok.

-spec default_config() -> map().
default_config() ->
    #{poll_directory => default_local_crl_source_dir(),
      policy_per_scope =>
          #{client_auth => disabled,
            node_to_node => disabled},
      delta_crls => false,
      poll_interval_ms => ?DEFAULT_POLL_INTERVAL_MS,
      check_intermediate_certs => false,
      crl_urls => [],
      url_poll_interval_ms => ?DEFAULT_URL_POLL_INTERVAL_MS}.

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
apply_config(Cfg, #state{poll_directory = OldPollDir,
                         url_file_state = OldUrlsState} = State) ->
    NewPollDir     = maps:get(poll_directory, Cfg),
    NewInterval    = maps:get(poll_interval_ms, Cfg),
    NewPolicies    = maps:get(policy_per_scope, Cfg),
    CheckInterm    = maps:get(check_intermediate_certs, Cfg, false),
    NewUrls        = maps:get(crl_urls, Cfg, []),
    NewUrlInterval = maps:get(url_poll_interval_ms, Cfg),
    State1 = State#state{poll_directory       = NewPollDir,
                         poll_interval_ms     = NewInterval,
                         url_poll_interval_ms = NewUrlInterval},

    %% Phase 1: disable scopes whose new policy is 'disabled'.
    %% Also disable intermediate-cert checking here when the new value is
    %% false, so no check runs against a partially-updated cache.
    maps:foreach(
      fun (Scope, disabled) ->
              cb_crl_cache:set_policy(Scope, disabled);
          (_Scope, _Policy) ->
              ok
      end, NewPolicies),
    case CheckInterm of
        false -> cb_crl_cache:set_check_intermediate_certs(false);
        true  -> ok
    end,

    %% Phase 2a: update poll-directory CRL data.
    State2 =
        case {OldPollDir, NewPollDir} of
            {Same, Same} ->
                %% Poll dir unchanged; cache already up-to-date.
                State1;
            {_, undefined} ->
                ?log_info(
                   "CRL source cleared; removing ~p poll-based CRL file(s)",
                   [maps:size(State1#state.loaded_locally)]),
                %% Only remove poll-based files in local_crls_dir();
                %% uploaded files in crls_dir() are unaffected.
                maps:foreach(
                  fun (Name, _) ->
                          remove_from_cache(local, Name)
                  end, State1#state.loaded_locally),
                State1#state{file_state = #{}, loaded_locally = #{}};
            {_, Dir} ->
                ?log_info("CRL poll directory set to ~p", [Dir]),
                scan_directory(Dir, State1, false)
        end,

    %% Phase 2b: update URL-based CRL data.
    %% reconcile_url_files removes stale URLs from cache and disk, adds
    %% newly configured ones, then fetches all using conditional GET
    %% (ETag-based, so unchanged CRLs are not re-downloaded).
    State3 = case lists:sort(NewUrls) /= lists:sort(maps:keys(OldUrlsState)) of
                 %% Something has changed:
                 true -> reconcile_url_files(NewUrls, false, State2);
                 %% Nothing changed:
                 false -> State2
             end,

    %% Phase 3: enable / update scopes whose new policy is not 'disabled'.
    %% CRL data is now in the cache, so the verify_fun will find what it
    %% needs as soon as it reads the new policy from ETS.
    %% Also enable intermediate-cert checking here, after CRL data is ready.
    maps:foreach(
      fun (_Scope, disabled) ->
              %% Already written in Phase 1; skip.
              ok;
          (Scope, Policy) ->
              cb_crl_cache:set_policy(Scope, Policy)
      end, NewPolicies),
    case CheckInterm of
        true  -> cb_crl_cache:set_check_intermediate_certs(true);
        false -> ok
    end,

    State3.

%% Schedule the next poll and return the updated state.
%% No timer is created when there is nothing to poll.
-spec schedule_poll_dir_timer(#state{}) -> #state{}.
schedule_poll_dir_timer(#state{poll_directory = undefined} = State) ->
    cancel_timer(State#state.poll_timer),
    State#state{poll_timer = undefined};
schedule_poll_dir_timer(#state{poll_interval_ms = Ms} = State) ->
    cancel_timer(State#state.poll_timer),
    Ref = erlang:send_after(Ms, self(), poll_directory),
    State#state{poll_timer = Ref}.

-spec cancel_timer(reference() | undefined) -> ok.
cancel_timer(undefined) -> ok;
cancel_timer(Ref) ->
    erlang:cancel_timer(Ref),
    ok.

%% Schedule (or cancel) the URL poll timer.
-spec schedule_url_timer(#state{}) -> #state{}.
schedule_url_timer(#state{url_file_state = UrlFS} = State)
        when map_size(UrlFS) =:= 0 ->
    cancel_timer(State#state.url_poll_timer),
    State#state{url_poll_timer = undefined};
schedule_url_timer(#state{url_poll_interval_ms = Ms,
                          url_file_state = UrlFS} = State) ->
    cancel_timer(State#state.url_poll_timer),
    AnyFailed =
        maps:fold(
          fun (_, #crl_reload_status{result = failed}, _) -> true;
              (_, _, Acc) -> Acc
          end, false, UrlFS),
    Interval = case AnyFailed of
                   true -> min(?URL_RETRY_INTERVAL_MS, Ms);
                   false -> Ms
               end,
    Ref = erlang:send_after(Interval, self(), poll_urls),
    State#state{url_poll_timer = Ref}.

%% Reconcile URL-based CRL files against URLList (from configuration).
%%
%%   Removed URLs — cache entry and disk files (CRL + .etag sidecar) are
%%                  deleted; the URL is removed from url_file_state.
%%   All URLs     — fetched using conditional GET; the stored ETag is sent
%%                  as If-None-Match so unchanged CRLs produce a 304 and
%%                  require no re-download.
-spec reconcile_url_files([binary()], boolean(), #state{}) -> #state{}.
reconcile_url_files(NewURLList, Force, State) ->
    NewUrlSet = sets:from_list(NewURLList),
    %% Remove files for URLs no longer in the configuration.
    ExpectedFilenamesSet = sets:from_list([url_filename(E) || E <- NewURLList]),
    NewLoaded = maps:filter(
                  fun (Filename, _Checksum) ->
                      case sets:is_element(Filename, ExpectedFilenamesSet) of
                          true -> true;
                          false ->
                              CrlPath = filename:join(url_crls_dir(), Filename),
                              case write_etag(CrlPath, undefined) of
                                  ok -> ok /= remove_from_cache(url, Filename);
                                  {error, _} -> true
                              end
                      end
                  end, State#state.loaded_from_urls),
    NewUrlFS = maps:filter(
                 fun (URL, _Status) -> sets:is_element(URL, NewUrlSet) end,
                 State#state.url_file_state),
    %% Download all URLs; ETags prevent redundant transfers.
    fetch_all_urls(NewURLList, Force,
                   State#state{loaded_from_urls = NewLoaded,
                               url_file_state = NewUrlFS}).

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
-spec scan_directory(file:filename_all() | undefined, #state{},
                     ForceReload :: boolean()) ->
          #state{}.
scan_directory(undefined, State, _ForceReload) ->
    State;
scan_directory(DirBin, State, ForceReload) when is_binary(DirBin) ->
    scan_directory(binary_to_list(DirBin), State, ForceReload);
scan_directory(Dir, State, ForceReload) ->
    maybe
        TrustedCAs = ns_server_cert:trusted_CAs(der),
        TS = calendar:universal_time(),
        {ok, DiskNames} ?=
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
        %% directory. loaded_locally (base names): vanished file's local copy
        %% and cache entry are removed.  file_state (full paths): stale records
        %% are dropped.
        DiskNameSet = sets:from_list(DiskNames),
        DiskPaths = [filename:join(Dir, N) || N <- DiskNames],
        DiskPathSet = sets:from_list(DiskPaths),
        Loaded2 =
            maps:filter(
            fun (Name, _Checksum) ->
                    case sets:is_element(Name, DiskNameSet) of
                        true  -> true;
                        false -> ok /= remove_from_cache(local, Name)
                    end
            end, UpdatedState#state.loaded_locally),
        FS2 = maps:filter(fun (Path, _Status) ->
                                sets:is_element(Path, DiskPathSet)
                        end, UpdatedState#state.file_state),
        UpdatedState#state{file_state = FS2, loaded_locally = Loaded2}
    else
        {error, {list_dir_error, Reason}} ->
            ?log_error("Failed to list CRL directory ~p: ~p", [Dir, Reason]),
            State
    end.

%% Attempt to load a single file from the load directory if it has changed
maybe_load_from_local_file(Name, FilePath, ForceReload, TS, TrustedCAs,
                           #state{file_state = FS} = State) ->
    MTime = filelib:last_modified(FilePath),
    Now = calendar:local_time(), %% because last_modified returns local time
    case MTime == Now of %% same second
        true ->
            %% The file has changed less then a second ago, and since mtime is
            %% in seconds we should wait 1 second to make sure we load the most
            %% recent file.
            %% Possible race:
            %%   1. File is written at time 0 (mtime=0)
            %%   2. We read the mtime
            %%   3. We read the file
            %%   3. In parallel the file changes again at time 0
            %%      (mtime is still 0)
            %%   4. Poll timer fires at time 10 and we start scanning
            %%   5. We ignore new file because mtime in memory matches
            %%      the file's mtime
            timer:sleep(1000);
        false ->
            ok
    end,
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
                     #state{file_state = FS,
                            loaded_locally = Loaded} = State) ->
    ?log_debug("CRL scan: loading file ~p", [Path]),
    maybe
        {ok, Binary} ?= case file:read_file(Path) of
                            {ok, Bin} -> {ok, Bin};
                            {error, Err} -> {error, {read_error, Err}}
                        end,
        AllowExpired = ?get_param(allow_expired_crls, false),
        {ok, Results} ?= decode_and_verify_crl(Binary, TrustedCAs,
                                               AllowExpired),
        Bad = [R || R <- Results, R#entry_result.result =/= ok],
        ok ?= case Bad of
                    [] -> ok;
                    _  -> {error, {bad_crl_entries, Bad}}
                end,
        {ok, Checksum} ?= add_to_cache(local, Name, Binary, Results),
        Status = #crl_reload_status{mtime  = FileMTime,
                                    result = loaded,
                                    time   = CurTS,
                                    errors = []},
        State#state{file_state = maps:put(Path, Status, FS),
                    loaded_locally = maps:put(Name, Checksum, Loaded)}
    else
        {error, Reason} ->
            ErrorStrings = format_load_errors(Reason),
            ?log_warning("Failed to load CRLs from ~s:~n~s",
                         [Path, lists:join(<<"\n">>, ErrorStrings)]),
            BadStatus = #crl_reload_status{mtime  = FileMTime,
                                           result = failed,
                                           time   = CurTS,
                                           errors = ErrorStrings},
            State#state{file_state = maps:put(Path, BadStatus, FS)}
    end.

%% Copy a fully-valid file verbatim into config/crls and insert its entries
%% into the cache.
-spec add_to_cache(local | upload | url, file:filename_all(), binary(),
                   [entry_result()]) ->
          {ok, binary()} | {error, term()}.
add_to_cache(CacheType, Name, Binary, VerifiedEntries) ->
    Dir = case CacheType of
              local  -> local_crls_dir();
              upload -> crls_dir();
              url    -> url_crls_dir()
          end,
    FilePath = filename:join(Dir, Name),
    ?log_debug("Adding CRL file ~p to cache", [FilePath]),
    maybe
        ok ?= misc:atomic_write_file(FilePath, Binary),
        Pairs = [{I, D}
                 || #entry_result{issuer = I, der = D} <- VerifiedEntries],
        cb_crl_cache:insert_file(FilePath, Pairs),
        {ok, file_checksum(Binary)}
    else
        {error, Err} ->
            ?log_error("Failed to add CRL file ~p to cache: ~p",
                       [FilePath, Err]),
            {error, Err}
    end.

%% Remove a CRL copy and its cache entry.
%% For URL-fetched files the ETag sidecar is also removed.
-spec remove_from_cache(local | upload | url, file:filename_all()) ->
          ok | {error, term()}.
remove_from_cache(CacheType, Name) ->
    Dir = case CacheType of
              local  -> local_crls_dir();
              upload -> crls_dir();
              url    -> url_crls_dir()
          end,
    FullPath = filename:join(Dir, Name),
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
format_load_errors({http_status, Code, undefined}) ->
    [misc:format_bin("HTTP ~p (missing body)", [Code])];
format_load_errors({http_status, Code, Body}) when is_binary(Body) ->
    [misc:format_bin("HTTP ~p ~s", [Code, misc:bin_part_near(Body, 0, 30)])];
format_load_errors({http_failed, Reason}) ->
    [misc:format_bin("HTTP Request failed: ~p", [Reason])];
format_load_errors({etag_save, Reason}) ->
    [misc:format_bin("Failed to save etag file: ~p", [Reason])];
format_load_errors({invalid_crl, _}) ->
    [<<"Invalid CRL">>];
format_load_errors(Other) ->
    [misc:format_bin("Unexpected error. Reason: ~p", [Other])].

%% Remove cache entries no longer in loaded_locally (config/crls/local/),
%% uploaded (config/crls/), or loaded_from_urls (config/crls/url/).
%% Cleans up stale entries left by a previous gen_server instance after
%% a crash during file deletion.
-spec purge_stale_cache_entries(active_files(), active_files(),
                                active_files()) -> ok.
purge_stale_cache_entries(LoadedLocally, Uploaded, LoadedFromUrls) ->
    LocalCrlsDir    = local_crls_dir(),
    UploadedCrlsDir = crls_dir(),
    UrlCrlsDir      = url_crls_dir(),
    ExpectedPaths =
        sets:from_list(
          [misc:normalize_path(filename:join(LocalCrlsDir, N))
           || N <- maps:keys(LoadedLocally)] ++
          [misc:normalize_path(filename:join(UploadedCrlsDir, N))
           || N <- maps:keys(Uploaded)] ++
          [misc:normalize_path(filename:join(UrlCrlsDir, N))
           || N <- maps:keys(LoadedFromUrls)]),
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

%% config/crls/ — storage for REST-uploaded CRL files.
-spec crls_dir() -> file:filename_all().
crls_dir() ->
    filename:join(path_config:component_path(data, "config"), "crls").

%% config/crls/local/ — storage for poll-directory-scanned CRL files.
%% Keeping the two sources in separate subdirectories makes the origin
%% of every file unambiguous on startup.
-spec local_crls_dir() -> file:filename_all().
local_crls_dir() ->
    filename:join(crls_dir(), "local").

%% config/crls/url/ — storage for URL-fetched CRL files.
%% Each file is named by the SHA-256 hex digest of its source URL, making
%% the mapping deterministic and filesystem-safe.
-spec url_crls_dir() -> file:filename_all().
url_crls_dir() ->
    filename:join(crls_dir(), "url").

%% misc:mkdir_p/1 returns ok when the directory already exists, so any error
%% here is genuine.  We return it so init/1 crashes the gen_server.
-spec ensure_dir(file:filename_all()) -> ok | {error, term()}.
ensure_dir(Dir) ->
    case misc:mkdir_p(Dir) of
        ok -> ok;
        {error, Reason} ->
            ?log_error("Failed to create CRL directory ~p: ~p", [Dir, Reason]),
            {error, Reason}
    end.

%% Decode every CRL file in Dir, insert into the cache, and return a
%% base-name => checksum map.  Files that fail to read or decode are
%% skipped (and left on disk for diagnosis).  Dot-files are ignored.
-spec populate_cache_from_dir(file:filename_all()) -> active_files().
populate_cache_from_dir(Dir) ->
    Names = case file:list_dir(Dir) of
                {ok, Ns} ->
                    [N || N <- Ns, N =/= [], hd(N) =/= $.,
                          filename:extension(N) =/= ".etag"];
                {error, _} -> []
            end,
    lists:foldl(
      fun (Name, Acc) ->
              Path = filename:join(Dir, Name),
              case file:read_file(Path) of
                  {ok, Binary} ->
                      case decode_to_entries(Binary) of
                          {ok, Entries} ->
                              Pairs = [{I, D}
                                       || #entry_result{issuer = I,
                                                        der = D} <- Entries],
                              cb_crl_cache:insert_file(Path, Pairs),
                              ?log_debug("CRL seeded from ~p", [Path]),
                              maps:put(Name, file_checksum(Binary), Acc);
                          {error, Reason} ->
                              ?log_error("Skipping undecodable CRL ~p: ~p",
                                         [Path, Reason]),
                              Acc
                      end;
                  {error, eisdir} ->
                      %% Ignore directories
                      Acc;
                  {error, Reason} ->
                      ?log_error("Failed to read CRL ~p: ~p",
                                 [Path, Reason]),
                      Acc
              end
      end, #{}, Names).

default_local_crl_source_dir() ->
    filename:join(path_config:component_path(data, "inbox"), "crls").

%%%===================================================================
%%% Push config helpers (used by get_push_config/0)
%%%===================================================================

%% Build the file-version list for the push config.
%% Returns [{PathBin, ChecksumBin}] for all currently-held CRL files.
-spec build_file_versions(#state{}) -> [{binary(), binary()}].
build_file_versions(#state{loaded_locally   = LoadedLocally,
                           uploaded         = Uploaded,
                           loaded_from_urls = LoadedFromUrls}) ->
    LocalDir  = local_crls_dir(),
    UploadDir = crls_dir(),
    UrlDir    = url_crls_dir(),
    [{iolist_to_binary(filename:join(LocalDir, N)), Cs}
     || {N, Cs} <- maps:to_list(LoadedLocally)] ++
    [{iolist_to_binary(filename:join(UploadDir, N)), Cs}
     || {N, Cs} <- maps:to_list(Uploaded)] ++
    [{iolist_to_binary(filename:join(UrlDir, N)), Cs}
     || {N, Cs} <- maps:to_list(LoadedFromUrls)].

%%%===================================================================
%%% Status helpers (used by get_status/0)
%%%===================================================================

%% Build the per-file status list for the status / reload endpoints.
%%
%% Returns [StatusMap] — one entry per file, all values RPC-safe.
%% Poll-based files (source = local_dir) come from file_state and
%% loaded_locally.  Uploaded files (source = uploaded) are driven by
%% the chronicle crl_files key (the authoritative list); a file in
%% chronicle but not yet downloaded appears with status not_loaded.
%%
%% Each map contains:
%%   filename    — binary base name
%%   source      — local_dir | uploaded | url
%%   status      — active | expired | not_yet_valid | untrusted
%%                 | invalid | not_loaded
%%   entries     — per-entry breakdown
%%   last_reload — #{result, time, errors}
-spec build_status_map(#state{}) -> [map()].
build_status_map(#state{file_state       = FS,
                        loaded_locally   = LoadedLocally,
                        uploaded         = Uploaded,
                        url_file_state   = UrlFS,
                        loaded_from_urls = LoadedFromUrls}) ->
    TrustedDerCAs = ns_server_cert:trusted_CAs(der),
    LocalDir    = local_crls_dir(),
    UploadedDir = crls_dir(),
    UrlDir      = url_crls_dir(),
    %% Poll-based entries — one per file_state entry.
    PollList =
        maps:fold(
          fun (Path, ReloadStatus, Acc) ->
                  Name    = filename:basename(Path),
                  NameBin = list_to_binary(Name),
                  {Status, Entries} =
                      case maps:is_key(Name, LoadedLocally) of
                          true ->
                              current_status(filename:join(LocalDir, Name),
                                             TrustedDerCAs);
                          false ->
                              {not_loaded, []}
                      end,
                  [#{filename    => NameBin,
                     source      => local_dir,
                     status      => Status,
                     entries     => Entries,
                     last_reload => last_reload_map(ReloadStatus)} | Acc]
          end, [], FS),
    %% Uploaded entries — chronicle map is the authoritative list.
    UploadedList =
        lists:map(
          fun ({NameBin, #{checksum := ExpectedChecksum,
                           upload_timestamp := UploadTS}}) ->
                  Name = binary_to_list(NameBin),
                  CrlPath = filename:join(UploadedDir, Name),
                  {Status, Entries} =
                      case maps:is_key(Name, Uploaded) of
                          true -> current_status(CrlPath, TrustedDerCAs);
                          false -> {not_loaded, []}
                      end,
                  LastReload = upload_file_status_map(Name, Uploaded,
                                                      UploadTS,
                                                      ExpectedChecksum),
                  #{filename    => NameBin,
                    source      => uploaded,
                    status      => Status,
                    entries     => Entries,
                    last_reload => LastReload}
          end, maps:to_list(get_crl_files_metadata())),
    %% URL-fetched entries — url_file_state is the authoritative list.
    UrlList =
        maps:fold(
          fun (URL, ReloadStatus, Acc) ->
                  Name    = url_filename(URL),
                  CrlPath = filename:join(UrlDir, Name),
                  {Status, Entries} =
                      case maps:is_key(Name, LoadedFromUrls) of
                          true ->
                              current_status(CrlPath, TrustedDerCAs);
                          false ->
                              {not_loaded, []}
                      end,
                  [#{filename    => iolist_to_binary(URL),
                     source      => url,
                     status      => Status,
                     entries     => Entries,
                     last_reload =>
                         last_reload_map(ReloadStatus)} | Acc]
          end, [], UrlFS),
    PollList ++ UploadedList ++ UrlList.

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
                            case decode_and_verify_crl(Der, TrustedDerCAs,
                                                       false) of
                                {ok, [R]} -> entry_to_map(R);
                                {error, _} -> invalid_entry_map()
                            end
                        end, DerCRLs),
            {aggregate_status(Results), Results}
    end.

%% Maps current status of an uploaded file to a status map
-spec upload_file_status_map(file:filename_all(), map(), calendar:datetime(),
                             binary()) ->
          #{result => atom(),
            time => calendar:datetime(),
            errors => [binary()]}.
upload_file_status_map(Name, UploadedMap, UploadTS, ExpectedChecksum) ->
    case maps:get(Name, UploadedMap, undefined) of
        ExpectedChecksum ->
            #{result => ok, time => UploadTS, errors => []};
        undefined ->
            %% File not yet downloaded
            #{result => in_progress,
              time   => UploadTS,
              errors => [<<"Synchronization in progress (file is missing)">>]};
        GotChecksum ->
            %% Stale checksum
            Msg = io_lib:format("Synchronization in progress "
                                "(checksum mismatch: expected ~s, got ~s)",
                                [ExpectedChecksum, GotChecksum]),
            #{result => checksum_mismatch,
              time   => UploadTS,
              errors => [iolist_to_binary(Msg)]}
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
                           der         = Der,
                           crl_number  = CrlNum}) ->
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
      checksum    => file_checksum(Der),
      crl_number  => CrlNum}.

invalid_entry_map() ->
    #{issuer      => <<"unknown">>,
      status      => invalid,
      this_update => undefined,
      next_update => undefined,
      checksum    => <<>>,
      crl_number  => undefined}.

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

%%%===================================================================
%%% URL-fetching helpers
%%%===================================================================

%% Derive the on-disk base name for a URL-fetched CRL.
%% Uses SHA-256 of the URL so the name is deterministic, unique per URL,
%% and filesystem-safe (64 lowercase hex chars).
-spec url_filename(binary()) -> string().
url_filename(URL) ->
    <<H:256/big-unsigned-integer>> = crypto:hash(sha256, URL),
    lists:flatten(io_lib:format("~64.16.0b.crl", [H])).

%% Return the path of the ETag sidecar file for a given CRL path.
-spec etag_path(file:filename_all()) -> file:filename_all().
etag_path(CrlPath) -> filename:rootname(CrlPath) ++ ".etag".

%% Read a stored ETag from its sidecar file.
%% Returns undefined when no sidecar exists or it cannot be read.
-spec read_etag(file:filename_all()) -> binary() | undefined.
read_etag(CrlPath) ->
    ETagPath = etag_path(CrlPath),
    case file:read_file(ETagPath) of
        {ok, ETag} -> string:trim(ETag);
        {error, enoent} -> undefined; %% expected
        {error, Reason} ->
            %% Not expected, not critical though. Will redownload the file
            ?log_warning("Failed to read etag file ~s: ~p", [ETagPath, Reason]),
            undefined
    end.

%% Write an ETag to its sidecar file atomically.
-spec write_etag(file:filename_all(), binary() | undefined) ->
          ok | {error, term()}.
write_etag(CrlPath, undefined) ->
    %% Server haven't sent us an etag
    %% Make sure we don't have any old etags on disk for that CRL
    ETagPath = etag_path(CrlPath),
    case file:delete(ETagPath) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} ->
            ?log_warning("Failed to delete etag file ~s: ~p",
                         [ETagPath, Reason]),
            {error, Reason}
    end;
write_etag(CrlPath, ETag) when is_binary(ETag) ->
    ETagPath = etag_path(CrlPath),
    case misc:atomic_write_file(ETagPath, ETag) of
        ok -> ok;
        {error, Reason} ->
            ?log_warning("Failed to write etag file ~s: ~p",
                         [ETagPath, Reason]),
            {error, Reason}
    end.

%% Extract the ETag value from HTTP response headers (case-insensitive).
-spec get_etag_header([{string(), string()}]) -> binary() | undefined.
get_etag_header(Headers) ->
    Lower = [{string:to_lower(K), V} || {K, V} <- Headers],
    case lists:keyfind("etag", 1, Lower) of
        {_, ETag} -> iolist_to_binary(string:trim(ETag));
        false     -> undefined
    end.

%% Fetch all configured URLs and update the state accordingly.
-spec fetch_all_urls([binary()], boolean(), #state{}) -> #state{}.
fetch_all_urls(URLList, Force, State) ->
    TS = calendar:universal_time(),
    lists:foldl(fun (URL, S) ->
                    fetch_one_url(URL, TS, Force, S)
                end, State, URLList).

%% Fetch a single URL using a conditional GET (If-None-Match when an ETag
%% is stored).  Updates url_file_state and loaded_from_urls in the state.
%%
%%   304 Not Modified → keep existing cached file; record loaded status.
%%   200 OK           → verify and install; store new ETag if present.
%%   Other / error    → record failure; leave any existing good copy.
-spec fetch_one_url(binary(), calendar:datetime(), boolean(), #state{}) ->
          #state{}.
fetch_one_url(URL, TS, Force, #state{url_file_state = UrlFS} = State) ->
    Name = url_filename(URL),
    CrlPath = filename:join(url_crls_dir(), Name),
    %% Use ETag from state when available; read the .etag sidecar from disk
    %% only on first access after startup.
    StoredETag = case maps:find(URL, UrlFS) of
                     {ok, #crl_reload_status{etag = ET}} -> ET;
                     error -> read_etag(CrlPath)
                 end,
    ReqHeaders = case StoredETag of
                     undefined -> [];
                     _ETag when Force -> [];
                     ETag when is_binary(ETag) -> [{"If-None-Match", ETag}]
                 end,
    URLStr = binary_to_list(URL),
    ?log_debug("CRL URL fetching ~s (etag=~p)", [URL, StoredETag]),
    case lhttpc:request(URLStr, "GET", ReqHeaders, [],
                        ?URL_FETCH_TIMEOUT_MS, []) of
        {ok, {{304, _}, _, _}} ->
            ?log_debug("CRL URL ~s: 304 Not Modified", [URL]),
            Status = #crl_reload_status{etag = StoredETag,
                                        result = loaded,
                                        time = TS,
                                        errors = []},
            State#state{url_file_state = maps:put(URL, Status, UrlFS)};
        {ok, {{200, _}, RespHeaders, Body}} ->
            ResponseETag = get_etag_header(RespHeaders),
            ?log_debug("CRL URL ~s: 200 (etag=~p)", [URL, ResponseETag]),
            install_url_crl(URL, Name, CrlPath, Body, ResponseETag, StoredETag,
                            TS, State);
        {ok, {{HttpStatus, _}, _, Body}} ->
            ?log_warning("CRL URL ~s: unexpected HTTP status ~p~nBody: ~p",
                            [URL, HttpStatus, Body]),
            R = {http_status, HttpStatus, Body},
            Status = #crl_reload_status{etag = StoredETag,
                                        result = failed,
                                        time   = TS,
                                        errors = format_load_errors(R)},
            State#state{url_file_state = maps:put(URL, Status, UrlFS)};
        {error, Reason} ->
            ?log_warning("CRL URL ~s: fetch failed: ~p", [URL, Reason]),
            R = {http_failed, Reason},
            Status = #crl_reload_status{etag = StoredETag,
                                        result = failed,
                                        time   = TS,
                                        errors = format_load_errors(R)},
            State#state{url_file_state = maps:put(URL, Status, UrlFS)}
    end.

%% Verify a downloaded CRL body and install it into the cache.
%% On success the file and its ETag sidecar are written atomically.
%% On failure any existing good copy is left untouched.
-spec install_url_crl(binary(), string(), file:filename_all(),
                      binary(), binary() | undefined, binary() | undefined,
                      calendar:datetime(), #state{}) -> #state{}.
install_url_crl(URL, Name, CrlPath, Body, NewETag, CurETag, TS,
                #state{loaded_from_urls = LoadedFromUrls,
                       url_file_state = UrlFS} = State) ->
    AllowExpired = ?get_param(allow_expired_crls, false),
    TrustedCAs = ns_server_cert:trusted_CAs(der),
    maybe
        {ok, Results} ?= decode_and_verify_crl(Body, TrustedCAs, AllowExpired),
        Bad = [R || R <- Results, R#entry_result.result =/= ok],
        ok ?= case Bad of
                  [] -> ok;
                  [_ | _] -> {error, {bad_crl_entries, Bad}}
              end,
        {ok, Checksum} ?= add_to_cache(url, Name, Body, Results),
        Errors = case write_etag(CrlPath, NewETag) of
                     ok -> [];
                     {error, R} -> format_load_errors({etag_save, R})
                 end,
        ?log_debug("CRL URL ~p: installed (~b bytes)", [URL, byte_size(Body)]),
        Status = #crl_reload_status{etag = NewETag,
                                    result = loaded,
                                    time   = TS,
                                    errors = Errors},
        State#state{url_file_state = maps:put(URL, Status, UrlFS),
                    loaded_from_urls = maps:put(Name, Checksum, LoadedFromUrls)}
    else
        {error, Reason} ->
            ErrorStrings = format_load_errors(Reason),
            ?log_warning("Failed to install CRL from URL ~s:~n~s",
                         [URL, lists:join(<<"\n">>, ErrorStrings)]),
            ErrStatus = #crl_reload_status{etag = CurETag,
                                           result = failed,
                                           time   = TS,
                                           errors = ErrorStrings},
            State#state{url_file_state = maps:put(URL, ErrStatus, UrlFS)}
    end.

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

decode_and_verify_crl(Binary, TrustedDerCAs, AllowExpiredCrls) ->
    maybe
        {ok, Triples} ?= decode_crl(Binary),
        {ok, verify_crls(Triples, TrustedDerCAs, AllowExpiredCrls)}
    else
        {error, Reason} ->
            {error, {decode_error, Reason}}
    end.

%% Sometimes we don't need to reverify the CRL so it is useful to have a
%% function that returns the decoded entries in the same format as verify_crls/2
decode_to_entries(Binary) ->
    maybe
        {ok, Triples} ?= decode_crl(Binary),
        {ok, [entry_result(ok, T) || T <- Triples]}
    else
        {error, Reason} ->
            {error, {decode_error, Reason}}
    end.

%% When AllowExpiredCrls is true the thisUpdate/nextUpdate validity window
%% is not checked; only the CRL signature is verified.  This is intended
%% for testing environments where expired CRLs must be loadable.
-spec verify_crls(
        [{public_key:issuer_name(), #'CertificateList'{}, binary()}],
        [binary()],
        AllowExpiredCrls :: boolean()) -> [entry_result()].
verify_crls(CRLTriples, TrustedDerCAs, AllowExpiredCrls) ->
    [begin
         Result = verify_crl(Decoded, TrustedDerCAs, AllowExpiredCrls),
         case Result of
             {error, Reason} ->
                 ?log_warning("CRL entry verification failed"
                              " (issuer ~p): ~p", [RawIssuer, Reason]);
             ok -> ok
         end,
         entry_result(Result, T)
     end || {RawIssuer, Decoded, _Der} = T <- CRLTriples].

entry_result(Result, {RawIssuer, Decoded, Der}) ->
    {ThisUpdate, NextUpdate} = crl_times(Decoded),
    #entry_result{result      = Result,
                  issuer      = RawIssuer,
                  this_update = ThisUpdate,
                  next_update = NextUpdate,
                  der         = Der,
                  crl_number  = get_crl_number(Decoded)}.

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
-spec verify_crl(#'CertificateList'{}, [binary()], boolean()) ->
          ok | {error, term()}.
verify_crl(CRL, TrustedDerCAs, AllowExpiredCrls) ->
    maybe
        ok ?= case AllowExpiredCrls of
                  true -> ok;
                  false -> check_crl_validity(CRL)
              end,
        ok ?= verify_crl_signature(CRL, TrustedDerCAs)
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
