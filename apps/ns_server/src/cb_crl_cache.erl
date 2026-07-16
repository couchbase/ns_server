%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_crl_cache).

-behaviour(gen_server).
-behaviour(ssl_crl_cache_api).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").
-include_lib("public_key/include/public_key.hrl").

%% Internal record — not exposed outside this module.
-record(crl_elem, {
    issuer,   %% public_key:issuer_name()   — normalised
    der,      %% binary()                   — DER-encoded CertificateList
    meta      %% map()                      — caller-supplied metadata, stored
              %%                              verbatim (see get_file_crls_meta)
}).

%% ssl_crl_cache_api behaviour
-export([lookup/3, select/2, fresh_crl/2]).

%% public API
-export([start_link/0,
         insert_file/2,
         remove_file/1,
         remove_all_crls/0,
         get_all_file_paths/0,
         get_file_crls/1,
         get_file_crls_meta/1,
         set_policy/2,
         get_policy/1,
         set_check_intermediate_certs/1,
         get_check_intermediate_certs/0,
         set_crl_version/1,
         get_crl_version/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ETS, cb_crl_cache).

-type crl_cache_ref() :: undefined.
-type der_crl() :: public_key:der_encoded().

%% ETS layout (set):
%%   {crl_file, NormPath}         => [#crl_elem{}]
%%   {issuer,   NormIssuer}       => [{crl_file, NormPath}]
%%   {policy,   Scope}            => crl_policy()
%%   check_intermediate_certs     => boolean()
%%   crl_version                  => integer()  (opaque config/data version)
%%
%% Each #crl_elem{} stores the normalised issuer, the DER-encoded CRL, and
%% a caller-supplied metadata map (stored verbatim, never interpreted here).
%%
%% Path normalization: misc:normalize_path/1 — resolves relative components
%%   and collapses . / .. segments (raises badarg if the path escapes root).
%% Issuer normalization: public_key:pkix_normalize_name/1 (applied in
%% insert_file).
%%
%% Policy entries are managed exclusively by cb_crl_manager with strict
%% ordering guarantees; see cb_crl_manager:apply_config/2.

-record(state, {}).

%%%===================================================================
%%% Public API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Insert (or atomically overwrite) all CRLs from one file.
%% CRLEntries is a list of {RawIssuer, DerCRL, Meta} triples — one element per
%% CRL entry found in the file (a PEM may contain several).  Meta is an
%% opaque map stored next to the DER so information captured when the CRL was
%% decoded (e.g. expiration dates) can be read back via get_file_crls_meta/1
%% without decoding the CRL again.
%% Path is normalized internally with misc:normalize_path/1.
%% Issuer normalization (pkix_normalize_name/1) is performed here so callers
%% do not need to do it.
-spec insert_file(file:filename_all(),
                  [{public_key:issuer_name(), der_crl(), map()}]) -> ok.
insert_file(Path, CRLEntries) ->
    gen_server:call(?SERVER, {insert_file, Path, CRLEntries}).

%% Remove all CRLs associated with a file path.
%% Determines the affected issuers from the existing {crl_file, _} entry and
%% removes only those issuer index entries, then deletes the crl_file row.
%% Path is normalized internally with misc:normalize_path/1.
-spec remove_file(file:filename_all()) -> ok.
remove_file(Path) ->
    gen_server:call(?SERVER, {remove_file, Path}).

%% Remove every {crl_file, _} and {issuer, _} entry from the table without
%% touching other record types that may be added in the future.
-spec remove_all_crls() -> ok.
remove_all_crls() ->
    gen_server:call(?SERVER, remove_all_crls).

%% Return the normalized paths of every file currently in the cache.
%% Reads directly from the ETS table (which is 'protected': any process may
%% read, only the owning gen_server may write).
-spec get_all_file_paths() -> [file:filename_all()].
get_all_file_paths() ->
    try
        [P || [P] <- ets:match(?ETS, {{crl_file, '$1'}, '_'})]
    catch
        error:badarg -> []
    end.

%% Return the DER-encoded CRLs for a single file currently in the cache.
%% Reads directly from ETS (safe: table is 'protected').
%% Returns [] when the path is not cached or the table does not exist yet.
-spec get_file_crls(file:filename_all()) -> [der_crl()].
get_file_crls(Path) ->
    NormPath = misc:normalize_path(Path),
    try
        case ets:lookup(?ETS, {crl_file, NormPath}) of
            []           -> [];
            [{_, Elems}] -> [E#crl_elem.der || E <- Elems]
        end
    catch
        error:badarg -> []
    end.

%% Return the metadata map supplied at insert time for each CRL entry of a
%% single file, without touching the DER data.
%% Reads directly from ETS (safe: table is 'protected').
%% Returns [] when the path is not cached or the table does not exist yet.
-spec get_file_crls_meta(file:filename_all()) -> [map()].
get_file_crls_meta(Path) ->
    NormPath = misc:normalize_path(Path),
    try
        case ets:lookup(?ETS, {crl_file, NormPath}) of
            []           -> [];
            [{_, Elems}] -> [E#crl_elem.meta || E <- Elems]
        end
    catch
        error:badarg -> []
    end.

%% Store the revocation policy for a given scope.
%% Called exclusively by cb_crl_manager with strict ordering guarantees:
%%   disabled policies are written before CRL data is modified;
%%   non-disabled policies are written after CRL data is loaded.
-spec set_policy(Scope :: crl_scope(), Policy :: crl_policy()) -> ok.
set_policy(Scope, Policy) ->
    gen_server:call(?SERVER, {set_policy, Scope, Policy}).

%% Read the revocation policy for a scope directly from ETS.
%% Returns 'unknown' — not 'disabled' — when the entry is absent or the ETS
%% table does not yet exist.  Callers must treat 'unknown' as a security
%% failure (the cache is not ready) rather than silently allowing traffic.
-spec get_policy(Scope :: crl_scope()) -> crl_policy() | unknown.
get_policy(Scope) ->
    try
        case ets:lookup(?ETS, {policy, Scope}) of
            [{{policy, _}, Policy}] -> Policy;
            []                      -> unknown
        end
    catch
        error:badarg -> unknown
    end.

%% Store the check_intermediate_certs flag.
%% Called exclusively by cb_crl_manager, after CRL data and policies are set.
-spec set_check_intermediate_certs(boolean()) -> ok.
set_check_intermediate_certs(V) ->
    gen_server:call(?SERVER, {set_check_intermediate_certs, V}).

-spec get_check_intermediate_certs() -> boolean() | unknown.
get_check_intermediate_certs() ->
    try
        case ets:lookup(?ETS, check_intermediate_certs) of
            [{_, V}] -> V;
            []       -> unknown
        end
    catch
        error:badarg -> unknown
    end.

%% Store the current CRL "version" (an opaque integer computed by cb_crl_manager
%% from the effective revocation configuration + CRL data; see
%% cb_crl_manager:crl_config_version/1).  It is written here, in the same
%% serialization point that owns the CRL data, at the end of every configuration
%% change, so it is guaranteed to be observed only after the corresponding data
%% writes.  cb_crl_status_cache reads it (get_crl_version/0) to decide whether a
%% cached verdict was computed against the current CRL data.
-spec set_crl_version(integer()) -> ok.
set_crl_version(Version) ->
    gen_server:call(?SERVER, {set_crl_version, Version}).

%% Fast, lock-free read of the current CRL version.  Returns 'undefined' when no
%% version has been written yet or the cache table is not up.
-spec get_crl_version() -> integer() | undefined.
get_crl_version() ->
    try
        case ets:lookup(?ETS, crl_version) of
            [{_, V}] -> V;
            []       -> undefined
        end
    catch
        error:badarg -> undefined
    end.

%%%===================================================================
%%% ssl_crl_cache_api callbacks
%%%===================================================================
%% This module is plugged into TLS options as
%%     {crl_cache, {cb_crl_cache, undefined}}
%% and so receives lookup/3, select/2 and fresh_crl/2 invocations from
%% the SSL handshake.
%%
%% De-facto the lookup callback is called when the certificate contains the CRL
%% Distribution Point extension.
%% The DP arg is the Distribution Point from the-certificate-to-be-validated.
%% CertIssuer is the issuer of the-certificate-to-be-validated.
%% DP may contain cRLIssuer, in this case we should return CRLs issued
%% by it, otherwise we should return CRLs issued by CertIssuer
%% According to rfc5280:
%% cRLIssuer ::= GeneralNames -- a list!!!
%% and CertIssuer is a Name where
%% Name ::= CHOICE { rdnSequence  RDNSequence }
-spec lookup(Distpoint :: #'DistributionPoint'{},
             Issuer :: public_key:issuer_name(),
             CacheRef :: crl_cache_ref()) -> not_available | [der_crl()].
lookup(#'DistributionPoint'{cRLIssuer = asn1_NOVALUE} = DP, CertIssuer,
       DbHandle) ->
    CRLs = select(CertIssuer, DbHandle),
    case lists:filter(public_key:pkix_match_dist_point(_, DP), CRLs) of
        [] -> not_available; %% Let it check other DPs
        Matched -> Matched
    end;
lookup(#'DistributionPoint'{cRLIssuer = CRLIssuer}, _CertIssuer, DbHandle) ->
    select(CRLIssuer, DbHandle).

%% De-facto the select callback is called when the certificate does not contain
%% the CRL DP extension.
%% The issuer is the issuer of the certificate-to-be-validated.
%% Issuer can also be taken from id-ce-issuerAltName extension of
%% the certificate-to-be-validated.
%% At the same time, according to the erlang doc the first arg can also be a
%% list names originating from #'DistributionPoint'.cRLissuer.
%% According to rfc5280:
%% Issuer is a Name while
%% id-ce-issuerAltName ::= GeneralNames -- a list!!!
%% and cRLIssuer ::= GeneralNames -- a list!!!

%% GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
%% GeneralName ::= CHOICE {
%%        otherName                       [0]     OtherName,
%%        rfc822Name                      [1]     IA5String,
%%        dNSName                         [2]     IA5String,
%%        x400Address                     [3]     ORAddress,
%%        directoryName                   [4]     Name,
%%        ediPartyName                    [5]     EDIPartyName,
%%        uniformResourceIdentifier       [6]     IA5String,
%%        iPAddress                       [7]     OCTET STRING,
%%        registeredID                    [8]     OBJECT IDENTIFIER }

-spec select(IssuerOrDPLocations, CacheRef) -> [der_crl()]
            when IssuerOrDPLocations :: public_key:issuer_name() | list(),
                 CacheRef :: crl_cache_ref().
select({rdnSequence, _} = Issuer, DbHandle) ->
    select([{directoryName, Issuer}], DbHandle);
select(DPLocations, _DbHandle) when is_list(DPLocations) ->
    issuer_crls(DPLocations);
select(_Other, _DbHandle) ->
    [].

%% Called by SSL when nextUpdate has passed; we return the CRL we have
%% (the gen_server is responsible for refreshing it asynchronously).
fresh_crl(_DP, CRL) ->
    CRL.

%% The arg can be any name:
%% GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
%% but de-facto ssl_crl_cache and ssl_crl_hash_dir handle only directoryName
%% so we also handle only directoryName here
-spec issuer_crls([{directoryName, public_key:issuer_name()} | any()]) ->
          [der_crl()].
issuer_crls(Names) ->
    lists:flatmap(
      fun ({directoryName, IssuerName}) ->
              NormIssuer = public_key:pkix_normalize_name(IssuerName),
              try ets:lookup(?ETS, {issuer, NormIssuer}) of
                  [] ->
                      [];
                  [{{issuer, _}, FileKeys}] ->
                      lists:flatmap(
                        fun (FileKey) ->
                                case ets:lookup(?ETS, FileKey) of
                                    [{_, Elems}] ->
                                        %% Return only CRLs whose issuer
                                        %% matches the one being looked up
                                        [E#crl_elem.der
                                         || E <- Elems,
                                            E#crl_elem.issuer =:= NormIssuer];
                                    [] ->
                                        []
                                end
                        end, FileKeys)
              catch
                  error:badarg -> []
              end;
          (_) -> []
      end, Names).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?ETS, [named_table, protected, set]),
    {ok, #state{}}.

handle_call({insert_file, Path, CRLEntries}, _From, State) ->
    NormPath  = misc:normalize_path(Path),
    FileKey   = {crl_file, NormPath},
    NewElems  = [#crl_elem{issuer  = public_key:pkix_normalize_name(I),
                           der     = D,
                           meta    = M} || {I, D, M} <- CRLEntries],
    NewIssuers = lists:usort([E#crl_elem.issuer || E <- NewElems]),
    %% Determine which issuers are present in the existing record (if any).
    OldIssuers =
        case ets:lookup(?ETS, FileKey) of
            []             -> [];
            [{_, OldElems}] -> lists:usort([E#crl_elem.issuer || E <- OldElems])
        end,
    %% Remove FileKey from issuer index entries that no longer appear in the
    %% new data.  We do this BEFORE overwriting the crl_file entry so that
    %% concurrent TLS lookups always see either the old or the new CRL — never
    %% a gap.  Issuers that are present in both old and new are left untouched.
    remove_file_key_for_issuers(FileKey, OldIssuers -- NewIssuers),
    %% Atomically overwrite the CRL data for this file.
    ets:insert(?ETS, {FileKey, NewElems}),
    %% Add FileKey to the issuer index for any issuers that are new to this file.
    lists:foreach(
      fun (NormIssuer) ->
              ExistingKeys =
                  case ets:lookup(?ETS, {issuer, NormIssuer}) of
                      []          -> [];
                      [{_, Keys}] -> Keys
                  end,
              UpdatedKeys = lists:usort([FileKey | ExistingKeys]),
              ets:insert(?ETS, {{issuer, NormIssuer}, UpdatedKeys})
      end, NewIssuers -- OldIssuers),
    {reply, ok, State};

handle_call({remove_file, Path}, _From, State) ->
    NormPath = misc:normalize_path(Path),
    FileKey  = {crl_file, NormPath},
    %% Read which issuers this file contributed before deleting it, then
    %% remove FileKey only from those specific issuer index entries.
    OldIssuers =
        case ets:lookup(?ETS, FileKey) of
            []              -> [];
            [{_, OldElems}] -> lists:usort([E#crl_elem.issuer || E <- OldElems])
        end,
    remove_file_key_for_issuers(FileKey, OldIssuers),
    ets:delete(?ETS, FileKey),
    {reply, ok, State};

handle_call(remove_all_crls, _From, State) ->
    %% Delete only crl_file and issuer records; policy and flag entries
    %% are managed independently by cb_crl_manager and must not be removed.
    ets:match_delete(?ETS, {{crl_file, '_'}, '_'}),
    ets:match_delete(?ETS, {{issuer,    '_'}, '_'}),
    {reply, ok, State};

handle_call({set_policy, Scope, Policy}, _From, State) ->
    ?log_debug("Setting policy '~p' for scope '~p'", [Policy, Scope]),
    ets:insert(?ETS, {{policy, Scope}, Policy}),
    {reply, ok, State};

handle_call({set_check_intermediate_certs, V}, _From, State) ->
    ets:insert(?ETS, {check_intermediate_certs, V}),
    {reply, ok, State};

handle_call({set_crl_version, Version}, _From, State) ->
    ets:insert(?ETS, {crl_version, Version}),
    {reply, ok, State};

handle_call(Req, _From, State) ->
    ?log_error("Received unknown call: ~p", [Req]),
    {reply, {error, unknown_request}, State}.

handle_cast(Msg, State) ->
    ?log_error("Received unknown cast: ~p", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    ?log_error("Received unknown info: ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_, State, _) -> {ok, State}.

%%%===================================================================
%%% Internal helpers
%%%===================================================================

%% For each NormIssuer in Issuers, remove FileKey from the {issuer, NormIssuer}
%% index entry.  Deletes the issuer row entirely when its list becomes empty.
-spec remove_file_key_for_issuers({crl_file, file:filename_all()},
                                  [public_key:issuer_name()]) -> ok.
remove_file_key_for_issuers(FileKey, Issuers) ->
    lists:foreach(
      fun (NormIssuer) ->
              case ets:lookup(?ETS, {issuer, NormIssuer}) of
                  [] -> ok;
                  [{_, Keys}] ->
                      case lists:delete(FileKey, Keys) of
                          []      -> ets:delete(?ETS, {issuer, NormIssuer});
                          NewKeys -> ets:insert(?ETS, {{issuer, NormIssuer}, NewKeys})
                      end
              end
      end, Issuers).
