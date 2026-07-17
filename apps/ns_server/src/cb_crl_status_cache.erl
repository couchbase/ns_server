%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Certificate revocation status (verdict) cache.
%%
%% Caches the *result* of a revocation determination (the verdict) rather than
%% the underlying CRL, so that repeated TLS handshakes for the same certificate
%% do not re-run public_key:pkix_crls_validate/3 every time.
%%
%% A cached entry records the raw public_key:pkix_crls_validate/3 result
%% (valid | {bad_cert, Reason}) as of a known point in time, together with
%% freshness bounds inherited from the source revocation data.  The verdict
%% stored here is policy-independent; cb_crl applies the per-scope permissive /
%% require policy at lookup time (the fail-open / fail-closed disposition).
%%
%% The cache is keyed on the certificate: callers pass the #'OTPCertificate'{}
%% and this module derives the key {IssuerId, Serial} (see make_cache_key/1).
%%
%% Backend: active_cache provides the ETS storage (reads served directly from
%% the calling process), per-key coalescing of concurrent computations, size
%% bounding and periodic cleanup.  This module layers CRL-specific validity on
%% top via active_cache:get_value_and_touch/4: each entry carries the CRL version
%% (see cb_crl_cache:get_crl_version/0) that produced it plus an absolute
%% effective-expiry, and fresh/1 accepts an entry only when its version matches
%% the current one AND it has not expired.
%%
%% Invalidation is therefore implicit: cb_crl_manager writes a new CRL version
%% into cb_crl_cache at the end of every configuration change, after the CRL data
%% writes; entries computed under the old version stop matching and are
%% recomputed on next use.  Because the version read that tags an entry happens
%% *before* the CRL check runs, an entry computed from stale data can never be
%% tagged with a version newer than the data it used, so a stale verdict is never
%% served as fresh.
%%
-module(cb_crl_status_cache).

-behaviour(active_cache).

-include("ns_common.hrl").
-include_lib("public_key/include/public_key.hrl").

%% public API
-export([start_link/0,
         crl_check/1]).

%% active_cache callbacks
-export([init/1, translate_options/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(ETS, ?MODULE).

%% All three tunables below are overridable per node via ?get_param, i.e. the
%% ns_config key {cb_crl_status_cache, <param>}.  MAX_CACHE_LIFETIME_S is read
%% live (on each verdict computation); MAX_ENTRIES / MAX_PARALLEL feed
%% active_cache options, read when the cache (re)starts.

%% Fallback lifetime for a verdict that has no CRL nextUpdate to anchor its
%% expiry to (no CRLs, or all of them expired) - see effective_expiry/3.  It is
%% not a cap on cached verdicts in general: a verdict backed by a CRL is served
%% until that CRL's nextUpdate, which may be well beyond this value.  Also used
%% as active_cache's value_lifetime, i.e. the idle window after which an unused
%% entry is evicted (entries are touched on access, so the timer resets on use).
-define(MAX_CACHE_LIFETIME_S, ?get_param(max_cache_lifetime_s, 2592000)).
%% Short TTL for error / indeterminate results, solely to limit redundant
%% upstream re-evaluation (spec 6.6).
-define(ERROR_TTL_S, ?get_param(error_ttl_s, 30)).
%% Bound on the number of cached verdicts; active_cache evicts when exceeded.
-define(MAX_ENTRIES, ?get_param(max_entries, 4096)).
%% Bound on concurrent verdict computations (active_cache worker buckets).
-define(MAX_PARALLEL, ?get_param(max_parallel_procs, 16)).

%% The raw public_key:pkix_crls_validate/3 outcome, stored verbatim.
-type cache_key() :: {IssuerId :: term(), Serial :: integer()}.

-type compute_fun() ::
        fun(() -> {cb_crl:pkix_crls_validate_verdict(),
                   NextUpdate :: calendar:datetime() | undefined}).

-record(status_entry, {
    verdict           :: cb_crl:pkix_crls_validate_verdict(),
    next_update       :: calendar:datetime() | undefined,
    effective_expiry  :: non_neg_integer(),  %% gregorian seconds (absolute)
    version           :: integer() | undefined
}).

%%%===================================================================
%%% Public API
%%%===================================================================

start_link() ->
    active_cache:start_link(?MODULE, ?MODULE, [], opts()).

opts() ->
    [{max_size, ?MAX_ENTRIES},
     {value_lifetime, ?MAX_CACHE_LIFETIME_S * 1000},
     {renew_interval, infinity},   %% pull-based; never proactively re-validate
     {max_parallel_procs, ?MAX_PARALLEL},
     %% cache a failing check briefly (and re-raise it) so a transient error
     %% does not re-run pkix on every handshake.
     {cache_exceptions, true}].

%% Return the cached verdict for the certificate when one is present, fresh (now
%% within the entry's effective validity window) and tagged with the current CRL
%% version.  Otherwise run cb_crl:crl_check to obtain a fresh determination,
%% cache it, and return it.  Concurrent misses on the same key are coalesced
%% (via active_cache) so that at most one ComputeFun per key runs at a time.
%%
%% The fast (hit) path reads ETS directly from the calling process and never
%% touches the backend gen_server.
%%
%% When the cache has not been started yet (early boot, before it is placed in
%% the supervision tree), the status is computed directly and not cached.
-spec crl_check(#'OTPCertificate'{}) ->
          {cb_crl:pkix_crls_validate_verdict(),
           calendar:datetime() | undefined}.
crl_check(OtpCert) ->
    get_or_compute(OtpCert, fun () -> cb_crl:crl_check(OtpCert) end).

%%%===================================================================
%%% active_cache callbacks
%%%===================================================================

init(_Args) ->
    ok.

translate_options(_) ->
    opts().

%%%===================================================================
%%% Lookup / compute
%%%===================================================================

-spec get_or_compute(#'OTPCertificate'{}, compute_fun()) -> 
          {cb_crl:pkix_crls_validate_verdict(),
           calendar:datetime() | undefined}.
get_or_compute(OtpCert, ComputeFun) ->
    Key = make_cache_key(OtpCert),
    %% get_value_and_touch (not get_value): refresh the entry's
    %% last-use timestamp so a periodically-used verdict is not
    %% evicted by active_cache's idle cleanup while still valid.
    try active_cache:get_value(
          ?MODULE, Key, fun () -> compute_entry(ComputeFun) end,
          #{touch => true,
            is_valid_value => fun fresh/1}) of
        Entry ->
            {Entry#status_entry.verdict, Entry#status_entry.next_update}
    catch
        %% Cache doesn't exist yet.  Fall back to a direct computation.
        error:badarg ->
            ComputeFun()
    end.

%% active_cache validity predicate: a cached entry is usable only if it was
%% computed against the current CRL version and has not expired.
-spec fresh(#status_entry{}) -> boolean().
fresh(#status_entry{version = V, effective_expiry = Exp}) ->
    V =:= cb_crl_cache:get_crl_version() andalso Exp > now_secs().

%% Compute a fresh verdict and wrap it into a #status_entry{}.  The CRL version
%% is read *before* running the check (ComputeFun), so the entry is tagged with
%% the version of the data actually used.  ComputeFun exceptions are not caught
%% here: active_cache runs this under its own try/catch (cache_exceptions), so a
%% failing check is cached briefly and re-raised to the caller.
-spec compute_entry(compute_fun()) -> #status_entry{}.
compute_entry(ComputeFun) ->
    Version = cb_crl_cache:get_crl_version(),
    {Verdict, NextUpdate} = ComputeFun(),
    Now = now_secs(),
    #status_entry{verdict          = Verdict,
                  next_update      = NextUpdate,
                  effective_expiry = effective_expiry(Verdict, NextUpdate, Now),
                  version          = Version}.

now_secs() ->
    calendar:datetime_to_gregorian_seconds(calendar:universal_time()).

%%%===================================================================
%%% Cache key
%%%===================================================================

%% Cache key: {IssuerId, Serial}.  IssuerId is the cert's Authority Key
%% Identifier keyIdentifier when present (uniquely identifies the issuer key,
%% surviving issuer DN reuse), falling back to the normalized issuer DN.  Serial
%% numbers are unique only within an issuer, so they are never used alone.
-spec make_cache_key(#'OTPCertificate'{}) -> cache_key().
make_cache_key(OtpCert) ->
    TBS = OtpCert#'OTPCertificate'.tbsCertificate,
    Serial = TBS#'OTPTBSCertificate'.serialNumber,
    case Serial of
        B when is_integer(B) -> ok;
        undefined -> erlang:error(no_cert_serial_number);
        asn1_NOVALUE -> erlang:error(no_cert_serial_number)
    end,
    IssuerId =
        case cert_aki_key_id(OtpCert) of
            undefined ->
                {dn, public_key:pkix_normalize_name(
                       TBS#'OTPTBSCertificate'.issuer)};
            KeyId ->
                {aki, KeyId}
        end,
    {IssuerId, Serial}.

%% Extract the keyIdentifier from a certificate's Authority Key Identifier
%% extension.  Handles both the OTP-decoded form (#'AuthorityKeyIdentifier'{})
%% and a raw DER extnValue.  Returns undefined when absent.
-spec cert_aki_key_id(#'OTPCertificate'{}) -> binary() | undefined.
cert_aki_key_id(OtpCert) ->
    TBS = OtpCert#'OTPCertificate'.tbsCertificate,
    case TBS#'OTPTBSCertificate'.extensions of
        asn1_NOVALUE ->
            undefined;
        Exts ->
            case lists:keyfind(?'id-ce-authorityKeyIdentifier',
                               #'Extension'.extnID, Exts) of
                false ->
                    undefined;
                #'Extension'{extnValue = Val} ->
                    aki_key_id_from_value(Val)
            end
    end.

aki_key_id_from_value(#'AuthorityKeyIdentifier'{keyIdentifier = asn1_NOVALUE}) ->
    undefined;
aki_key_id_from_value(#'AuthorityKeyIdentifier'{keyIdentifier = KeyId}) ->
    KeyId;
aki_key_id_from_value(Val) when is_binary(Val) ->
    try public_key:der_decode('AuthorityKeyIdentifier', Val) of
        Decoded -> aki_key_id_from_value(Decoded)
    catch _:_ -> undefined
    end;
aki_key_id_from_value(_) ->
    undefined.

%%%===================================================================
%%% Internal helpers
%%%===================================================================

%% Effective expiry (absolute gregorian seconds) of a verdict.
-spec effective_expiry(cb_crl:pkix_crls_validate_verdict(),
                       calendar:datetime() | undefined,
                       non_neg_integer()) -> non_neg_integer().
effective_expiry(Verdict, NextUpdate, Now) ->
    case {is_expected_verdict(Verdict), NextUpdate} of
        %% Happens when there are no CRLs, or when all of them have expired
        {true, undefined} -> Now + ?MAX_CACHE_LIFETIME_S;
        {true, _} -> calendar:datetime_to_gregorian_seconds(NextUpdate);
        %% Happens when we are not sure the verdict is defined by CRL, so we
        %% can't rely on the CRLs expiration
        {false, _} -> Now + ?ERROR_TTL_S
    end.

-spec is_expected_verdict(cb_crl:pkix_crls_validate_verdict()) -> boolean().
is_expected_verdict(valid) -> true;
is_expected_verdict({bad_cert, {revocation_status_undetermined, _}}) -> true;
is_expected_verdict({bad_cert, {revoked, _}}) -> true;
is_expected_verdict(_) -> false.

%%%===================================================================
%%% Tests
%%%===================================================================
-ifdef(TEST).

dt(Secs) ->
    calendar:gregorian_seconds_to_datetime(Secs).

%% ?get_param reads ns_config, which is not running under eunit; make it return
%% each call's default so the tunables resolve to their built-in defaults.
mock_ns_config() ->
    meck:new(ns_config, [passthrough]),
    meck:expect(ns_config, search_node_with_default,
                fun (_Key, Default) -> Default end).

unmock_ns_config() ->
    meck:unload(ns_config).

%% Start the real cb_crl_cache so get_crl_version/0 and set_crl_version/1 exercise
%% the actual code path, and set an initial version.  Returns its pid so the
%% caller can shut it down.
setup_crl_cache() ->
    {ok, Pid} = cb_crl_cache:start_link(),
    set_crl_version(0),
    Pid.

set_crl_version(V) ->
    cb_crl_cache:set_crl_version(V).

stop_proc(Pid) ->
    unlink(Pid),
    Ref = monitor(process, Pid),
    exit(Pid, shutdown),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 5000 ->
        %% Didn't shut down cleanly; force it and wait for the exit.
        exit(Pid, kill),
        receive {'DOWN', Ref, process, Pid, _} -> ok end
    end.

with_server(Fun) ->
    mock_ns_config(),
    CachePid = setup_crl_cache(),
    {ok, Pid} = start_link(),
    try Fun()
    after
        stop_proc(Pid),
        stop_proc(CachePid),
        unmock_ns_config()
    end.

future_dt() ->
    dt(now_secs() + 1000000).

past_dt() ->
    dt(now_secs() - 100).

not_started_fallback_test() ->
    %% Do not create the cache process
    %% Check that we fall back to a direct computation
    Ref = counters:new(1, []),
    Cert = fake_cert(<<"i">>, 42),
    DT = future_dt(),
    Fun = fun () ->
                  counters:add(Ref, 1, 1),
                  {valid, DT}
          end,
    ?assertEqual({valid, DT}, get_or_compute(Cert, Fun)),
    ?assertEqual(1, counters:get(Ref, 1)),
    ?assertEqual({valid, DT}, get_or_compute(Cert, Fun)),
    ?assertEqual(2, counters:get(Ref, 1)).

caching_test_() ->
    {timeout, 30,
     fun () ->
             with_server(
               fun () ->
                       Ref = counters:new(1, []),
                       Cert = fake_cert(<<"i">>, 42),
                       DT = future_dt(),
                       Fun = fun () ->
                                     counters:add(Ref, 1, 1),
                                     {valid, DT}
                             end,
                       ?assertEqual({valid, DT},
                                    get_or_compute(Cert, Fun)),
                       ?assertEqual(1, counters:get(Ref, 1)),
                       %% Second lookup is a hit; Fun is not re-run.
                       ?assertEqual({valid, DT},
                                    get_or_compute(Cert, Fun)),
                       ?assertEqual(1, counters:get(Ref, 1)),
                       %% A new CRL version makes the entry stale; Fun runs again.
                       set_crl_version(1),
                       ?assertEqual({valid, DT},
                                    get_or_compute(Cert, Fun)),
                       ?assertEqual(2, counters:get(Ref, 1)),
                       %% ...and is fresh again under the new version.
                       ?assertEqual({valid, DT},
                                    get_or_compute(Cert, Fun)),
                       ?assertEqual(2, counters:get(Ref, 1))
               end)
     end}.

%% An entry whose effective_expiry is already in the past must not be served, so
%% each lookup recomputes.
expired_not_served_test_() ->
    {timeout, 30,
     fun () ->
             with_server(
               fun () ->
                       Ref = counters:new(1, []),
                       Cert = fake_cert(<<"d">>, 7),
                       %% Past nextUpdate ⇒ effective_expiry already elapsed.
                       DT = past_dt(),
                       Fun = fun () ->
                                     counters:add(Ref, 1, 1),
                                     {valid, DT}
                             end,
                       ?assertEqual({valid, DT},
                                    get_or_compute(Cert, Fun)),
                       ?assertEqual({valid, DT},
                                    get_or_compute(Cert, Fun)),
                       %% Expired ⇒ recomputed on the second lookup too.
                       ?assertEqual(2, counters:get(Ref, 1))
               end)
     end}.

%% Build a minimal #'OTPCertificate'{} with a given issuer keyIdentifier (AKI)
%% and serial - enough for make_cache_key/1.
fake_cert(KeyId, Serial) ->
    AKI = #'Extension'{extnID = ?'id-ce-authorityKeyIdentifier',
                       critical = false,
                       extnValue = #'AuthorityKeyIdentifier'{
                                      keyIdentifier = KeyId}},
    TBS = #'OTPTBSCertificate'{serialNumber = Serial,
                               extensions = [AKI]},
    #'OTPCertificate'{tbsCertificate = TBS}.

make_cache_key_test() ->
    %% AKI present -> keyed by {aki, KeyId}.
    ?assertEqual({{aki, <<"kid">>}, 5},
                 make_cache_key(fake_cert(<<"kid">>, 5))),
    %% No extensions -> falls back to the normalized issuer DN.
    TBS = #'OTPTBSCertificate'{serialNumber = 9, extensions = asn1_NOVALUE,
                               issuer = {rdnSequence, []}},
    Cert = #'OTPCertificate'{tbsCertificate = TBS},
    {{dn, _}, 9} = make_cache_key(Cert).

-endif.
