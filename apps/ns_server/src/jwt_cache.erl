%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

%% @doc
%% This module implements the JWT key cache responsible for managing JWKS (JSON
%% Web Key Set) for jwks_uri issuers.
%%
%% The cache is refreshed in the following ways:
%%    - On-demand refresh:
%%      * If a key lookup fails or is expired, a refresh is attempted
%%      * A cooldown period of 1 minute prevents excessive network requests
%%    - Periodic refresh:
%%      * Background timer refreshes all JWKS URIs periodically
%%      * Random jitter prevents all nodes from refreshing at the same time
%%      * Settings changes trigger a refresh
%%   All updates are serialized via gen_server.
%%   All updates are atomic. Old keys are removed and replaced with new keys for
%%   a given issuer in a single operation.
%%
%% Consistency:
%% - Each node maintains its own cache and caches are refreshed independently
%%   The refresh times need not be consistent across nodes if a node restarts,
%%   for instance.
-module(jwt_cache).
-behaviour(gen_server).

-include("ns_common.hrl").
-include("jwt.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([start_link/0,
         get_jwk/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(cache_state, {
                      refresh_timer_ref :: undefined | reference(),
                      refresh_interval_ms :: undefined | pos_integer()
                     }).

%% Cache entry for a single JWKS URI issuer
-record(jwks_cache_entry, {
                           kid_to_jwk :: jwt_kid_to_jwk(),
                           fetch_time :: integer(),
                           expiry :: integer()
                          }).

-define(JWKS_DEFAULT_EXPIRY_S, 6 * 60 * 60). %% 6 hours
-define(JWKS_SYNC_TIMEOUT_MS, 10000). %% 10 seconds
-define(JWKS_COOLDOWN_INTERVAL_MS, 60000). %% 1 minute
-define(JWKS_FETCH_RETRY_COUNT, 1).
-define(JWKS_REFRESH_JITTER_MS, 30000). %% 30 seconds of maximum jitter
-define(JWKS_REFRESH_TIMEOUT_MS, 90000).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec get_jwk(IssuerProps :: map(), Kid :: binary() | undefined) ->
          {ok, jose_jwk:key()} | {error, binary()}.
%% Static JWKS - direct lookup from settings
get_jwk(#{public_key_source := jwks, jwks := {_, KidToJWKMap}}, Kid) ->
    get_key_from_map(KidToJWKMap, Kid);
%% Dynamic JWKS URI - lookup from cache with retry if needed
get_jwk(#{public_key_source := jwks_uri} = Props, Kid) ->
    get_jwk_with_retry(Props, Kid, ?JWKS_FETCH_RETRY_COUNT).

-spec get_jwk_with_retry(IssuerProps :: map(), Kid :: binary() | undefined,
                         RetryCount :: integer()) ->
          {ok, jose_jwk:key()} | {error, binary()}.
get_jwk_with_retry(#{public_key_source := jwks_uri} = Props, Kid, RetryCount) ->
    Issuer = maps:get(name, Props),
    Map = case ets:lookup(?MODULE, Issuer) of
              [{Issuer, #jwks_cache_entry{kid_to_jwk = KidToJWKMap,
                                          expiry = Expiry}}] ->
                  case erlang:monotonic_time(millisecond) > Expiry of
                      true ->
                          ?log_debug("JWT issuer ~p entries have expired",
                                     [Issuer]),
                          #{};
                      false -> KidToJWKMap
                  end;
              [] -> #{}
          end,
    case get_key_from_map(Map, Kid) of
        {ok, JWK} -> {ok, JWK};
        {error, _} when RetryCount > 0 ->
            gen_server:call(?MODULE, {refresh_issuer, Props},
                            ?JWKS_REFRESH_TIMEOUT_MS),
            get_jwk_with_retry(Props, Kid, RetryCount - 1);
        {error, Reason} ->
            {error, Reason}
    end.

-spec get_key_from_map(jwt_kid_to_jwk(), binary() | undefined) ->
          {ok, jose_jwk:key()} | {error, binary()}.
get_key_from_map(KidToJWKMap, Kid) ->
    case maps:find(Kid, KidToJWKMap) of
        {ok, JWKMap} ->
            {ok, jose_jwk:from_map(JWKMap)};
        error when is_binary(Kid) ->
            {error, <<"Key with kid: ", Kid/binary, " not found">>};
        error ->
            {error, <<"Key (no kid specified) not found">>}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Extract the max-age from the Cache-Control header. This is used to set the
%% expiry time for the JWKS in the cache.
-spec extract_max_age(CacheControl :: binary()) -> integer() | undefined.
extract_max_age(CacheControl) ->
    case re:run(CacheControl, "max-age=(\\d+)", [{capture, [1], list}]) of
        {match, [MaxAgeStr]} ->
            try
                list_to_integer(MaxAgeStr)
            catch
                error:badarg ->
                    ?log_warning("Invalid max-age value in Cache-Control: ~p",
                                 [MaxAgeStr]),
                    undefined
            end;
        nomatch ->
            undefined
    end.

-spec extract_connect_options(URL :: string(), IssuerProps :: map()) -> list().
extract_connect_options(URL, IssuerProps) ->
    AddrSettings =
        case maps:get(jwks_uri_address_family, IssuerProps, undefined) of
            undefined -> [];
            AF -> [AF]
        end,

    Opts =
        case URL of
            "https://" ++ _ ->
                case maps:get(jwks_uri_tls_verify_peer, IssuerProps) of
                    true ->
                        {_, Certs} = maps:get(jwks_uri_tls_ca, IssuerProps),
                        CACerts = Certs ++ ns_server_cert:trusted_CAs(der),
                        [{verify, verify_peer}, {cacerts, CACerts},
                         {depth, ?ALLOWED_CERT_CHAIN_LENGTH}] ++
                            case maps:get(jwks_uri_tls_sni, IssuerProps, "") of
                                "" -> [];
                                SNI -> [{server_name_indication, SNI}]
                            end;
                    false ->
                        [{verify, verify_none}]
                end;
            "http://" ++ _ ->
                []
        end ++ AddrSettings,

    ExtraOpts = maps:get(jwks_uri_tls_extra_opts, IssuerProps, []),
    misc:update_proplist_relaxed(Opts, ExtraOpts).

-spec fetch_jwks(IssuerProps :: map()) ->
          {Json :: binary(), MaxAge :: integer() | undefined} | {error, term()}.
fetch_jwks(IssuerProps) ->
    URL = maps:get(jwks_uri, IssuerProps),
    TimeoutMs = maps:get(jwks_uri_http_timeout_ms, IssuerProps),
    try
        ConnectOptions = extract_connect_options(URL, IssuerProps),
        case rest_utils:request(<<"jwks">>, URL, "GET", [], <<>>, TimeoutMs,
                                [{connect_options, ConnectOptions}]) of
            {ok, {{200, _}, RespHeaders, Bin}} ->
                LowercaseHeaders = [{string:lowercase(K), V} ||
                                       {K, V} <- RespHeaders],
                MaxAge = case proplists:get_value("cache-control",
                                                  LowercaseHeaders) of
                             undefined -> undefined;
                             CacheCtrl -> extract_max_age(CacheCtrl)
                         end,
                ?log_debug("Received JWKS from ~s:~n~s MaxAge:~p",
                           [URL, Bin, MaxAge]),
                {Bin, MaxAge};
            {ok, {{Status, _Reason}, _RespHeaders, _RespBody}} ->
                throw({rest_failed, URL, {status, Status}});
            {error, Reason} ->
                throw({rest_failed, URL, {error, Reason}})
        end
    catch
        throw:Error ->
            ?log_error("Failed to get JWKS from ~p.~nReason: ~p", [URL, Error]),
            {error, Error}
    end.

-spec fetch_and_parse_jwks(IssuerProps :: map()) ->
          {ok, #jwks_cache_entry{}} | {error, binary()}.
fetch_and_parse_jwks(IssuerProps = #{public_key_source := jwks_uri}) ->
    FetchTime = erlang:monotonic_time(millisecond),
    case fetch_jwks(IssuerProps) of
        {error, _} ->
            {error, <<"JWKS fetch failed">>};
        {JwksJson, MaxAge} ->
            case validate_jwks(JwksJson, IssuerProps) of
                {ok, KidToJWKMap} ->
                    Expiry = FetchTime +
                        (case MaxAge of
                             undefined -> ?JWKS_DEFAULT_EXPIRY_S;
                             Age -> Age
                         end) * 1000,
                    {ok, #jwks_cache_entry{
                            kid_to_jwk = KidToJWKMap,
                            fetch_time = FetchTime,
                            expiry = Expiry
                           }};
                {error, _} ->
                    {error, <<"Invalid JWKS">>}
            end
    end.

-spec check_cooldown(Issuer :: string()) -> ok | {error, cooldown}.
check_cooldown(Issuer) ->
    Now = erlang:monotonic_time(millisecond),
    case ets:lookup(?MODULE, Issuer) of
        [{_, #jwks_cache_entry{fetch_time = LastTime}}]
          when Now - LastTime < ?JWKS_COOLDOWN_INTERVAL_MS ->
            ?log_debug("JWT issuer ~p cooldown period not yet met", [Issuer]),
            {error, cooldown};
        _ ->
            ok
    end.

-spec validate_jwks(JwksJson :: binary(), IssuerProps :: map()) ->
          {ok, jwt_kid_to_jwk()} | {error, term()}.
validate_jwks(JwksJson, IssuerProps) ->
    Issuer = maps:get(name, IssuerProps),
    try jose:decode(JwksJson) of
        JsonMap ->
            Algo = maps:get(signing_algorithm, IssuerProps),
            case menelaus_web_jwt_key:validate_jwks_algorithm(JsonMap, Algo) of
                {ok, KidToJWKMap} ->
                    ?log_debug("Parsed JWKS for ~p~n", [Issuer]),
                    {ok, KidToJWKMap};
                {error, Reason} ->
                    ?log_error("Error validating JWKS: ~p", [Reason]),
                    {error, Reason}
            end
    catch _:_ ->
            ?log_error("Error parsing JWKS:~p", [JwksJson]),
            {error, <<"Invalid JWKS JSON">>}
    end.

schedule_refresh(Interval) ->
    Jitter = rand:uniform(?JWKS_REFRESH_JITTER_MS),
    erlang:send_after(Interval + Jitter, self(), periodic_refresh).

cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> erlang:cancel_timer(Ref).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?MODULE, [named_table, set, public, {read_concurrency, true}]),
    Self = self(),
    chronicle_compat_events:subscribe(
      fun (jwt_settings) -> Self ! settings_update;
          (_) -> ok
      end),
    self() ! settings_update,
    {ok, #cache_state{}}.

%% On demand node refresh. When a lookup fails, the node will refresh the JWKS.
handle_call({refresh_issuer, #{name := Issuer} = Props}, _From, State) ->
    case check_cooldown(Issuer) of
        {error, cooldown} ->
            {reply, {error, cooldown}, State};
        ok ->
            case fetch_and_parse_jwks(Props) of
                {ok, Entry} ->
                    ets:insert(?MODULE, {Issuer, Entry}),
                    {reply, ok, State};
                {error, Reason} ->
                    {reply, {error, Reason}, State}
            end
    end;
handle_call(sync, _From, State) ->
    {reply, ok, State};
handle_call(Request, _From, State) ->
    ?log_warning("Unhandled call: ~p", [Request]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?log_warning("Unhandled cast: ~p", [Msg]),
    {noreply, State}.

handle_info(settings_update,
            #cache_state{refresh_timer_ref = TimerRef} = State) ->
    ?log_debug("JWT settings init/change, invalidating cache.", []),
    ets:delete_all_objects(?MODULE),
    misc:flush(settings_update),
    misc:flush(periodic_refresh),
    cancel_timer(TimerRef),

    case chronicle_kv:get(kv, jwt_settings) of
        {ok, {#{enabled := true, issuers := IssuersMap} = Settings, _Rev}} ->
            HasJwksUri =
                lists:any(fun(#{public_key_source := jwks_uri}) -> true;
                             (_) -> false
                          end, maps:values(IssuersMap)),
            case HasJwksUri of
                true ->
                    Interval =
                        maps:get(jwks_uri_refresh_interval_s, Settings) * 1000,
                    %% Schedule the first refresh immediately to populate the
                    %% cache, subsequent refreshes will use the configured
                    %% interval with jitter
                    {noreply, State#cache_state{
                                refresh_timer_ref = schedule_refresh(0),
                                refresh_interval_ms = Interval}};
                false ->
                    {noreply,
                     State#cache_state{refresh_timer_ref = undefined,
                                       refresh_interval_ms = undefined}}
            end;
        _ ->
            {noreply, State#cache_state{refresh_timer_ref = undefined,
                                        refresh_interval_ms = undefined}}
    end;
handle_info(periodic_refresh,
            #cache_state{refresh_timer_ref = Ref} = State) ->
    misc:flush(periodic_refresh),
    cancel_timer(Ref),
    ?log_debug("Initiating JWKS refresh.", []),

    case chronicle_kv:get(kv, jwt_settings) of
        {ok, {#{enabled := true, issuers := IssuersMap}, _}} ->
            maps:foreach(
              fun(Issuer, #{public_key_source := jwks_uri} = Props) ->
                      case fetch_and_parse_jwks(Props#{name => Issuer}) of
                          {ok, Entry} -> ets:insert(?MODULE, {Issuer, Entry});
                          {error, _} -> ok
                      end;
                 (_, _) -> ok
              end, IssuersMap),

            case State#cache_state.refresh_interval_ms of
                undefined -> {noreply, State};
                Interval ->
                    {noreply, State#cache_state{
                                refresh_timer_ref = schedule_refresh(Interval)}}
            end;
        _ ->
            {noreply, State}
    end;
handle_info(Request, State) ->
    ?log_warning("Unhandled info: ~p", [Request]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-ifdef(TEST).

cache_lookup_test() ->
    meck:new(chronicle_compat_events, [passthrough]),
    meck:new(chronicle_kv, [passthrough]),
    meck:expect(chronicle_compat_events, subscribe, fun(_) -> ok end),
    meck:expect(chronicle_kv, get,
                fun(kv, jwt_settings) ->
                        {ok, {#{enabled => true,
                                issuers => #{}}, '_'}}
                end),
    TestJWKS =
        <<
          "{",
          "    \"keys\": [",
          "        {",
          "            \"kty\": \"EC\",",
          "            \"crv\": \"P-256\",",
          "            \"x\": \"wS5Whg7la7uUcmgyDn2UrA4ZpUF7tBsCidd90AkYn00\",",
          "            \"y\": \"_XPJU549tLUCFgaKUD9IbBQDSweeT4t7EEXsC3sJHwM\",",
          "            \"alg\": \"ES256\",",
          "            \"use\": \"sig\",",
          "            \"kid\": \"key1\"",
          "        },",
          "        {",
          "            \"kty\": \"EC\",",
          "            \"crv\": \"P-256\",",
          "            \"x\": \"A29hrKJ7zXQ3P8iV5n0qLmBCm2T4NB9eQo5E6J8gXx0\",",
          "            \"y\": \"B5J3F92mLvX0hTLKo7M4Qj9VwY6eTR3mPk0xvZKfXQY\",",
          "            \"alg\": \"ES256\",",
          "            \"use\": \"sig\",",
          "            \"kid\": \"key2\"",
          "        }",
          "    ]",
          "}"
        >>,

    meck:new(rest_utils, [passthrough]),
    meck:expect(rest_utils, request,
                fun(<<"jwks">>, "https://www.googleapis.com/oauth2/v3/certs",
                    "GET", [], <<>>, 5000, _) ->
                        {ok, {{200, []}, [{"cache-control",
                                           "max-age=21600"}], TestJWKS}}
                end),
    IssuerProps = #{
                    name => "test1",
                    public_key_source => jwks_uri,
                    jwks_uri => "https://www.googleapis.com/oauth2/v3/certs",
                    signing_algorithm => 'ES256',
                    jwks_uri_http_timeout_ms => 5000,
                    jwks_uri_tls_verify_peer => false
                   },

    StartTime = erlang:monotonic_time(millisecond),

    {ok, _Pid} = jwt_cache:start_link(),

    {ok, JWK} = get_jwk(IssuerProps, <<"key1">>),
    ?assert(is_tuple(JWK)),
    ?assertEqual(jose_jwk, element(1, JWK)),
    [{_, #jwks_cache_entry{kid_to_jwk = KidToJWKMap,
                           fetch_time = FetchTime,
                           expiry = Expiry}}] = ets:lookup(?MODULE, "test1"),
    ?assert(is_map(KidToJWKMap)),
    ?assertEqual(2, maps:size(KidToJWKMap)),
    ?assert(Expiry > FetchTime),

    %% First lookup should fetch
    {ok, JWK1} = get_jwk(IssuerProps, <<"key1">>),
    ?assertEqual(meck:num_calls(rest_utils, request, ['_', '_', '_', '_', '_',
                                                      '_', '_']), 1),

    %% Set the cache entry to expired
    ExpiredEntry = {"test1", #jwks_cache_entry{kid_to_jwk = KidToJWKMap,
                                               fetch_time = FetchTime,
                                               expiry = StartTime}},
    ets:insert(?MODULE, ExpiredEntry),

    %% Cooldown period is not met, should not fetch
    {error, _} = get_jwk(IssuerProps, <<"key2">>),
    ?assertEqual(meck:num_calls(rest_utils, request, ['_', '_', '_', '_', '_',
                                                      '_', '_']), 1),

    %% Invalidate the cache and wait until it is handled
    jwt_cache ! settings_update,
    gen_server:call(jwt_cache, sync, 1000),
    ?assertEqual(0, ets:info(?MODULE, size)),

    %% Should trigger fetch
    {ok, JWK2} = get_jwk(IssuerProps, <<"key2">>),
    ?assertEqual(meck:num_calls(rest_utils, request, ['_', '_', '_', '_', '_',
                                                      '_', '_']), 2),

    %% Cache hits, should not fetch
    {ok, JWK2} = get_jwk(IssuerProps, <<"key2">>),
    {ok, JWK1} = get_jwk(IssuerProps, <<"key1">>),
    ?assertEqual(meck:num_calls(rest_utils, request, ['_', '_', '_', '_', '_',
                                                      '_', '_']), 2),

    meck:unload(chronicle_kv),
    meck:unload(chronicle_compat_events),
    meck:unload(rest_utils),
    gen_server:stop(jwt_cache).

-endif.
