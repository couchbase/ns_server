%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc jwt_issuer

-module(jwt_issuer).

-include("ns_common.hrl").
-include("rbac.hrl").
-include("jwt.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([chronicle_upgrade_to_85/1,
         name/0,
         issue/3,
         settings/0]).

-spec name() -> binary().
name() ->
    <<"ns_server">>.

%% Every FIPS module approves ES256.
generate_keys() ->
    {_, Map} = jose_jwk:to_map(jose_jwk:generate_key({ec, <<"P-256">>})),
    Map.

%% Keys created before 8.5 are Ed25519.
signing_alg(#{<<"kty">> := <<"EC">>}) -> 'ES256';
signing_alg(#{<<"kty">> := <<"OKP">>}) -> 'EdDSA'.

%% The key is created only here, so ES256 starts exactly at 8.5 compat.
%% Fusion buckets need 8.5 compat, so no token signed with the old key is in
%% use when it is replaced.
-spec chronicle_upgrade_to_85(term()) -> term().
chronicle_upgrade_to_85(ChronicleTxn) ->
    chronicle_upgrade:set_key(?JWT_SIGNING_KEYS_KEY, generate_keys(),
                              ChronicleTxn).

get_jwk() ->
    case chronicle_kv:get(kv, ?JWT_SIGNING_KEYS_KEY) of
        {ok, {Map, _}} ->
            {ok, Map};
        {error, not_found} ->
            {error, keys_are_not_setup}
    end.

-spec issue(rbac_user_id(), [rbac_role()], integer()) ->
          {ok, binary()} | {error, keys_are_not_setup}.
issue(User, Roles, LifetimeSec) ->
    case get_jwk() of
        {ok, JWKMap} ->
            Now = erlang:system_time(second),
            JWT = #{<<"iss">> => name(),
                    <<"exp">> => Now + LifetimeSec,
                    <<"sub">> => list_to_binary(User),
                    <<"aud">> => <<"ns_server_internal">>,
                    <<"roles">> =>
                        [menelaus_web_rbac:role_to_binary(R) || R <- Roles]
                   },
            JWK = jose_jwk:from_map(JWKMap),
            JWS = jose_jwt:sign(
                    JWK, #{<<"alg">> => atom_to_binary(signing_alg(JWKMap))},
                    JWT),
            {_, CompactJWS} = jose_jws:compact(JWS),
            {ok, CompactJWS};
        Error ->
            Error
    end.

-spec settings() -> map().
settings() ->
    case get_jwk() of
        {ok, JWKMap} ->
            PEM = jose_jwk:to_pem(jose_jwk:to_public(JWKMap)),
            #{
              <<"ns_server">> =>
                  #{signing_algorithm => signing_alg(JWKMap),
                    public_key_source => pem,
                    public_key => PEM,
                    expiry_leeway_s => 0,
                    audience_handling => any,
                    audiences => [<<"ns_server_internal">>],
                    jit_provisioning => true
                   }
             };
        _Error ->
            #{}
    end.

-ifdef(TEST).
issue_test_() ->
    {foreach, fun issue_setup/0, fun issue_teardown/1,
     [{"ES256 key", fun () -> issue_and_verify(generate_keys()) end},
      {"Ed25519 key from before 8.5",
       fun () -> issue_and_verify(ed25519_keys()) end}]}.

upgrade_to_85_test_() ->
    {foreach, fun fake_chronicle_kv:setup/0,
     fun (_) -> fake_chronicle_kv:teardown() end,
     [{"replaces the Ed25519 key",
       fun () -> upgrade_to_85_t(ed25519_keys()) end},
      {"creates the key on a fresh cluster",
       fun () -> upgrade_to_85_t(undefined) end}]}.

ed25519_keys() ->
    {_, Map} = jose_jwk:to_map(jose_jwk:generate_key({okp, 'Ed25519'})),
    Map.

issue_setup() ->
    fake_ns_config:setup(),
    fake_ns_config:update_snapshot({node, node() ,is_enterprise}, true),

    meck:new(chronicle_compat_events, [passthrough]),
    meck:expect(chronicle_compat_events, subscribe, fun(_) -> ok end),
    fake_chronicle_kv:setup(),
    fake_chronicle_kv:update_snapshot(ns_bucket:root(), []),

    {ok, CachePid} = jwt_cache:start_link(),
    %% A cache crash then fails the test, not the eunit runner
    unlink(CachePid),
    CachePid.

issue_teardown(CachePid) ->
    gen_server:stop(CachePid),
    fake_chronicle_kv:teardown(),
    fake_ns_config:teardown(),
    meck:unload(chronicle_compat_events).

issue_and_verify(Keys) ->
    fake_chronicle_kv:update_snapshot(?JWT_SIGNING_KEYS_KEY, Keys),
    jwt_cache ! internal_key_update,
    gen_server:call(jwt_cache, sync, 1000),

    RV = issue("@test", [<<"admin">>, <<"metakv2_access">>], 1000),
    ?assertMatch({ok, _}, RV),
    {ok, TokenBin} = RV,
    ?assertEqual(atom_to_binary(signing_alg(Keys)),
                 maps:get(<<"alg">>,
                          jose:decode(jose_jws:peek_protected(TokenBin)))),
    RV1 = jwt_auth:authenticate(binary_to_list(TokenBin)),
    ?assertMatch({ok, #authn_res{type = tmp,
                                 session_id = undefined,
                                 authenticated_identity = {"@test", external},
                                 identity = {"@test", external},
                                 extra_groups = [],
                                 extra_roles = [<<"admin">>, <<"metakv2_access">>],
                                 expiration_datetime_utc = _,
                                 password_expired = false}, _}, RV1).

upgrade_to_85_t(OldKeys) ->
    OldKeys =:= undefined orelse
        fake_chronicle_kv:update_snapshot(?JWT_SIGNING_KEYS_KEY, OldKeys),
    ?assertMatch(
       {ok, _},
       chronicle_kv:txn(
         kv, fun (Txn) ->
                     chronicle_upgrade:build_commit(
                       chronicle_upgrade_to_85({#{}, Txn}))
             end)),
    {ok, {Keys, _}} = chronicle_kv:get(kv, ?JWT_SIGNING_KEYS_KEY),
    ?assertEqual('ES256', signing_alg(Keys)).

-endif.
