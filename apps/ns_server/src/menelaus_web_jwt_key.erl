%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

%% @doc Key validation functions for JWT configuration

-module(menelaus_web_jwt_key).

-include("ns_common.hrl").
-include_lib("public_key/include/public_key.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([validate_jwks_algorithm/2,
         validate_jwks_keys/2,
         validate_key_algorithm/2,
         algorithm_type/1,
         ec_params_to_algorithm/1,
         get_key_from_pem_contents/1,
         validate_shared_secret/2]).

%% Types for key validation
-type pubkey() ::
        #'RSAPublicKey'{} |
        {#'ECPoint'{}, {namedCurve, term()}} |
        #'SubjectPublicKeyInfo'{
           algorithm :: #'AlgorithmIdentifier'{
                           algorithm :: ?'id-Ed25519' | ?'id-Ed448'}}.

-export_type([pubkey/0]).

algorithm_type(Algo) ->
    case Algo of
        "RS" ++ _ -> "RSA";
        "PS" ++ _ -> "RSA";
        "ES" ++ _ -> "ECDSA";
        "EdDSA" -> "EdDSA"
    end.

ec_params_to_algorithm(secp256k1) ->
    "ES256K";
ec_params_to_algorithm(secp256r1) ->
    "ES256";
ec_params_to_algorithm(secp384r1) ->
    "ES384";
ec_params_to_algorithm(secp521r1) ->
    "ES512";
ec_params_to_algorithm(Parameters) when is_tuple(Parameters) ->
    ec_params_to_algorithm(pubkey_cert_records:namedCurves(Parameters)).

-spec validate_key_algorithm(Key :: pubkey() | {error, string()},
                             Algorithm :: string()) -> ok | {error, string()}.
validate_key_algorithm(Key, Algorithm) ->
    Algo = algorithm_type(Algorithm),
    case {Algo, Key} of
        {_, {error, Y}} -> {error, Y};
        {"RSA", #'RSAPublicKey'{modulus = N}} ->
            Bits = bit_size(binary:encode_unsigned(N)),
            %% NIST has mandated a minimum length of 2048 bits since 2015.
            %% OpenSSL doesn't recommend lengths longer than 16384 bits.
            %% The only reason to limit it is key generation/verification time.
            MinBits = 2048,
            MaxBits = 16384,
            case Bits of
                X when X >= MinBits andalso X =< MaxBits -> ok;
                Y  -> {error,
                       lists:flatten(
                         io_lib:format("The specified key has ~p bits. Key "
                                       "length should be between ~p and ~p",
                                       [Y, MinBits, MaxBits]))}
            end;
        {"RSA", _} ->
            {error, lists:flatten(
                      io_lib:format("Invalid key for ~p signing algorithm",
                                    [Algorithm]))};
        {"ECDSA", {#'ECPoint'{}, {namedCurve, Params}}} ->
            case ec_params_to_algorithm(Params) of
                X when X =:= Algorithm -> ok;
                Y -> {error,
                      lists:flatten(
                        io_lib:format("Mismatch between algorithm in key:~p "
                                      "and signing algorithm:~p",
                                      [Y, Algorithm]))}
            end;
        {"ECDSA", _} ->
            {error, lists:flatten(
                      io_lib:format("Invalid key for ~p signing algorithm",
                                    [Algorithm]))};
        {"EdDSA", #'SubjectPublicKeyInfo'{
                     algorithm =
                         #'AlgorithmIdentifier'{
                            algorithm = ?'id-Ed25519'
                           }}} -> ok;
        {"EdDSA", #'SubjectPublicKeyInfo'{
                     algorithm =
                         #'AlgorithmIdentifier'{
                            algorithm = ?'id-Ed448'
                           }}} -> ok;
        {"EdDSA", _} ->
            {error, lists:flatten(
                      io_lib:format("Invalid key for ~p signing algorithm",
                                    [Algorithm]))}
    end.

-spec validate_jwks_keys([pubkey()], string()) -> ok | {error, string()}.
validate_jwks_keys([], _Algorithm) -> ok;
validate_jwks_keys([Key | Rest], Algorithm) ->
    case validate_key_algorithm(Key, Algorithm) of
        ok -> validate_jwks_keys(Rest, Algorithm);
        {error, Reason} -> {error, Reason}
    end.

-spec validate_jwks_algorithm(map(), string()) -> ok | {error, string()}.
validate_jwks_algorithm(JSONMap, Algo) ->
    case parse_jwks(JSONMap) of
        {error, Reason} -> {error, Reason};
        {ok, JWKSet} -> validate_jwks_keys_for_algorithm(JWKSet, Algo)
    end.

-spec parse_jwks(map()) -> {ok, [jose_jwk:key()]} | {error, string()}.
parse_jwks(JSONMap) ->
    try jose_jwk:from(JSONMap) of
        {error, _} -> {error, "Invalid JWKS"};
        %% Multiple keys require a 'kid' to identify which one to use
        #jose_jwk{keys = {jose_jwk_set, [_, _|_] = Items}} ->
            validate_jwks_set(Items, JSONMap);
        %% Single key in a key set
        #jose_jwk{keys = {jose_jwk_set, [Item]}} ->
            {ok, [Item]};
        %% Single key JWK (as opposed to a single key JWKS)
        JWK ->
            {ok, [JWK]}
    catch T:E:S ->
            ?log_error("exception in jose_jwk:from JWKS:~n~p", [{T, E, S}]),
            {error, "Invalid JWKS"}
    end.

-spec validate_jwks_set([jose_jwk:key()], map()) -> {ok, [jose_jwk:key()]} |
          {error, string()}.
validate_jwks_set(Items, JSONMap) ->
    case maps:get(<<"keys">>, JSONMap) of
        Keys when is_list(Keys) ->
            case lists:all(fun(Key) ->
                                   is_map(Key) andalso
                                       maps:is_key(<<"kid">>, Key)
                           end, Keys) of
                true -> {ok, Items};
                false -> {error, "Missing 'kid' in JWKS key"}
            end;
        _ -> {error, "Invalid 'keys' array"}
    end.

-spec validate_jwks_keys_for_algorithm([jose_jwk:key()], string()) ->
          ok | {error, string()}.
validate_jwks_keys_for_algorithm(JWKSet, Algo) ->
    case lists:filtermap(
           fun(JWK) ->
                   case lists:member(list_to_binary(Algo),
                                     jose_jwk:verifier(JWK)) of
                       true ->
                           {_, Key} = jose_jwk:to_key(JWK),
                           {true, Key};
                       false -> false
                   end
           end, JWKSet) of
        [] -> {error,
               lists:flatten(io_lib:format("No suitable keys in JWKS "
                                           "for signing algorithm: ~p",
                                           [Algo]))};
        ValidKeys -> validate_jwks_keys(ValidKeys, Algo)
    end.

%% @doc Validates a shared secret for HMAC algorithms (HS256, HS384, HS512).
%% The secret must be valid UTF-8 and meet minimum length requirements based on
%% the algorithm's bit size.
-spec validate_shared_secret(string(), string()) ->
          {ok, {value, jose_jwk:key()}} | {error, string()}.
validate_shared_secret(Secret, "HS" ++ Length) ->
    %% See JWA RFC7518 Section 3.2. A key of the same size as the hash output
    %% (for instance, 256 bits for "HS256") or larger MUST be used.
    MinLength = list_to_integer(Length) / 8,
    %% See RFC4868 Section 2.1.2.
    %% Providing keys longer than the block size doesn't increase security. The
    %% key will be hashed to fit the block length before use.
    MaxLength = case Length of
                    "256" -> 512;
                    "384" -> 1024;
                    "512" -> 1024
                end,

    %% Mochiweb converts the utf8 string to a list, which isn't
    %% correct, so we need to undo that conversion here.
    case unicode:characters_to_binary(Secret) of
        {incomplete, _, _} ->
            {error, "Incomplete utf8 shared secret"};
        {error, _, _} ->
            {error, "Ill-formed utf8 shared secret"};
        BinaryChars ->
            SecretLength = string:length(BinaryChars),
            case SecretLength < MinLength orelse SecretLength > MaxLength of
                true ->
                    Msg = "Shared secret length must be in the range from ~p to"
                        "~p inclusive",
                    {error, lists:flatten(io_lib:format(
                                            Msg,
                                            [MinLength, MaxLength]))};
                false ->
                    {ok, {value, jose_jwk:from_oct(list_to_binary(Secret))}}
            end
    end.

%% PEM and Certificate handling functions
%% Key Processing Flow:
%%
%% 1. Certificate Processing Path:
%%    get_key_from_pem_contents(PemBin)
%%    ↓
%%    [{'Certificate', DER, not_encrypted}] = public_key:pem_decode(PemBin)
%%    ↓
%%    decode_key({'Certificate', _, not_encrypted})
%%    ↓
%%    #'Certificate'{} = public_key:pem_entry_decode(Entry)
%%    ↓
%%    get_key_from_certificate extracts #'SubjectPublicKeyInfo'{}
%%    ↓
%%    get_key_from_spki re-encodes to PEM format
%%    ↓
%%    Process through raw PEM path (below)
%%
%% 2. Raw PEM Processing Path:
%%    get_key_from_pem_contents(PemBin)
%%    ↓
%%    decode_key(PEMEntry)
%%    ↓
%%    normalize_key(DecodedKey) ->
%%    - RSAPublicKey
%%    - {ECPoint, Params}
%%    - SubjectPublicKeyInfo (EdDSA)

-type pem_entry() :: {'Certificate' | 'SubjectPublicKeyInfo' | 'RSAPublicKey' |
                      'ECPrivateKey', binary(), 'not_encrypted'}.

-spec get_key_from_pem_contents(binary()) -> pubkey() | {error, string()}.
get_key_from_pem_contents(PemBin) ->
    try public_key:pem_decode(PemBin) of
        [PemEntry] -> decode_key(PemEntry);
        [_|_] -> {error, "Too many PEM entries"}
    catch T:E:S ->
            ?log_error("Unknown error while parsing PEM contents:~n~p",
                       [{T, E, S}]),
            {error, "Invalid key"}
    end.

-spec decode_key(pem_entry()) -> pubkey() | {error, string()}.
decode_key({'Certificate', _, not_encrypted} = Entry) ->
    try public_key:pem_entry_decode(Entry) of
        #'Certificate'{} = Cert -> get_key_from_certificate(Cert)
    catch T:E:S ->
            ?log_error("Unknown error while parsing cert:~n~p", [{T, E, S}]),
            {error, "Invalid certificate"}
    end;
decode_key(Entry) ->
    try public_key:pem_entry_decode(Entry) of
        Key -> normalize_key(Key)
    catch T:E:S ->
            ?log_error("Unknown error while parsing PEM entry:~n~p",
                       [{T, E, S}]),
            decode_spki_from_der(Entry)
    end.

%% Normalize decoded keys to consistent format
-spec normalize_key(term()) -> pubkey() | {error, string()}.

%% The EcpkParameters should have been decoded by pem_entry_decode.
%% If not, decode them to get the named curve for ECDSA algorithms.
normalize_key(#'SubjectPublicKeyInfo'{
                 algorithm = #'AlgorithmIdentifier'{
                                algorithm = ?'id-ecPublicKey',
                                parameters = ECParameters
                               },
                 subjectPublicKey = ECPublicKey
                }) ->
    {#'ECPoint'{point = ECPublicKey},
     public_key:der_decode('EcpkParameters', ECParameters)};
normalize_key({#'ECPoint'{}, _} = Key) -> Key;
normalize_key(#'SubjectPublicKeyInfo'{} = Key) -> Key;
normalize_key(#'RSAPublicKey'{} = Key) -> Key;

%% Don't allow private keys (RSAPrivateKey, ECPrivateKey, PrivateKeyInfo) or
%% unrecognized types.
normalize_key(_) -> {error, "Invalid key"}.

-spec decode_spki_from_der(Entry :: {'SubjectPublicKeyInfo', binary(),
                                     'not_encrypted'}) ->
          pubkey() | {error, string()}.
decode_spki_from_der({'SubjectPublicKeyInfo', Der, _}) when is_binary(Der) ->
    %% For EdDSA curves (Ed25519 and Ed448), public_key:pem_entry_decode throws
    %% an error while attempting der_decode('EcpkParameters, asn1_NOVALUE).
    %% EdDSA curves never contain parameters in AlgorithmIdentifier (RFC 8410).
    %% Ignore the error while attempting to decode EcpkParameters of NULL.
    %% See Erlang/OTP Issue #9009.
    try public_key:der_decode('SubjectPublicKeyInfo', Der)
    catch T:E:S ->
            ?log_error("Unknown error der_decode:~n~p", [{T, E, S}]),
            {error, "Invalid key"}
    end;
decode_spki_from_der(_) ->
    {error, "Invalid key"}.

-spec get_key_from_certificate(#'Certificate'{}) -> pubkey() |
          {error, string()}.
get_key_from_certificate(#'Certificate'
                         {tbsCertificate = #'TBSCertificate'
                          {subjectPublicKeyInfo = #'SubjectPublicKeyInfo'{} =
                               SubjectPublicKeyInfo}}) ->
    get_key_from_spki(SubjectPublicKeyInfo).

-spec get_key_from_spki(Info :: #'SubjectPublicKeyInfo'{} |
                                {'SubjectPublicKeyInfo', binary(),
                                 'not_encrypted'}) ->
          pubkey() | {error, string()}.

%% Handle already decoded SPKI record from certificates - re-encode to ensure
%% consistent processing through raw PEM path.
get_key_from_spki(#'SubjectPublicKeyInfo'{algorithm = #'AlgorithmIdentifier'{}}
                  = SubjectPublicKeyInfo) ->
    %% If Asn1Type is 'SubjectPublicKeyInfo', Entity must be either an
    %% RSA, DSA (not in use by JWT), ECDSA or EdDSA public key.
    try public_key:pem_entry_encode('SubjectPublicKeyInfo',
                                    SubjectPublicKeyInfo) of
        Encoded -> get_key_from_spki(Encoded)
    catch T:E:S ->
            ?log_error("Unknown error while encoding PEM entry:~n~p",
                       [{T, E, S}]),
            {error, "Invalid key"}
    end;

%% Handle raw PEM entry format - process through main decode path.
get_key_from_spki(PEMEntry = {'SubjectPublicKeyInfo',
                              DER, not_encrypted}) when is_binary(DER) ->
    decode_key(PEMEntry).
