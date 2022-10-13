%% @author Couchbase <info@couchbase.com>
%% @copyright 2014-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc access api for admin credentials

-module(ns_config_auth).

-include("ns_common.hrl").
-include("cut.hrl").

-export([authenticate/2,
         set_admin_credentials/2,
         set_admin_with_auth/2,
         get_user/1,
         get_password/1,
         get_password/2,
         get_password/3,
         get_special_passwords/2,
         admin_credentials_changed/2,
         get_admin_user_and_auth/0,
         get_admin_creds/1,
         is_system_provisioned/0,
         is_system_provisioned/1,
         new_password_hash/2,
         hash_password/2,
         check_hash/2]).

admin_cfg_key() ->
    rest_creds.

set_admin_credentials(User, Password) ->
    set_admin_with_auth(User, menelaus_users:build_auth([Password])).

set_admin_with_auth(User, Auth) ->
    ns_config:set(admin_cfg_key(), {User, {auth, Auth}}).

get_admin_user_and_auth() ->
    get_admin_user_and_auth(ns_config:latest()).

get_admin_user_and_auth(Config) ->
    {value, UserAuth} = ns_config:search(Config, admin_cfg_key()),
    UserAuth.

is_system_provisioned() ->
    is_system_provisioned(ns_config:latest()).

is_system_provisioned(Config) ->
    case get_admin_user_and_auth(Config) of
        {_, _} ->
            true;
        _ ->
            false
    end.

get_user(special) ->
    "@";
get_user(admin) ->
    case get_admin_user_and_auth() of
        {U, _} ->
            U;
        _ ->
            undefined
    end.
get_password(special) ->
    get_password(node(), special).

get_password(Node, special) ->
    get_password(Node, ns_config:latest(), special).

get_password(Node, Config, special) ->
    case get_special_passwords(Node, Config) of
        [] -> undefined;
        [Pass | _] -> Pass
    end.

get_special_passwords(Node, Config) when is_atom(Node)->
    case ns_config:search_node_prop(Node, Config, memcached, admin_pass) of
        undefined -> [];
        {v2, Passwords} -> Passwords;
        Password when is_list(Password) -> [Password]
    end.

get_salt_and_mac({password, {Salt, Mac}}) ->
    [{?HASH_ALG_KEY, ?SHA1_HASH},
     {?SALT_KEY, base64:encode(Salt)},
     {?HASHES_KEY, [base64:encode(Mac)]}];
get_salt_and_mac({auth, Auth}) ->
    menelaus_users:get_salt_and_mac(Auth).

get_admin_creds(Config) ->
    case get_admin_user_and_auth(Config) of
        {User, Auth} ->
            {User, get_salt_and_mac(Auth)};
        _ ->
            undefined
    end.

admin_credentials_changed(User, Password) ->
    case get_admin_creds(ns_config:latest()) of
        {User, HashInfo} ->
            not check_hash(HashInfo, Password);
        _ ->
            true
    end.

authenticate_special("@prometheus" = User, Password) ->
    prometheus_cfg:authenticate(User, Password);
authenticate_special([$@ | _] = User, Password) ->
    case get_special_passwords(node(), ns_config:latest()) of
        [] ->
            {error, temporary_failure};
        SpecPasswords ->
            case misc:compare_secure_many(Password, SpecPasswords) of
                true ->
                    {ok, {User, admin}};
                false ->
                    authenticate_admin(User, Password)
            end
    end;
authenticate_special(User, Password) ->
    authenticate_admin(User, Password).

authenticate(Username, Password) ->
    case authenticate_special(Username, Password) of
        {ok, Id} ->
            {ok, Id};
        {error, auth_failure} ->
            case menelaus_users:authenticate(Username, Password) of
                true ->
                    {ok, {Username, local}};
                false ->
                    %% This code can be removed when 7.0 is the minimum
                    %% supported release.
                    case is_bucket_auth(Username, Password) of
                        true ->
                            {ok, {Username, bucket}};
                        false ->
                            {error, auth_failure}
                    end
            end;
        {error, Reason} ->
            {error, Reason}
    end.

authenticate_admin(User, Password) ->
    case get_admin_user_and_auth() of
        null ->
            {ok, {User, admin}};
        {User, Auth} ->
            case check_hash(get_salt_and_mac(Auth), Password) of
                true ->
                    {ok, {User, admin}};
                false ->
                    {error, auth_failure}
            end;
        {_, _} ->
            {error, auth_failure}
    end.

check_hash(HashInfo, Password) ->
    Base64Hashes = proplists:get_value(?HASHES_KEY, HashInfo),
    Hashes = [base64:decode(H) || H <- Base64Hashes],
    Hash1 = hash_password(HashInfo, Password),
    misc:compare_secure_many(Hash1, Hashes).

new_password_hash(Type, Passwords) ->
    Info = new_hash_info(Type),
    Hashes = [base64:encode(hash_password(Info, P)) || P <- Passwords],
    [{?HASHES_KEY, Hashes} | Info].

new_hash_info(T) ->
    [{?HASH_ALG_KEY, T} | new_hash_info_int(T)].

new_hash_info_int(?ARGON2ID_HASH) ->
    SaltSize = enacl:pwhash_SALTBYTES(),
    [{?SALT_KEY, base64:encode(crypto:strong_rand_bytes(SaltSize))},
     {?ARGON_TIME_KEY,
        ns_config:read_key_fast(argon2id_time, ?DEFAULT_ARG2ID_TIME)},
     {?ARGON_MEM_KEY,
        ns_config:read_key_fast(argon2id_mem, ?DEFAULT_ARG2ID_MEM)},
     {?ARGON_THREADS_KEY, 1}]; %% we support only p=1 because enacl+libsodium always uses 1
new_hash_info_int(?PBKDF2_HASH) ->
    [{?SALT_KEY, base64:encode(crypto:strong_rand_bytes(64))},
     {?PBKDF2_ITER_KEY, ns_config:read_key_fast(pbkdf2_sha512_iterations,
                                                ?DEFAULT_PBKDF2_ITER)}];
new_hash_info_int(?SHA1_HASH) ->
    [{?SALT_KEY, base64:encode(crypto:strong_rand_bytes(16))}].

hash_password(HashInfo, Password) ->
    case proplists:get_value(?HASH_ALG_KEY, HashInfo) of
        ?ARGON2ID_HASH ->
            Salt = base64:decode(proplists:get_value(?SALT_KEY, HashInfo)),
            Ops = proplists:get_value(?ARGON_TIME_KEY, HashInfo),
            Mem = proplists:get_value(?ARGON_MEM_KEY, HashInfo),
            1 = proplists:get_value(?ARGON_THREADS_KEY, HashInfo),
            enacl:pwhash(Password, Salt, Ops, Mem, argon2id13);
        ?PBKDF2_HASH ->
            Salt = base64:decode(proplists:get_value(?SALT_KEY, HashInfo)),
            Iterations = proplists:get_value(?PBKDF2_ITER_KEY, HashInfo),
            scram_sha:pbkdf2(sha512, Password, Salt, Iterations);
        ?SHA1_HASH ->
            Salt = base64:decode(proplists:get_value(?SALT_KEY, HashInfo)),
            crypto:mac(hmac, sha, Salt, list_to_binary(Password))
    end.

is_bucket_auth(User, Password) ->
    case cluster_compat_mode:is_cluster_70() of
        true ->
            false;
        false ->
            case ns_bucket:get_bucket(User) of
                {ok, BucketConf} ->
                    case {proplists:get_value(auth_type, BucketConf),
                          proplists:get_value(sasl_password, BucketConf)} of
                        {none, _} ->
                            Password =:= "";
                        {sasl, P} ->
                            misc:compare_secure(Password, P)
                    end;
                not_present ->
                    false
            end
    end.
