%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2018 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% @doc implementation of server side SCRAM-SHA according to
%%      https://tools.ietf.org/html/rfc5802
%%      https://tools.ietf.org/html/rfc7804

-module(scram_sha).

-include("cut.hrl").

-export([start_link/0,
         authenticate/1,
         meta_header/0,
         get_resp_headers_from_req/1]).

%% callback for token_server
-export([init/0]).

start_link() ->
    token_server:start_link(?MODULE, 1024, 15).

init() ->
    ok.

meta_header() ->
    "menelaus-auth-scram-sha_reply".

get_resp_headers_from_req(Req) ->
    get_resp_headers(Req:get_header_value(meta_header())).

get_resp_headers(undefined) ->
    [];
get_resp_headers("A" ++ Value) ->
    [{"WWW-Authenticate", Value}];
get_resp_headers("I" ++ Value) ->
    [{"Authentication-Info", Value}].

server_first_message(Nonce, Salt, IterationCount) ->
    "r=" ++ Nonce ++ ",s=" ++ Salt ++ ",i=" ++ integer_to_list(IterationCount).

encode_with_sid(Sid, Message) ->
    "sid=" ++ base64:encode_to_string(Sid) ++
        ",data=" ++ base64:encode_to_string(Message).

reply_error() ->
    {auth_failure, []}.

reply_auth_failure(Msg) ->
    {auth_failure, [{meta_header(), Msg}]}.

reply_error(Sid, Error) ->
    reply_auth_failure(
      "I" ++ encode_with_sid(Sid, "e=" ++ Error)).

reply_success(Sid, UserName, ServerProof) ->
    {ok, {UserName, local},
     [{meta_header(),
       "I" ++ encode_with_sid(
                Sid,
                "v=" ++ base64:encode_to_string(ServerProof))}]}.

reply_first_step(Sha, Sid, Msg) ->
    reply_auth_failure("A" ++ www_authenticate_prefix(Sha) ++ " " ++
                           encode_with_sid(Sid, Msg)).

www_authenticate_prefix(sha512) ->
    "SCRAM-SHA-512";
www_authenticate_prefix(sha256) ->
    "SCRAM-SHA-256";
www_authenticate_prefix(sha) ->
    "SCRAM-SHA-1".

parse_authorization_header_prefix("SHA-512 " ++ Rest) ->
    {sha512, Rest};
parse_authorization_header_prefix("SHA-256 " ++ Rest) ->
    {sha256, Rest};
parse_authorization_header_prefix("SHA-1 " ++ Rest) ->
    {sha, Rest};
parse_authorization_header_prefix(_) ->
    error.

auth_info_key(sha512) ->
    <<"sha512">>;
auth_info_key(sha256) ->
    <<"sha256">>;
auth_info_key(sha) ->
    <<"sha1">>.

parse_authorization_header(Value) ->
    Sections = string:tokens(Value, ","),
    ParsedParams =
        lists:keysort(
          1,
          lists:filtermap(
            fun ("data=" ++ Rest) ->
                    {true, {data, Rest}};
                ("sid=" ++ Rest) ->
                    {true, {sid, Rest}};
                (_) ->
                    false
            end, Sections)),
    case ParsedParams of
        [{data, D}] ->
            {undefined, D};
        [{data, D}, {sid, S}] ->
            {S, D};
        _ ->
            error
    end.

parse_client_first_message("n,," ++ Bare) ->
    Sections = string:tokens(Bare, ","),
    WithoutReserved =
        lists:dropwhile(?cut(not lists:prefix("n=", _)), Sections),
    case WithoutReserved of
        ["n=" ++ Name, "r=" ++ Nonce | _] ->
            {Name, Nonce, Bare};
        _ ->
            error
    end;
parse_client_first_message(_) ->
    error.

parse_client_final_message(Msg) ->
    Sections = string:tokens(Msg, ","),
    case Sections of
        %% <<"n,,">> = base64:decode("biws")
        ["c=biws", "r=" ++ Nonce | Rest = [_|_]] ->
            case lists:last(Rest) of
                "p=" ++ Proof ->
                    MsgWithoutProof =
                        lists:sublist(Msg, length(Msg) - length(Proof) - 3),
                    {Nonce, Proof, MsgWithoutProof};
                _ ->
                    error
            end;
        _ ->
            error
    end.

authenticate(AuthHeader) ->
    case parse_authorization_header_prefix(AuthHeader) of
        {Sha, Rest} ->
            case parse_authorization_header(Rest) of
                error ->
                    reply_error();
                {EncodedSid, EncodedData} ->
                    case (catch {case EncodedSid of
                                     undefined ->
                                         undefined;
                                     _ ->
                                         base64:decode(EncodedSid)
                                 end,
                                 base64:decode_to_string(EncodedData)}) of
                        {'EXIT', _} ->
                            reply_error();
                        {Sid, Data} ->
                            authenticate(Sha, Sid, Data)
                    end
            end;
        error ->
            reply_error()
    end.

authenticate(Sha, undefined, Data) ->
    case parse_client_first_message(Data) of
        error ->
            reply_error();
        {Name, Nonce, Bare} ->
            handle_client_first_message(Sha, Name, Nonce, Bare)
    end;
authenticate(Sha, Sid, Data) ->
    case parse_client_final_message(Data) of
        error ->
            reply_error();
        {Nonce, Proof, ClientFinalMessage} ->
            handle_client_final_message(Sha, Sid, Nonce, Proof,
                                        ClientFinalMessage)
    end.

gen_nonce() ->
    [crypto:rand_uniform(48,125) || _ <- lists:seq(1,15)].

find_auth_info(Sha, Name) ->
    case menelaus_users:get_auth_info({Name, local}) of
        false ->
            {error, "unknown-user"};
        AuthInfo ->
            case proplists:get_value(auth_info_key(Sha), AuthInfo) of
                undefined ->
                    {error, "other-error"};
                {Info} ->
                    Info
            end
    end.

-record(memo, {auth_message,
               name,
               nonce}).

handle_client_first_message(Sha, Name, Nonce, Bare) ->
    case find_auth_info(Sha, Name) of
        {error, _} ->
            reply_error();
        Props ->
            Salt = binary_to_list(proplists:get_value(<<"s">>, Props)),
            IterationCount = proplists:get_value(<<"i">>, Props),

            ServerNonce = Nonce ++ gen_nonce(),
            ServerMessage =
                server_first_message(ServerNonce, Salt, IterationCount),
            Memo = #memo{auth_message = Bare ++ "," ++ ServerMessage,
                         name = Name,
                         nonce = ServerNonce},
            Sid = token_server:generate(?MODULE, Memo),
            reply_first_step(Sha, Sid, ServerMessage)
    end.

calculate_client_proof(Sha, SaltedPassword, AuthMessage) ->
    ClientKey = crypto:hmac(Sha, SaltedPassword, <<"Client Key">>),
    StoredKey = crypto:hash(Sha, ClientKey),
    ClientSignature = crypto:hmac(Sha, StoredKey, AuthMessage),
    misc:bin_bxor(ClientKey, ClientSignature).

calculate_server_proof(Sha, SaltedPassword, AuthMessage) ->
    ServerKey = crypto:hmac(Sha, SaltedPassword, <<"Server Key">>),
    crypto:hmac(Sha, ServerKey, AuthMessage).

handle_client_final_message(Sha, Sid, Nonce, Proof, ClientFinalMessage) ->
    case token_server:take(?MODULE, Sid) of
        false ->
            reply_error(Sid, "other-error");
        {ok, #memo{auth_message = AuthMessage,
                   name = Name,
                   nonce = ServerNonce}} ->
            case misc:compare_secure(Nonce, ServerNonce) of
                false ->
                    reply_error(Sid, "other-error");
                true ->
                    case find_auth_info(Sha, Name) of
                        {error, Error} ->
                            reply_error(Sid, Error);
                        Props ->
                            SaltedPassword =
                                base64:decode(proplists:get_value(<<"h">>,
                                                                  Props)),
                            FullAuthMessage =
                                AuthMessage ++ "," ++ ClientFinalMessage,
                            case handle_proofs(Sha, SaltedPassword,
                                               Proof, FullAuthMessage) of
                                error ->
                                    reply_error(Sid, "invalid-proof");
                                ServerProof ->
                                    reply_success(Sid, Name, ServerProof)
                            end
                    end
            end
    end.

handle_proofs(Sha, SaltedPassword, Proof, AuthMessage) ->
    ClientProof = calculate_client_proof(Sha, SaltedPassword, AuthMessage),
    case misc:compare_secure(Proof, base64:encode_to_string(ClientProof)) of
        false ->
            error;
        true ->
            calculate_server_proof(Sha, SaltedPassword, AuthMessage)
    end.
