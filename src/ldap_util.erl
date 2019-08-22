%% @author Couchbase <info@couchbase.com>
%% @copyright 2018-2019 Couchbase, Inc.
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
-module(ldap_util).

-include("ns_common.hrl").
-include_lib("eldap/include/eldap.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([with_authenticated_connection/4,
         search/6,
         parse_url/1,
         parse_url/2,
         escape/1,
         get_setting/1,
         build_settings/0,
         set_settings/1,
         replace_expressions/2]).

ssl_options(Host, Settings) ->
    case proplists:get_value(server_cert_validation, Settings) of
        true ->
            [{verify, verify_peer}, {cacerts, get_cacerts(Settings)},
             {server_name_indication, Host}, {log_alert, false}];
        false ->
            [{verify, verify_none}]
    end.

get_cacerts(Settings) ->
    case proplists:get_value(cacert, Settings) of
        {_Cert, DecodedCert} -> [DecodedCert];
        undefined ->
            case ns_server_cert:cluster_ca() of
                {_, _} -> []; %% No point in using self signed cert
                {UploadedCAProps, _, _} ->
                    Pem = proplists:get_value(pem, UploadedCAProps),
                    [ns_server_cert:decode_single_certificate(Pem)]
            end
    end.

%% Can't just pass the list of hosts to eldap:open/2 because it is impossible
%% to get the peer's hostname later, so we have to iterate over the list
%% of hosts and memorize the one we were able to connect.
%% We need the peer's hostname information for server name validation
%% later in StartTLS
open_ldap_connection([], _Port, _SSL, _Timeout, _Settings) ->
    {error,"connect failed"};
open_ldap_connection([Host|Hosts], Port, SSL, Timeout, Settings) ->
    SSLOpts = case SSL of
                  true -> [{ssl, true}, {sslopts, ssl_options(Host, Settings)}];
                  false -> []
              end,
    %% Note: timeout option sets not only connect timeout but a timeout for any
    %%       request to ldap server
    case eldap:open([Host], [{port, Port}, {timeout, Timeout} | SSLOpts]) of
        {ok, Handle} -> {ok, Handle, Host};
        {error, _} -> open_ldap_connection(Hosts, Port, SSL, Timeout, Settings)
    end.

with_connection(Settings, Fun) ->
    Hosts = proplists:get_value(hosts, Settings),
    Port = proplists:get_value(port, Settings),
    Timeout = proplists:get_value(request_timeout, Settings),
    Encryption = proplists:get_value(encryption, Settings),
    SSL = Encryption == 'TLS',

    case open_ldap_connection(Hosts, Port, SSL, Timeout, Settings) of
        {ok, Handle, Host} ->
            ?log_debug("Connected to LDAP server: ~p", [Host]),
            try
                %% The upgrade is done in two phases: first the server is asked
                %% for permission to upgrade. Second, if the request is
                %% acknowledged, the upgrade to tls is performed.
                %% The Timeout parameter is for the actual tls upgrade (phase 2)
                %% while the timeout in eldap:open/2 is used for the initial
                %% negotiation about upgrade (phase 1).
                case Encryption == 'StartTLSExtension' andalso
                     eldap:start_tls(Handle,
                                     ssl_options(Host, Settings),
                                     Timeout) of
                    Res when Res == ok; Res == false ->
                        Fun(Handle);
                    {error, Reason} ->
                        ?log_error("LDAP TLS start failed: ~p", [Reason]),
                        {error, {start_tls_failed, Reason}}
                end
            after
                eldap:close(Handle)
            end;
        {error, Reason} ->
            ?log_error("Connect to ldap {~p, ~p, ~p} failed: ~p",
                       [Hosts, Port, SSL, Reason]),
            {error, {connect_failed, Reason}}
    end.

with_authenticated_connection(DN, Password, Settings, Fun) ->
    with_connection(Settings,
                    fun (Handle) ->
                            PasswordBin = iolist_to_binary(Password),
                            Bind = eldap:simple_bind(Handle, DN, PasswordBin),
                            ?log_debug("Bind for dn ~p: ~p",
                                       [ns_config_log:tag_user_name(DN), Bind]),
                            case Bind of
                                ok -> Fun(Handle);
                                {error, Error} ->
                                    {error, {bind_failed, DN, Error}}
                            end
                    end).

get_setting(Prop) ->
    proplists:get_value(Prop, build_settings()).

default_settings() ->
    [{authentication_enabled, false},
     {authorization_enabled, false},
     {hosts, []},
     {port, 389},
     {encryption, 'None'},
     {user_dn_mapping, []},
     {query_dn, ""},
     {query_pass, {password, ""}},
     {groups_query, undefined},
     {max_parallel_connections, 100},
     {max_cache_size, 10000},
     {request_timeout, 5000},
     {nested_groups_enabled, false},
     {nested_groups_max_depth, 10},
     {fail_on_max_depth, false},
     {cache_value_lifetime,
      round(0.5*menelaus_roles:external_auth_polling_interval())},
     {cacert, undefined},
     {server_cert_validation, true}].

build_settings() ->
    case ns_config:search(ldap_settings) of
        {value, Settings} ->
            misc:update_proplist(default_settings(), Settings);
        false ->
            default_settings()
    end.

set_settings(Settings) ->
    OldProps = ns_config:read_key_fast(ldap_settings, []),
    ns_config:set(ldap_settings, misc:update_proplist(OldProps, Settings)).

parse_scope("base") -> eldap:baseObject();
parse_scope("one") -> eldap:singleLevel();
parse_scope("sub") -> eldap:wholeSubtree().

search(Handle, Base, Attributes, Scope, Filter, Timeout) ->
    case ldap_filter_parser:parse(Filter) of
        {ok, EldapFilter} ->
            %% The timeout option in the SearchOptions is for the ldap server,
            %% while the timeout in eldap:open/2 is used for each individual
            %% request in the search operation
            SearchProps = [{base, Base}, {attributes, Attributes},
                           {scope, parse_scope(Scope)}, {filter, EldapFilter},
                           {timeout, Timeout}],
            eldap_search(Handle, SearchProps);
        {error, E} ->
            {error, {invalid_filter, Filter, E}}
    end.

eldap_search(Handle, SearchProps) ->
    case eldap:search(Handle, SearchProps) of
        {ok, #eldap_search_result{
                entries = Entries,
                referrals = Refs}} ->
            Refs == [] orelse ?log_error("LDAP search continuations are not "
                                         "supported yet, ignoring: ~p", [Refs]),
            ?log_debug("LDAP search res ~p: ~p", [SearchProps, Entries]),
            {ok, Entries};
        {ok, {referral, Refs}} ->
            ?log_error("LDAP referrals are not supported yet, ignoring: ~p",
                       [Refs]),
            {ok, []};
        {error, Reason} ->
            ?log_error("LDAP search failed ~p: ~p", [SearchProps, Reason]),
            {error, Reason}
    end.

parse_url(Template, ReplacePairs) ->
    [URL] = replace_expressions([Template], ReplacePairs),
    parse_url(URL).

%% RFC4516 ldap url parsing
parse_url(Str) ->
    SchemeValidator = fun (S) ->
                              case string:to_lower(S) of
                                  "ldap" -> valid;
                                  _ -> {error, {invalid_scheme, S}}
                              end
                      end,
    try
        {Scheme, _UserInfo, Host, Port, "/" ++ EncodedDN, Query} =
            case http_uri:parse(Str, [{scheme_defaults, [{ldap, 389}]},
                                 {scheme_validation_fun, SchemeValidator}]) of
                {ok, R} -> R;
                {error, _} -> throw({error, malformed_url})
            end,

        [[], AttrsStr, Scope, FilterEncoded, Extensions | _] =
            string:split(Query ++ "?????", "?", all),
        Attrs = [mochiweb_util:unquote(A) || A <- string:tokens(AttrsStr, ",")],

        DN = mochiweb_util:unquote(EncodedDN),
        case eldap:parse_dn(DN) of
            {ok, _} -> ok;
            {parse_error, _, _} -> throw({error, {invalid_dn, DN}})
        end,

        ScopeLower = string:to_lower(Scope),
        try
            ScopeLower =:= "" orelse parse_scope(ScopeLower)
        catch
            _:_ -> throw({error, {invalid_scope, Scope}})
        end,

        Filter = mochiweb_util:unquote(FilterEncoded),
        case Filter =:= "" orelse ldap_filter_parser:parse(Filter) of
            true -> ok;
            {ok, _} -> ok;
            {error, Reason2} ->
                throw({error, {invalid_filter, Filter, Reason2}})
        end,

        {ok,
         [{scheme, Scheme}] ++
         [{host, Host} || Host =/= ""] ++
         [{port, Port}] ++
         [{dn, DN} || DN =/= ""] ++
         [{attributes, Attrs} || Attrs =/= []] ++
         [{scope, ScopeLower} || ScopeLower =/= ""] ++
         [{filter, Filter} || Filter =/= ""] ++
         [{extensions, Extensions} || Extensions =/= ""]
        }
    catch
        throw:{error, _} = Error -> Error
    end.

-define(ALLOWED_CHARS, "abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "0123456789=: ").

%% Escapes any special chars (RFC 4515) from a string representing a
%% a search filter assertion value
%% Based on https://ldap.com/2018/05/04/understanding-and-defending-against-ldap-injection-attacks/
escape(Input) ->
    Characters = unicode:characters_to_list(iolist_to_binary(Input)),
    S = lists:map(
          fun (C) ->
                  case lists:member(C, ?ALLOWED_CHARS) of
                      true -> C;
                      false ->
                          Hex = misc:hexify(unicode:characters_to_binary([C])),
                          [[$\\, H, L] || <<H:8, L:8>> <= Hex]
                  end
          end, Characters),

    FlatStr = lists:flatten(S),

    %% If a value has any leading or trailing spaces, then you should escape
    %% those spaces by prefixing them with a backslash or as \20. Spaces in
    %% the middle of a value don’t need to be escaped.
    {Trail, Rest} = lists:splitwith(_ =:= $\s, lists:reverse(FlatStr)),
    {Lead, Rest2} = lists:splitwith(_ =:= $\s, lists:reverse(Rest)),
    lists:flatten(["\\20" || _ <- Lead] ++ Rest2 ++ ["\\20" || _ <- Trail]).

replace_expressions(Strings, Substitutes) ->
    lists:foldl(
        fun ({Re, ValueFun}, Acc) ->
            replace(Acc, Re, ValueFun, [])
        end, Strings, Substitutes).

replace([], _, _, Res) -> lists:reverse(Res);
replace([Str | Tail], Re, Value, Res) when is_function(Value) ->
    case re:run(Str, Re, [{capture, none}]) of
        match -> replace([Str | Tail], Re, Value(), Res);
        nomatch -> replace(Tail, Re, Value, [Str | Res])
    end;
replace([Str | Tail], Re, Value, Res) ->
    %% Replace \ with \\ to prevent re skipping all hex bytes from Value
    %% which are specified as \\XX according to LDAP RFC. Example:
    %%   Str = "(uid=%u)",
    %%   Re  = "%u",
    %%   Value = "abc\\23def",
    %%   Without replacing the result is "(uid=abcdef)"
    %%   With replacing it is "(uid=abc\\23def)"
    Value2 = re:replace(Value, "\\\\", "\\\\\\\\", [{return, list}, global]),
    ResStr = re:replace(Str, Re, Value2, [global, {return, list}]),
    replace(Tail, Re, Value, [ResStr | Res]).


-ifdef(TEST).
escape_test() ->
%% Examples from RFC 4515
    ?assertEqual("Parens R Us \\28for all your parenthetical needs\\29",
                 escape("Parens R Us (for all your parenthetical needs)")),
    ?assertEqual("\\2a", escape("*")),
    ?assertEqual("C:\\5cMyFile", escape("C:\\MyFile")),
    ?assertEqual("\\00\\00\\00\\04", escape([16#00, 16#00, 16#00, 16#04])),
    ?assertEqual("Lu\\c4\\8di\\c4\\87", escape(<<"Lučić"/utf8>>)).

parse_url_test_() ->
    Parse = fun (S) -> {ok, R} = parse_url(S), R end,
    [
        ?_assertEqual([{scheme, ldap}, {port, 389}], Parse("ldap://")),
        ?_assertEqual([{scheme, ldap}, {host, "127.0.0.1"}, {port, 389}],
                      Parse("ldap://127.0.0.1")),
        ?_assertEqual([{scheme, ldap}, {host, "127.0.0.1"}, {port, 636}],
                      Parse("ldap://127.0.0.1:636")),
        ?_assertEqual([{scheme, ldap}, {host, "127.0.0.1"}, {port, 636},
                       {dn,"uid=al,ou=users,dc=example"}],
                      Parse("ldap://127.0.0.1:636"
                            "/uid%3Dal%2Cou%3Dusers%2Cdc%3Dexample")),
        ?_assertEqual([{scheme, ldap}, {host, "127.0.0.1"}, {port, 636},
                       {dn,"uid=al,ou=users,dc=example"}],
                      Parse("ldap://127.0.0.1:636"
                            "/uid%3Dal%2Cou%3Dusers%2Cdc%3Dexample")),
        ?_assertEqual([{scheme, ldap}, {host, "127.0.0.1"}, {port, 636},
                       {dn,"uid=al,ou=users,dc=example"},
                       {attributes, ["attr1", "attr2"]}],
                      Parse("ldap://127.0.0.1:636"
                            "/uid%3Dal%2Cou%3Dusers%2Cdc%3Dexample"
                            "?attr1,attr2")),
        ?_assertEqual([{scheme, ldap}, {host, "127.0.0.1"}, {port, 636},
                       {dn,"uid=al,ou=users,dc=example"},
                       {attributes, ["attr1", "attr2"]},
                       {scope, "base"},
                       {filter, "(!(&(uid=%u)(email=%u@%d)))"}],
                      Parse("ldap://127.0.0.1:636"
                            "/uid%3Dal%2Cou%3Dusers%2Cdc%3Dexample?attr1,attr2"
                            "?base?%28%21%28%26%28uid%3D%25u%29%28"
                            "email%3D%25u%40%25d%29%29%29")),

%% Tests from RFC4516 examples:
        ?_assertEqual([{scheme, ldap}, {port, 389},
                       {dn, "o=University of Michigan,c=US"}],
                      Parse("ldap:///o=University%20of%20Michigan,c=US")),
        ?_assertEqual([{scheme, ldap}, {host, "ldap1.example.net"}, {port, 389},
                       {dn, "o=University of Michigan,c=US"}],
                      Parse("ldap://ldap1.example.net"
                            "/o=University%20of%20Michigan,c=US")),
        ?_assertEqual([{scheme, ldap}, {host, "ldap1.example.net"}, {port, 389},
                       {dn, "o=University of Michigan,c=US"},
                       {scope, "sub"}, {filter, "(cn=Babs Jensen)"}],
                      Parse("ldap://ldap1.example.net/o=University%20of%2"
                             "0Michigan,c=US??sub?(cn=Babs%20Jensen)")),
        ?_assertEqual([{scheme, ldap}, {host, "ldap1.example.com"}, {port, 389},
                       {dn, "c=GB"}, {attributes, ["objectClass"]},
                       {scope, "one"}],
                      Parse("LDAP://ldap1.example.com/c=GB?objectClass?ONE")),
        ?_assertEqual([{scheme, ldap}, {host, "ldap2.example.com"}, {port, 389},
                       {dn, "o=Question?,c=US"}, {attributes, ["mail"]}],
                      Parse("ldap://ldap2.example.com"
                            "/o=Question%3f,c=US?mail")),
        ?_assertEqual([{scheme, ldap}, {host, "ldap3.example.com"}, {port, 389},
                       {dn, "o=Babsco,c=US"},
                       {filter, "(four-octet=\\00\\00\\00\\04)"}],
                      Parse("ldap://ldap3.example.com/o=Babsco,c=US"
                            "???(four-octet=%5c00%5c00%5c00%5c04)")),
        ?_assertEqual([{scheme, ldap}, {host, "ldap.example.com"}, {port, 389},
                       {dn, "o=An Example\\2C Inc.,c=US"}],
                      Parse("ldap://ldap.example.com"
                            "/o=An%20Example%5C2C%20Inc.,c=US"))
    ].
-endif.
