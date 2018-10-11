-module(ldap_auth).

-include("ns_common.hrl").

-include_lib("eldap/include/eldap.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("cut.hrl").

-export([with_connection/2,
         authenticate/2,
         authenticate/3,
         build_settings/0,
         set_settings/1,
         user_groups/1,
         user_groups/2,
         get_setting/2,
         parse_url/1,
         format_error/1]).

-define(DEFAULT_TIMEOUT, 5000).

authenticate(Username, Password) ->
    authenticate(Username, Password, build_settings()).

authenticate(Username, Password, Settings) ->
    case proplists:get_value(authentication_enabled, Settings, false) of
        true ->
            case get_user_DN(Username, Settings) of
                {ok, DN} ->
                    case with_authenticated_connection(DN, Password, Settings,
                                                       fun (_) -> ok end) of
                        ok -> true;
                        {error, _} -> false
                    end;
                {error, _} -> false
            end;
        false ->
            ?log_debug("LDAP authentication is disabled"),
            false
    end.

with_connection(Settings, Fun) ->
    Hosts = proplists:get_value(hosts, Settings, []),
    Port = proplists:get_value(port, Settings, 389),
    Timeout = proplists:get_value(request_timeout, Settings, ?DEFAULT_TIMEOUT),
    Encryption = proplists:get_value(encryption, Settings, tls),
    SSL = Encryption == ssl,
    %% Note: timeout option sets not only connect timeout but a timeout for any
    %%       request to ldap server
    case eldap:open(Hosts, [{port, Port}, {ssl, SSL}, {timeout, Timeout}]) of
        {ok, Handle} ->
            ?log_debug("Connected to LDAP server"),
            try
                %% The upgrade is done in two phases: first the server is asked
                %% for permission to upgrade. Second, if the request is
                %% acknowledged, the upgrade to tls is performed.
                %% The Timeout parameter is for the actual tls upgrade (phase 2)
                %% while the timeout in eldap:open/2 is used for the initial
                %% negotiation about upgrade (phase 1).
                case Encryption == tls andalso
                     eldap:start_tls(Handle, [], Timeout) of
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
                                _ -> {error, {bind_failed, Bind}}
                            end
                    end).

get_user_DN(Username, Settings) ->
    Map = proplists:get_value(user_dn_mapping, Settings, []),
    case map_user_to_DN(Username, Settings, Map) of
        {ok, DN} ->
            ?log_debug("Built LDAP DN ~p for username ~p",
                       [ns_config_log:tag_user_name(DN),
                        ns_config_log:tag_user_name(Username)]),
            {ok, DN};
        {error, Error} ->
            ?log_error("Build LDAP DN failed for username ~p: ~p",
                       [ns_config_log:tag_user_name(Username), Error]),
            {error, Error}
    end.

map_user_to_DN(Username, _Settings, []) -> {ok, Username};
map_user_to_DN(Username, Settings, [{Re, {Type, Template}}|T]) ->
    case re:run(Username, Re, [{capture, all_but_first, list}]) of
        nomatch -> map_user_to_DN(Username, Settings, T);
        {match, Captured} ->
            ReplaceRe = ?cut(lists:flatten(io_lib:format("\\{~b\\}", [_]))),
            Subs = [{ReplaceRe(N), escape(S)} ||
                        {N, S} <- misc:enumerate(Captured, 0)],
            [Res] = replace_expressions([Template], Subs),
            case Type of
                template -> {ok, Res};
                'query' -> dn_query(Res, Settings)
            end
    end.

dn_query(Query, Settings) ->
    QueryDN = proplists:get_value(query_dn, Settings, undefined),
    QueryPass = proplists:get_value(query_pass, Settings, undefined),
    Timeout = proplists:get_value(request_timeout, Settings, ?DEFAULT_TIMEOUT),
    with_authenticated_connection(
      QueryDN, QueryPass, Settings,
      fun (Handle) ->
              dn_query(Handle, Query, Timeout)
      end).

dn_query(Handle, Query, Timeout) ->
    case parse_url("ldap:///" ++ Query) of
        {ok, URLProps} ->
            Base = proplists:get_value(dn, URLProps, ""),
            Scope = proplists:get_value(scope, URLProps, "one"),
            Filter = proplists:get_value(filter, URLProps, "(objectClass=*)"),
            case search(Handle, Base, ["objectClass"], Scope, Filter, Timeout) of
                {ok, [#eldap_entry{object_name = DN}]} -> {ok, DN};
                {ok, []} -> {error, dn_not_found};
                {ok, [_|_]} -> {error, not_unique_username};
                {error, Reason} -> {error, {dn_search_failed, Reason}}
            end;
        {error, Error} ->
            {error, {ldap_url_parse_error, Query, Error}}
    end.

build_settings() ->
    case ns_config:search(ldap_settings) of
        {value, Settings} ->
            Settings;
        false ->
            []
    end.

set_settings(Settings) ->
    ns_config:set(ldap_settings, Settings).

get_setting(Prop, Default) ->
    ns_config:search_prop(ns_config:latest(), ldap_settings, Prop, Default).

user_groups(User) ->
    user_groups(User, build_settings()).
user_groups(User, Settings) ->
    QueryDN = proplists:get_value(query_dn, Settings, undefined),
    QueryPass = proplists:get_value(query_pass, Settings, undefined),
    with_authenticated_connection(
      QueryDN, QueryPass, Settings,
      fun (Handle) ->
              Query = proplists:get_value(groups_query, Settings, undefined),
              get_groups(Handle, User, Settings, Query)
      end).

get_groups(_Handle, _Username, _Settings, undefined) ->
    {ok, []};
get_groups(Handle, Username, Settings, {user_attributes, _, AttrName}) ->
    Timeout = proplists:get_value(request_timeout, Settings, ?DEFAULT_TIMEOUT),
    case get_user_DN(Username, Settings) of
        {ok, DN} ->
            case search(Handle, DN, [AttrName], "base",
                        "(objectClass=*)", Timeout) of
                {ok, [#eldap_entry{attributes = Attrs}]} ->
                    AttrsLower = [{string:to_lower(K), V} || {K, V} <- Attrs],
                    Groups = proplists:get_value(string:to_lower(AttrName),
                                                 AttrsLower, []),
                    ?log_debug("Groups search for ~p: ~p",
                               [ns_config_log:tag_user_name(Username), Groups]),
                    {ok, Groups};
                {error, Reason} ->
                    {error, {ldap_search_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {username_to_dn_map_failed, Reason}}
    end;
get_groups(Handle, Username, Settings, {user_filter, _, Base, Scope, Filter}) ->
    DNFun =
        fun () ->
                case get_user_DN(Username, Settings) of
                    {ok, DN} -> DN;
                    {error, Reason} ->
                        throw({error, {username_to_dn_map_failed, Reason}})
                end
        end,
    try
        [Base2, Filter2] = replace_expressions([Base, Filter],
                                               [{"%u", escape(Username)},
                                                {"%D", DNFun}]),
        Timeout = proplists:get_value(request_timeout, Settings,
                                      ?DEFAULT_TIMEOUT),
        Entries =
            case search(Handle, Base2, ["objectClass"], Scope, Filter2,
                        Timeout) of
                {ok, L} -> L;
                {error, Reason} -> throw({error, {ldap_search_failed, Reason}})
            end,
        Groups = [DN || #eldap_entry{object_name = DN} <- Entries],
        ?log_debug("Groups search for ~p: ~p",
                   [ns_config_log:tag_user_name(Username), Groups]),
        {ok, Groups}
    catch
        throw:{error, _} = Error -> Error
    end.

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

format_error({ldap_search_failed, Reason}) ->
    io_lib:format("LDAP search returned error: ~s", [format_error(Reason)]);
format_error({connect_failed, _}) ->
    "Connot connect to the server";
format_error({start_tls_failed, _}) ->
    "Failed to use StartTLS extension";
format_error({ldap_url_parse_error, URL, Error}) ->
    io_lib:format("Failed to parse ldap url ~p (~s)", [URL, format_error(Error)]);
format_error({dn_search_failed, Reason}) ->
    io_lib:format("LDAP search for user DN failed with reason '~s'",
                  [format_error(Reason)]);
format_error(dn_not_found) ->
    "LDAP DN not found";
format_error(not_unique_username) ->
    "Search returned more than one DN for given username";
format_error({invalid_filter, Filter, Reason}) ->
    io_lib:format("Invalid ldap filter ~p (~s)", [Filter, Reason]);
format_error({username_to_dn_map_failed, R}) ->
    io_lib:format("Failed to map username to DN: ~s", [format_error(R)]);
format_error({invalid_scheme, S}) ->
    io_lib:format("Invalid scheme ~p", [S]);
format_error(malformed_url) ->
    "Malformed LDAP URL";
format_error({invalid_dn, DN}) ->
    io_lib:format("Invalid ldap DN '~s'", [DN]);
format_error({invalid_scope, Scope}) ->
    io_lib:format("Invalid ldap scope: ~p, possible values are one, "
                  "base or sub", [Scope]);
format_error(Error) ->
    io_lib:format("~p", [Error]).


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

-ifdef(EUNIT).

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
