-module(ldap_auth).

-include("ns_common.hrl").

-include_lib("eldap/include/eldap.hrl").
-include("cut.hrl").

-export([authenticate/2,
         authenticate/3,
         user_groups/1,
         user_groups/2,
         format_error/1]).

-define(DEFAULT_TIMEOUT, 5000).

authenticate(Username, Password) ->
    authenticate(Username, Password, ldap_util:build_settings()).

authenticate(Username, Password, Settings) ->
    case proplists:get_value(authentication_enabled, Settings, false) of
        true ->
            case get_user_DN(Username, Settings) of
                {ok, DN} ->
                    case ldap_util:with_authenticated_connection(
                           DN, Password, Settings, fun (_) -> ok end) of
                        ok -> true;
                        {error, _} -> false
                    end;
                {error, _} -> false
            end;
        false ->
            ?log_debug("LDAP authentication is disabled"),
            false
    end.

with_query_connection(Settings, Fun) ->
    DN = proplists:get_value(query_dn, Settings, undefined),
    Pass = proplists:get_value(query_pass, Settings, undefined),
    ldap_util:with_authenticated_connection(DN, Pass, Settings, Fun).

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
            Subs = [{ReplaceRe(N), ldap_util:escape(S)} ||
                        {N, S} <- misc:enumerate(Captured, 0)],
            [Res] = replace_expressions([Template], Subs),
            case Type of
                template -> {ok, Res};
                'query' -> dn_query(Res, Settings)
            end
    end.

dn_query(Query, Settings) ->
    Timeout = proplists:get_value(request_timeout, Settings, ?DEFAULT_TIMEOUT),
    with_query_connection(
      Settings,
      fun (Handle) ->
              dn_query(Handle, Query, Timeout)
      end).

dn_query(Handle, Query, Timeout) ->
    case ldap_util:parse_url("ldap:///" ++ Query) of
        {ok, URLProps} ->
            Base = proplists:get_value(dn, URLProps, ""),
            Scope = proplists:get_value(scope, URLProps, "one"),
            Filter = proplists:get_value(filter, URLProps, "(objectClass=*)"),
            case ldap_util:search(Handle, Base, ["objectClass"], Scope, Filter,
                                  Timeout) of
                {ok, [#eldap_entry{object_name = DN}]} -> {ok, DN};
                {ok, []} -> {error, dn_not_found};
                {ok, [_|_]} -> {error, not_unique_username};
                {error, Reason} -> {error, {dn_search_failed, Reason}}
            end;
        {error, Error} ->
            {error, {ldap_url_parse_error, Query, Error}}
    end.

user_groups(User) ->
    user_groups(User, ldap_util:build_settings()).
user_groups(User, Settings) ->
    with_query_connection(
      Settings,
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
            case ldap_util:search(Handle, DN, [AttrName], "base",
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
        [Base2, Filter2] = replace_expressions(
                             [Base, Filter],
                             [{"%u", ldap_util:escape(Username)},
                              {"%D", DNFun}]),
        Timeout = proplists:get_value(request_timeout, Settings,
                                      ?DEFAULT_TIMEOUT),
        Entries =
            case ldap_util:search(Handle, Base2, ["objectClass"], Scope,
                                  Filter2, Timeout) of
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
