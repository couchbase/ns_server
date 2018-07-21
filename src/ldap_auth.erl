-module(ldap_auth).

-include("ns_common.hrl").

-include_lib("eldap/include/eldap.hrl").

-export([authenticate/2, build_settings/0, set_settings/1, user_groups/1,
         get_setting/2]).

authenticate(Username, Password) ->
    case get_setting(authentication_enabled, false) of
        true ->
            DN = get_user_DN(Username),
            case with_connection(DN, Password, fun (_) -> ok end) of
                ok -> true;
                {error, _} -> false
            end;
        false ->
            ?log_debug("LDAP authentication is disabled"),
            false
    end.

with_connection(DN, Password, Fun) ->
    Hosts = get_setting(hosts, []),
    Port = get_setting(port, 389),
    Encryption = get_setting(encryption, tls),
    SSL = Encryption == ssl,
    case eldap:open(Hosts, [{port, Port}, {ssl, SSL}, {timeout, 1000}]) of
        {ok, Handle} ->
            ?log_debug("Connected to LDAP server"),
            try
                case Encryption == tls andalso eldap:start_tls(Handle, []) of
                    Res when Res == ok; Res == false ->
                        Bind = eldap:simple_bind(Handle, DN, Password),
                        ?log_debug("Bind for dn ~p: ~p",
                                   [ns_config_log:tag_user_name(DN), Bind]),
                        case Bind of
                            ok -> Fun(Handle);
                            _ -> {error, {bind_failed, Bind}}
                        end;
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

get_user_DN(Username) ->
    Template = get_setting(user_dn_template, "%u"),
    DN = re:replace(Template, "%u", Username, [{return,list}]),
    ?log_debug("Built LDAP DN ~p by username ~p",
               [ns_config_log:tag_user_name(DN),
                ns_config_log:tag_user_name(Username)]),
    DN.

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
    QueryDN = get_setting(query_dn, undefined),
    QueryPass = get_setting(query_pass, undefined),
    with_connection(QueryDN, QueryPass,
        fun (Handle) ->
            get_groups(Handle, User, get_setting(groups_query, undefined))
        end).

get_groups(_Handle, _Username, undefined) ->
    {ok, []};
get_groups(Handle, Username, {user_attributes, _, AttrName}) ->
    case search(Handle, get_user_DN(Username), [AttrName],
                eldap:baseObject(), eldap:present("objectClass")) of
        {ok, [#eldap_entry{attributes = Attrs}]} ->
            Groups = proplists:get_value(AttrName, Attrs, []),
            ?log_debug("Groups search for ~p: ~p",
                       [ns_config_log:tag_user_name(Username), Groups]),
            {ok, Groups};
        {error, Reason} ->
            {error, {ldap_search_failed, Reason}}
    end;
get_groups(Handle, Username, {user_filter, _, Base, Scope, Filter}) ->
    DNFun = fun () -> get_user_DN(Username) end,
    [Base2, Filter2] = replace_expressions([Base, Filter], [{"%u", Username},
                                                            {"%D", DNFun}]),
    {ok, FilterEldap} = ldap_filter_parser:parse(Filter2),
    ScopeEldap = parse_scope(Scope),
    case search(Handle, Base2, ["objectClass"], ScopeEldap, FilterEldap) of
        {ok, Entries} ->
            Groups = [DN || #eldap_entry{object_name = DN} <- Entries],
            ?log_debug("Groups search for ~p: ~p",
                       [ns_config_log:tag_user_name(Username), Groups]),
            {ok, Groups};
        {error, Reason} ->
            {error, {ldap_search_failed, Reason}}
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
    ResStr = re:replace(Str, Re, Value, [global, {return, list}]),
    replace(Tail, Re, Value, [ResStr | Res]).

parse_scope("base") -> eldap:baseObject();
parse_scope("one") -> eldap:singleLevel();
parse_scope("sub") -> eldap:wholeSubtree().

search(Handle, Base, Attributes, Scope, Filter) ->
    SearchProps = [{base, Base}, {attributes, Attributes}, {scope, Scope},
                   {filter, Filter}],

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
