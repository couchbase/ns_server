-module(ldap_auth).

-include("ns_common.hrl").

-export([authenticate/2, build_settings/0, set_settings/1]).

authenticate(Username, Password) ->
    case get_setting(authentication_enabled, false) of
        true ->
            UserDN = get_user_DN(Username),
            Hosts = get_setting(hosts, []),
            Port = get_setting(port, 389),
            SSL = get_setting(ssl, true),
            check_creds(Hosts, Port, SSL, UserDN, Password);
        false ->
            ?log_debug("LDAP authentication is disabled"),
            false
    end.

check_creds(Hosts, Port, SSL, DN, Password) ->
    case eldap:open(Hosts, [{port, Port}, {ssl, SSL}, {timeout, 1000}]) of
        {ok, Handle} ->
            ?log_debug("Connected to LDAP server"),
            try
                Bind = eldap:simple_bind(Handle, DN, Password),
                ?log_debug("Bind for dn ~p: ~p",
                           [ns_config_log:tag_user_name(DN), Bind]),
                ok =:= Bind
            after
                eldap:close(Handle)
            end;
        {error, Reason} ->
            ?log_error("Connect to ldap {~p, ~p, ~p} failed: ~p",
                       [Hosts, Port, SSL, Reason]),
            false
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
