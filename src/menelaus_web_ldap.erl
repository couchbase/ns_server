%% @author Couchbase <info@couchbase.com>
%% @copyright 2019 Couchbase, Inc.
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

%% @doc rest api's for ldap support
-module(menelaus_web_ldap).

-include("ns_common.hrl").
-include("cut.hrl").

-export([handle_ldap_settings/1,
         handle_ldap_settings_post/1,
         handle_ldap_settings_validate_post/2,
         handle_invalidate_ldap_cache/1,
         invalidate_ldap_cache/0]).

handle_ldap_settings(Req) ->
    menelaus_web_rbac:assert_groups_and_ldap_enabled(),
    Settings = ldap_util:build_settings(),
    menelaus_util:reply_json(Req, {prepare_ldap_settings(Settings)}).

prepare_ldap_settings(Settings) ->
    Fun =
      fun (_, undefined) -> undefined;
          (hosts, Hosts) ->
              [list_to_binary(H) || H <- Hosts];
          (user_dn_mapping, L) ->
              lists:map(
                fun ({Re, {'query', Q}}) ->
                        {[{re, iolist_to_binary(Re)},
                          {'query', iolist_to_binary(Q)}]};
                    ({Re, {template, T}}) ->
                        {[{re, iolist_to_binary(Re)},
                          {template, iolist_to_binary(T)}]}
                end, L);
          (query_dn, DN) ->
              list_to_binary(DN);
          (query_pass, {password, ""}) ->
              <<>>;
          (query_pass, {password, _}) ->
              <<"**********">>;
          (groups_query, Orig) ->
              list_to_binary(Orig);
          (cacert, {CA, _Decoded}) ->
              CA;
          (_, Value) ->
              Value
      end,
    [{K, Fun(K, V)} || {K, V} <- Settings, V =/= undefined].

handle_ldap_settings_post(Req) ->
    menelaus_web_rbac:assert_groups_and_ldap_enabled(),
    validator:handle(
      fun (Props) ->
              ns_audit:ldap_settings(Req, prepare_ldap_settings(Props)),
              ldap_util:set_settings(Props),
              handle_ldap_settings(Req)
      end, Req, form, ldap_settings_validators()).

build_new_ldap_settings(Props) ->
    misc:update_proplist(ldap_util:build_settings(), Props).

handle_ldap_settings_validate_post(Type, Req) when Type =:= "connectivity";
                                                   Type =:= "authentication";
                                                   Type =:= "groups_query" ->
    menelaus_web_rbac:assert_groups_and_ldap_enabled(),
    validator:handle(
      fun (Props) ->
              NewProps = build_new_ldap_settings(Props),
              Res = validate_ldap_settings(Type, NewProps),
              menelaus_util:reply_json(Req, {Res})
      end, Req, form, ldap_settings_validator_validators(Type) ++
                      ldap_settings_validators());
handle_ldap_settings_validate_post(_Type, Req) ->
    menelaus_util:reply_json(Req, <<"Unknown validation type">>, 404).

validate_ldap_settings("connectivity", Settings) ->
    case ldap_auth:with_query_connection(Settings, fun (_) -> ok end) of
        ok ->
            [{result, success}];
        {error, Error} ->
            Bin = iolist_to_binary(ldap_auth:format_error(Error)),
            [{result, error},
             {reason, Bin}]
    end;
validate_ldap_settings("authentication", Settings) ->
    User = proplists:get_value(auth_user, Settings),
    Pass = proplists:get_value(auth_pass, Settings),
    case ldap_auth:authenticate_with_cause(User, Pass, Settings) of
        {ok, DN} ->
            [{result, success}, {dn, iolist_to_binary(DN)}];
        {error, Error} ->
            Bin = iolist_to_binary(ldap_auth:format_error(Error)),
            [{result, error}, {reason, Bin}]
    end;
validate_ldap_settings("groups_query", Settings) ->
    GroupsUser = proplists:get_value(groups_query_user, Settings),
    case ldap_auth:user_groups(GroupsUser, Settings) of
        {ok, Groups} ->
            [{result, success},
             {groups, [list_to_binary(G) || G <- Groups]}];
        {error, Error2} ->
            Bin2 = iolist_to_binary(ldap_auth:format_error(Error2)),
            [{result, error},
             {reason, Bin2}]
    end.

ldap_settings_validators() ->
    [
        validator:boolean(authentication_enabled, _),
        validator:boolean(authorization_enabled, _),
        validate_ldap_hosts(hosts, _),
        validator:integer(port, 0, 65535, _),
        validator:one_of(encryption, ["TLS", "StartTLSExtension", "None"], _),
        validator:convert(encryption, fun list_to_atom/1, _),
        validate_user_dn_mapping(user_dn_mapping, _),
        validate_ldap_dn(query_dn, _),
        validator:touch(query_pass, _),
        validator:convert(query_pass, ?cut({password, _}), _),
        validate_ldap_groups_query(groups_query, _),
        validator:integer(max_parallel_connections, 1, 1000, _),
        validator:integer(max_cache_size, 0, 10000, _),
        validator:integer(cache_value_lifetime, 0, infinity, _),
        validator:integer(request_timeout, 0, infinity, _),
        validator:boolean(nested_groups_enabled, _),
        validator:integer(nested_groups_max_depth, 1, 100, _),
        validator:boolean(fail_on_max_depth, _),
        validator:boolean(server_cert_validation, _),
        validate_cert(cacert, _),
        validator:unsupported(_)
    ].

validate_cert(Name, State) ->
    validator:validate(
      fun ("") -> {value, undefined};
          (Cert) ->
              BinCert = iolist_to_binary(Cert),
              case ns_server_cert:decode_single_certificate(BinCert) of
                  {error, _} -> {error, "invalid ca certificate"};
                  Decoded -> {value, {BinCert, Decoded}}
              end
      end, Name, State).

ldap_settings_validator_validators("connectivity") -> [];
ldap_settings_validator_validators("authentication") ->
    [validator:required(auth_user, _),
     validator:required(auth_pass, _)];
ldap_settings_validator_validators("groups_query") ->
    [validator:required(groups_query_user, _)].

validate_ldap_hosts(Name, State) ->
    validator:validate(
      fun (HostsRaw) ->
              {value, [string:trim(T) || T <- string:tokens(HostsRaw, ",")]}
      end, Name, State).

validate_user_dn_mapping(Name, State) ->
    validator:validate(
      fun (Str) ->
              Parse = ?cut(parse_user_dn_mapping_record(lists:usort(_))),
              try
                  Map = try ejson:decode(Str) of
                            M when is_list(M) -> M;
                            _ -> throw({error, "Should be a list"})
                        catch _:_ ->
                            throw({error, "Invalid JSON"})
                        end,
                  {value, [Parse(Props) || {Props} <- Map]}
              catch
                  throw:{error, _} = Err -> Err
              end
      end, Name, State).

parse_user_dn_mapping_record([{<<"re">>, Re}, {<<"template">>, Template}]) ->
    DN = re:replace(Template, "\\{\\d+\\}", "placeholder",
                    [{return, list}, global]),
    case eldap:parse_dn(DN) of
        {ok, _} -> ok;
        {parse_error, Reason, _} ->
            throw({error, io_lib:format("Template is not a valid LDAP "
                                        "distinguished name: ~p", [Reason])})
    end,
    {validate_re(Re), {template, validate_placeholders(Template)}};
parse_user_dn_mapping_record([{<<"query">>, QueryTempl}, {<<"re">>, Re}]) ->
    case ldap_util:parse_url("ldap:///" ++ QueryTempl,
                             [{"\\{\\d+\\}", "placeholder"}]) of
        {ok, _} -> ok;
        {error, Reason} ->
            throw({error, io_lib:format(
                            "Invalid LDAP query '~s': ~s",
                            [QueryTempl, ldap_auth:format_error(Reason)])})
    end,
    {validate_re(Re), {'query', validate_placeholders(QueryTempl)}};
parse_user_dn_mapping_record(Props) ->
    throw({error, io_lib:format("Invalid record: ~p",
                                [ejson:encode({Props})])}).

validate_placeholders(Str) ->
    case re:run(Str, "\\{\\d+\\}", []) of
        {match, _} -> Str;
        nomatch ->
            throw({error, "Template or query should contain at least one "
                          "placeholder, like \"{0}\""})
    end.

validate_re(Re) ->
    case re:compile(Re) of
        {ok, _} -> Re;
        {error, {ErrStr, Pos}} ->
            throw({error, io_lib:format("Invalid regular expression ~s: ~s "
                                        "at ~b", [Re, ErrStr, Pos])})
    end.

validate_ldap_dn(Name, State) ->
    validator:validate(
      fun (DN) ->
              case eldap:parse_dn(DN) of
                  {ok, _} -> {value, DN};
                  {parse_error, Reason, _} ->
                      Msg = io_lib:format("Should be valid LDAP distinguished "
                                          "name: ~p", [Reason]),
                      {error, Msg}
              end
      end, Name, State).

validate_ldap_groups_query(Name, State) ->
    validator:validate(
      fun (Query) ->
              case ldap_util:parse_url(
                     "ldap:///" ++ Query,
                     [{"%u", "test_user"}, {"%D", "uid=testdn"}]) of
                  {ok, URLProps} ->
                      Base = proplists:get_value(dn, URLProps, ""),
                      Attrs = proplists:get_value(attributes, URLProps, []),
                      if
                          length(Attrs) > 1 ->
                              {error, "Only one attribute can be specified"};
                          Base == "" ->
                              {error, "Search base cannot be empty"};
                          true ->
                              ok
                      end;
                  {error, _} ->
                      {error, "Invalid LDAP query"}
              end
      end, Name, State).

handle_invalidate_ldap_cache(Req) ->
    case remote_api:invalidate_ldap_cache(ns_node_disco:nodes_actual()) of
        {_, []} -> menelaus_util:reply_json(Req, {[]});
        {_, BadNodes} ->
            Msg = io_lib:format("Invalidation failed on nodes: ~p", [BadNodes]),
            menelaus_util:reply_json(Req, iolist_to_binary(Msg), 500)
    end.

invalidate_ldap_cache() ->
    ldap_auth_cache:flush(),
    roles_cache:renew(),
    memcached_permissions:refresh().
