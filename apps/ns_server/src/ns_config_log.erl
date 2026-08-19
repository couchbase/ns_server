%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(ns_config_log).

-behaviour(gen_server).

-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, sanitize/1, sanitize/2, sanitize_value/1,
         sanitize_value/2,
         compute_bucket_diff/2,
         frequently_changed_key/1]).

-include("ns_common.hrl").
-include("ns_config.hrl").
-include_lib("ns_common/include/generic.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-record(state, {buckets=[]}).

%% state sanitization
-export([format_status/1, tag_user_data/1, tag_user_name/1, tag_doc_id/1,
         tag_group_name/1,
         tag_user_props/1, tag_misc_item/1]).

format_status(#{state := State}) ->
    #{state => sanitize(State)}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [],
                          [{hibernate_after,
                            ?get_param(hibernate_after, 10000)}]).

init([]) ->
    %% We receive the whole KVList of every config change, so the mailbox can
    %% both grow long and hold large terms. Keep it off the heap so GC doesn't
    %% have to walk it (MB-72708).
    process_flag(message_queue_data, off_heap),
    Self = self(),
    ns_pubsub:subscribe_link(ns_config_events,
                             fun (KVList) when is_list(KVList) ->
                                     Self ! {config_change, KVList};
                                 (_) ->
                                     ok
                             end),
    {ok, #state{}}.

terminate(_Reason, _State)     -> ok.
code_change(_OldVsn, State, _) -> {ok, State}.

% Don't log values for some password/auth-related config values.

handle_call(Request, From, State) ->
    ?log_warning("Unexpected handle_call(~p, ~p, ~p)", [Request, From, State]),
    {reply, ok, State}.

handle_cast(Request, State) ->
    ?log_warning("Unexpected handle_cast(~p, ~p)", [Request, State]),
    {noreply, State}.

handle_info({config_change, KVList}, State) ->
    lists:foreach(fun ({K, V}) -> log_kv(K, V) end, KVList),
    {noreply, State};
handle_info(Info, State) ->
    ?log_warning("Unexpected handle_info(~p, ~p)", [Info, State]),
    {noreply, State}.

compute_bucket_diff(NewProps, OldProps) ->
    OldMap = proplists:get_value(map, OldProps, []),
    NewMap = proplists:get_value(map, NewProps, []),
    MapDiff = misc:compute_map_diff(NewMap, OldMap),

    OldFFMap = proplists:get_value(fastForwardMap, OldProps, []),
    NewFFMap = proplists:get_value(fastForwardMap, NewProps, []),
    FFMapDiff = misc:compute_map_diff(NewFFMap, OldFFMap),

    functools:chain(NewProps,
                    [lists:keystore(map, 1, _,
                                    {map_diff, MapDiff}),
                     lists:keystore(fastForwardMap, 1, _,
                                    {fastForwardMap_diff, FFMapDiff})]).

do_tag_user_name("@" ++ _ = Name) ->
    {ok, Name};
do_tag_user_name(Name) when is_list(Name) ->
    {ok, "<ud>" ++ Name ++ "</ud>"};
do_tag_user_name(NotName) when is_atom(NotName) ->
    {ok, NotName};  %% Cases like {source, local} we don't want to tag.
do_tag_user_name(Name) when is_binary(Name) ->
    {ok, list_to_binary(tag_user_name(binary_to_list(Name)))};
do_tag_user_name(_) ->
    continue.

tag_user_data(DebugKVList) ->
    misc:rewrite_tuples(
      fun tag_user_tuples_fun/1, tag_jwt_audit_claims(DebugKVList)).

%% A JWT authentication audit body is a proplist keyed by claim name, and an
%% operator can add any custom claim to it under any name, so there is no
%% fixed set of keys for tag_user_tuples_fun/1 to match on. Identify the body
%% by its type claim instead and tag the claim values wholesale, the way
%% menelaus_web_saml wraps a whole decoded assertion.
tag_jwt_audit_claims(KVList) when is_list(KVList) ->
    case lists:member({<<"type">>, <<"jwt">>}, KVList) of
        true ->
            [tag_jwt_claim(KV) || KV <- KVList];
        false ->
            KVList
    end;
tag_jwt_audit_claims(Other) ->
    Other.

%% Keys this pass leaves alone. There are two unrelated reasons:
%%
%% Cannot identify anyone: aud, exp, iss, reason and type carry no identifier,
%% and mapped_roles is safe because roles are a closed vocabulary that ships
%% with the product - jwt_auth keeps only the ones
%% menelaus_roles:validate_roles/2 accepted.
%%
%% mapped_groups is here for the opposite reason. It does identify people:
%% groups are named by whoever set the cluster up, which is why this module
%% has a tag_group_name/1 and a tag_user_name/1 and no tag_role_name. It is
%% tagged by the {<<"mapped_groups">>, _} clause of tag_user_tuples_fun/1
%% instead of here, because it is not a claim at all -
%% menelaus_auth:get_authn_res_audit_props/1 builds it from
%% #authn_res.extra_groups - and menelaus_web_rbac:handle_access_forbidden/3
%% audits it in a body that carries no type claim, which this pass never
%% looks at. Tagging on the key covers every body that can carry it. Tagging
%% it here as well would tag the JWT one twice and emit
%% <ud><ud>eng</ud></ud>, which the non-greedy <ud>(.+?)</ud> rule in
%% cbcollect_info cannot unpick. So do not "fix" this by dropping it from
%% this list; the tagging lives one function down.
%%
%% The token_roles claim is tagged as well: it is whatever the IdP put at the
%% operator-configured path, and it is audited without being checked against
%% the vocabulary at all.
-define(UNTAGGED_JWT_CLAIMS, [<<"aud">>, <<"exp">>, <<"iss">>,
                              <<"mapped_groups">>, <<"mapped_roles">>,
                              <<"reason">>, <<"type">>]).

tag_jwt_claim({Key, Value}) ->
    case lists:member(Key, ?UNTAGGED_JWT_CLAIMS) of
        true -> {Key, Value};
        false -> {Key, tag_jwt_claim_value(Value)}
    end;
tag_jwt_claim(Other) ->
    Other.

%% Only strings can carry an identifier that redaction needs to strip.
%% Numbers and booleans are left alone so that timestamp claims such as nbf
%% and iat stay readable, and so that tagging cannot turn a value into
%% something the reader cannot recognise.
tag_jwt_claim_value(Value) when is_binary(Value) ->
    tag_misc_item(Value);
tag_jwt_claim_value(Values) when is_list(Values) ->
    [tag_jwt_claim_value(V) || V <- Values];
tag_jwt_claim_value({KVs}) when is_list(KVs) ->
    {[{K, tag_jwt_claim_value(V)} || {K, V} <- KVs]};
tag_jwt_claim_value(Value) ->
    Value.

tag_user_tuples_fun({user, UserName}) when is_binary(UserName) ->
    {stop, {user, tag_user_name(UserName)}};
tag_user_tuples_fun({doc, {user, {U, D}}, _, _, V} = Doc) ->
    T = setelement(2, Doc, {user, {tag_user_name(U), D}}),
    {stop, setelement(5, T, tag_user_props(V))};
tag_user_tuples_fun({docv2, {user, {U, D}}, V, _} = Doc) ->
    T = setelement(2, Doc, {user, {tag_user_name(U), D}}),
    {stop, setelement(3, T, tag_user_props(V))};
tag_user_tuples_fun({full_name, FullName}) when is_binary(FullName) ->
    {stop, {full_name, tag_user_name(FullName)}};
tag_user_tuples_fun({raw_url, RawUrl}) ->
    {stop, {raw_url, tag_misc_item(RawUrl)}};
tag_user_tuples_fun({doc_id, DocId}) ->
    {stop, {doc_id, tag_user_name(DocId)}};
tag_user_tuples_fun({<<"bindDN">>, DistinguishedName}) ->
    {stop, {<<"bindDN">>, tag_user_name(DistinguishedName)}};
tag_user_tuples_fun({CertType, Certificate})
  when CertType =:= <<"cacert">> orelse
       CertType =:= <<"clientTLSCert">> ->
    {stop, {CertType, tag_misc_item(Certificate)}};
tag_user_tuples_fun({UName, Type}) when Type =:= local orelse
                                        Type =:= external orelse
                                        Type =:= admin ->
    case do_tag_user_name(UName) of
        continue ->
            continue;
        {ok, Val} ->
            {stop, {Val, Type}}
    end;
tag_user_tuples_fun({<<"spContactEmail">>, ContactEmail}) ->
    {stop, {<<"spContactEmail">>, tag_misc_item(ContactEmail)}};
tag_user_tuples_fun({<<"spContactName">>, ContactName}) ->
    {stop, {<<"spContactName">>, tag_misc_item(ContactName)}};
tag_user_tuples_fun({<<"spOrgDisplayName">>, DisplayName}) ->
    {stop, {<<"spOrgDisplayName">>, tag_misc_item(DisplayName)}};
tag_user_tuples_fun({<<"spOrgName">>, OrgName}) ->
    {stop, {<<"spOrgName">>, tag_misc_item(OrgName)}};
tag_user_tuples_fun({<<"spOrgURL">>, OrgURL}) ->
    {stop, {<<"spOrgURL">>, tag_misc_item(OrgURL)}};
%% Fixed key names that carry an identifier and reach the debug.log copy in
%% bodies tag_jwt_audit_claims/1 does not see. Unlike a JWT claim, whose name
%% the operator chooses, every key below is written in this repo, so matching
%% the key is enough and the positional pass is not needed.
%%
%% mapped_groups is the joined list menelaus_auth:get_authn_res_audit_props/1
%% builds, so the whole run is tagged as one item rather than group by group.
tag_user_tuples_fun({<<"mapped_groups">>, Groups}) ->
    {stop, {<<"mapped_groups">>, tag_group_name(Groups)}};
%% A credential id is chosen by the operator and is commonly the name of the
%% system or the person the credential belongs to. The description is free
%% text, and the list prefix can be a whole id, so all three are identifiers.
tag_user_tuples_fun({credential_id, Id}) ->
    {stop, {credential_id, tag_misc_item(Id)}};
tag_user_tuples_fun({credential_description, Description}) ->
    {stop, {credential_description, tag_misc_item(Description)}};
tag_user_tuples_fun({prefix, Prefix}) ->
    {stop, {prefix, tag_misc_item(Prefix)}};
%% menelaus_web_jwt audits the already-encoded settings response, so by the
%% time the body gets here the document is one binary with nothing left to
%% walk into. It holds groups_maps, sub_maps and roles_maps - rules written
%% over group and subject names, which auth_mapping tags when it logs them -
%% so tag the whole document. Tagging cannot be done where it is audited:
%% that value also goes to the audit sink, which must stay verbatim.
tag_user_tuples_fun({jwt_settings, Settings}) ->
    {stop, {jwt_settings, tag_misc_item(Settings)}};
tag_user_tuples_fun(_Other) ->
    continue.

tag_user_name(UserName) ->
    {ok, Val} = do_tag_user_name(UserName),
    Val.

tag_group_name(GroupName) ->
    {ok, Val} = do_tag_group_name(GroupName),
    Val.

do_tag_group_name(GroupName) when is_list(GroupName) ->
    {ok, "<ud>" ++ GroupName ++ "</ud>"};
do_tag_group_name(GroupName) when is_binary(GroupName) ->
    {ok, Val} = do_tag_group_name(binary_to_list(GroupName)),
    {ok, list_to_binary(Val)};
do_tag_group_name(_) ->
    no_change.

tag_user_props(Props) ->
    generic:transformt(?transform({name, N}, {name, tag_user_name(N)}),
                       Props).

do_tag_misc_item(Item) when is_list(Item) ->
    {ok, "<ud>" ++ Item ++ "</ud>"};
do_tag_misc_item(Item) when is_binary(Item) ->
    {ok, Val} = do_tag_misc_item(binary_to_list(Item)),
    {ok, list_to_binary(Val)};
do_tag_misc_item(_) ->
    no_change.

tag_misc_item(Item) ->
    case do_tag_misc_item(Item) of
        no_change ->
            Item;
        {ok, Val} ->
            Val
    end.

tag_doc_id(DocId) ->
    tag_misc_item(DocId).

rewrite_tuples_with_vclock(Fun, Config) ->
    misc:rewrite_tuples(
      fun ({Key, Value0} = KV) ->
          case ns_config:extract_vclock(Value0) of
              {0, []} ->
                  Fun(KV);
              {Ts, VClock} ->
                  Value = ns_config:strip_metadata(Value0),
                  case Fun({Key, Value}) of
                      continue ->
                          continue;
                      {stop, {Key, NewValue}} ->
                          {stop, {Key, [ns_config:build_vclock(Ts, VClock)
                                        | NewValue]}}
                  end
          end;
          (Other) ->
              Fun(Other)
      end, Config).

sanitize(Config) ->
    sanitize(Config, false).

sanitize(Config, TagUserTuples) ->
    Continue =
        case TagUserTuples of
            false ->
                functools:const(continue);
            true ->
                fun tag_user_tuples_fun/1
        end,
    rewrite_tuples_with_vclock(
      fun ({password, _}) ->
              {stop, {password, "*****"}};
          ({specialPasswords, _}) ->
              {stop, {specialPasswords, "*****"}};
          ({admin_pass, _}) ->
              {stop, {admin_pass, "*****"}};
          ({pass, _}) ->
              {stop, {pass, "*****"}};
          %% remove sanitization of this key when 7.6 becomes the min
          %% supported version
          ({cert_and_pkey, {Cert, PKey}}) ->
              {stop, {cert_and_pkey, {Cert, sanitize_value(PKey)}}};
          ({cert_and_pkey, {Props, Cert, PKey}}) ->
              {stop, {cert_and_pkey, {Props, Cert, sanitize_value(PKey)}}};
          ({{metakv, K}, {?METAKV_SENSITIVE, V}}) ->
              {stop, {{metakv, K}, {?METAKV_SENSITIVE, sanitize_value(V)}}};
          ({cookie, Cookie}) ->
              {stop, {cookie, ns_cookie_manager:sanitize_cookie(Cookie)}};
          ({privateKeyPassphrase, _}) ->
              {stop, {privateKeyPassphrase, "*****"}};
          ({clientPrivateKeyPassphrase, _}) ->
              {stop, {clientPrivateKeyPassphrase, "*****"}};
          ({UName, {auth, Auth}}) ->
              {stop, {tag_user_name(UName),
                      {auth, sanitize(Auth, TagUserTuples)}}};
          ({?HASHES_KEY, V}) ->
              {stop, {?HASHES_KEY, sanitize_value(V)}};
          ({?OLD_HASH_KEY, V}) ->
              {stop, {?OLD_HASH_KEY, sanitize_value(V)}};
          ({<<"plain">>, V}) ->
              {stop, {<<"plain">>, sanitize_value(V)}};
          ({Key, ListUsers}) when Key =:= disabled_users orelse
                                  Key =:= disabled_userids ->
              TaggedUsers = [{tag_user_name(N), Src} || {N, Src} <- ListUsers],
              {stop, {Key, TaggedUsers}};
          ({newURL, _URLBin}) ->
              {stop, {newURL, "<sanitized>"}};
          ({contact_name, ContactName}) ->
              {stop, {contact_name, tag_misc_item(ContactName)}};
          ({contact_email, ContactEmail}) ->
              {stop, {contact_email, tag_misc_item(ContactEmail)}};
          ({org_display_name, OrgDisplayName}) ->
              {stop, {org_display_name, tag_misc_item(OrgDisplayName)}};
          ({org_name, OrgName}) ->
              {stop, {org_name, tag_misc_item(OrgName)}};
          ({org_url, OrgURL}) ->
              {stop, {org_url, tag_misc_item(OrgURL)}};
          ({group, GroupName}) ->
              {stop, {group, tag_group_name(GroupName)}};
          ({key, Bin}) when is_binary(Bin) ->
              {stop, {key, <<"******">>}};
          (Other) ->
              Continue(Other)
      end, Config).

sanitize_value(Value) ->
    sanitize_value(Value, []).

sanitize_value(_Value0, [mask]) ->
    {sanitized, <<"*****">>};
sanitize_value(Value0, Options) ->
    Salt = case Options of
               [add_salt] ->
                   crypto:strong_rand_bytes(32);
               _ ->
                   <<>>
           end,
    Value = term_to_binary(Value0),
    {sanitized,
     base64:encode(crypto:hash(
                     sha256,
                     <<Value/binary, Salt/binary>>))}.

log_kv(K, V) ->
    %% These can get pretty big, so pre-format them for the logger.
    {_, VS} = sanitize({K, V}),
    VB = list_to_binary(io_lib:print(VS, 0, 80, 100)),
    case frequently_changed_key(K) of
        true ->
            ok;
        false ->
            ?log_debug("config change:~n~p ->~n~s", [K, VB])
    end.

frequently_changed_key({local_changes_count, _}) ->
    true;
frequently_changed_key({metakv, <<"/regulator/report", _/binary>>}) ->
    true;
frequently_changed_key(_) ->
    false.

-ifdef(TEST).

%% The audit body jwt_auth builds for a successful authentication, with a
%% custom claim, a nested custom claim and an array claim.
jwt_audit_body() ->
    [{<<"aud">>, [<<"couchbase">>]},
     {<<"department">>, <<"finance">>},
     {<<"exp">>, 1234567890},
     {<<"groups">>, [<<"eng">>, <<"ops">>]},
     {<<"iss">>, <<"https://idp.example.com">>},
     %% menelaus_auth:get_authn_res_audit_props/1 joins the groups into one
     %% binary.
     {<<"mapped_groups">>, <<"admins,ops">>},
     {<<"mapped_roles">>, [<<"bucket_admin[*]">>]},
     {<<"nbf">>, 1234567800},
     {<<"profile">>, {[{<<"email">>, <<"a@example.com">>}]}},
     {<<"sub">>, <<"alice">>},
     {<<"token_roles">>, [<<"cluster_admin">>]},
     {<<"type">>, <<"jwt">>}].

tag_jwt_audit_claims_test() ->
    Tagged = tag_jwt_audit_claims(jwt_audit_body()),
    Get = fun(K) -> proplists:get_value(K, Tagged) end,

    %% Identifiers taken from the token are tagged, whether the claim is a
    %% string or an array, and whichever name the operator gave it.
    ?assertEqual(<<"<ud>alice</ud>">>, Get(<<"sub">>)),
    ?assertEqual([<<"<ud>eng</ud>">>, <<"<ud>ops</ud>">>],
                 Get(<<"groups">>)),

    %% mapped_groups is left to tag_user_tuples_fun/1, which owns it in every
    %% body rather than only in a JWT one. Tagging it here too would nest the
    %% markers.
    ?assertEqual(<<"admins,ops">>, Get(<<"mapped_groups">>)),
    ?assertEqual(<<"<ud>finance</ud>">>, Get(<<"department">>)),

    %% A nested custom claim is tagged at its leaves, keys untouched.
    ?assertEqual({[{<<"email">>, <<"<ud>a@example.com</ud>">>}]},
                 Get(<<"profile">>)),

    %% The claim is whatever the IdP sent, so it is tagged too. It is
    %% audited as token_roles, the event's own roles field being the grant.
    ?assertEqual([<<"<ud>cluster_admin</ud>">>], Get(<<"token_roles">>)),

    %% mapped_roles survived validate_roles/2, so it is a role name and is
    %% left readable. So are the claims that cannot identify anyone.
    ?assertEqual([<<"bucket_admin[*]">>], Get(<<"mapped_roles">>)),
    ?assertEqual([<<"couchbase">>], Get(<<"aud">>)),
    ?assertEqual(<<"https://idp.example.com">>, Get(<<"iss">>)),
    ?assertEqual(<<"jwt">>, Get(<<"type">>)),

    %% Numbers stay numbers, so timestamp claims remain readable.
    ?assertEqual(1234567890, Get(<<"exp">>)),
    ?assertEqual(1234567800, Get(<<"nbf">>)),

    %% Every key of the body survives.
    ?assertEqual(length(jwt_audit_body()), length(Tagged)).

tag_jwt_audit_claims_non_ascii_test() ->
    %% jwt_auth normalizes a claim value by the type declared for the claim,
    %% so a value carrying anything above ASCII arrives here as a utf8 binary
    %% rather than as the list of byte values this would have recursed into
    %% and left untagged.
    Body = [{<<"groups">>, [<<"Ingenjörer"/utf8>>]},
            {<<"sub">>, <<"Алиса"/utf8>>},
            {<<"type">>, <<"jwt">>}],
    Tagged = tag_jwt_audit_claims(Body),
    ?assertEqual(<<"<ud>Алиса</ud>"/utf8>>,
                 proplists:get_value(<<"sub">>, Tagged)),
    ?assertEqual([<<"<ud>Ingenjörer</ud>"/utf8>>],
                 proplists:get_value(<<"groups">>, Tagged)).

tag_jwt_audit_claims_only_for_jwt_test() ->
    %% A body that is not a JWT audit record is returned untouched, so the
    %% other callers of tag_user_data/1 are unaffected.
    Other = [{<<"sub">>, <<"alice">>}, {<<"type">>, <<"saml">>}],
    ?assertEqual(Other, tag_jwt_audit_claims(Other)),
    ?assertEqual([], tag_jwt_audit_claims([])),
    ?assertEqual({user, <<"alice">>},
                 tag_jwt_audit_claims({user, <<"alice">>})).

tag_jwt_audit_failure_test() ->
    %% A failure body carries the reason and no mapped values. The reason is
    %% ns_server text, not a claim, so it stays readable.
    Body = [{<<"reason">>, <<"Token has expired">>},
            {<<"sub">>, <<"alice">>},
            {<<"type">>, <<"jwt">>}],
    Tagged = tag_jwt_audit_claims(Body),
    ?assertEqual(<<"Token has expired">>,
                 proplists:get_value(<<"reason">>, Tagged)),
    ?assertEqual(<<"<ud>alice</ud>">>,
                 proplists:get_value(<<"sub">>, Tagged)).

tag_user_data_tags_jwt_claims_test() ->
    %% The whole path: tag_user_data/1 is what ns_audit calls.
    Tagged = tag_user_data(jwt_audit_body()),
    ?assertEqual(<<"<ud>alice</ud>">>,
                 proplists:get_value(<<"sub">>, Tagged)),

    %% The claim pass leaves mapped_groups alone and tag_user_tuples_fun/1
    %% tags it, so the whole path tags it exactly once. Nested markers would
    %% defeat the non-greedy redaction rule.
    ?assertEqual(<<"<ud>admins,ops</ud>">>,
                 proplists:get_value(<<"mapped_groups">>, Tagged)).

%% The body menelaus_web_rbac:handle_access_forbidden/3 audits. It carries
%% mapped_groups with no type claim, so tag_jwt_audit_claims/1 does not fire
%% and the key clause is the only thing tagging it. This is the case that
%% reached debug.log in the clear.
access_forbidden_body() ->
    [{raw_url, <<"/pools/default/buckets">>},
     {<<"expiry_with_leeway">>, <<"2026-08-26T12:00:00">>},
     {<<"mapped_groups">>, <<"admins,ops">>},
     {<<"mapped_roles">>, <<"bucket_admin[*]">>}].

tag_user_data_tags_mapped_groups_without_a_type_claim_test() ->
    Tagged = tag_user_data(access_forbidden_body()),
    Get = fun(K) -> proplists:get_value(K, Tagged) end,
    ?assertEqual(<<"<ud>admins,ops</ud>">>, Get(<<"mapped_groups">>)),

    %% mapped_roles stays readable here for the same reason it does in a JWT
    %% body, and the expiry is a timestamp.
    ?assertEqual(<<"bucket_admin[*]">>, Get(<<"mapped_roles">>)),
    ?assertEqual(<<"2026-08-26T12:00:00">>, Get(<<"expiry_with_leeway">>)).

tag_user_data_tags_credential_fields_test() ->
    %% What menelaus_web_credentials:format_audit_params/3 emits, after
    %% ns_audit:prepare_list/1 has turned the strings into binaries.
    Body = [{credential_id, <<"alice-backup">>},
            {credential_description, <<"nightly backup to s3">>},
            {prefix, <<"alice-">>},
            {type, <<"password">>},
            {count, 3}],
    Tagged = tag_user_data(Body),
    Get = fun(K) -> proplists:get_value(K, Tagged) end,
    ?assertEqual(<<"<ud>alice-backup</ud>">>, Get(credential_id)),
    ?assertEqual(<<"<ud>nightly backup to s3</ud>">>,
                 Get(credential_description)),
    ?assertEqual(<<"<ud>alice-</ud>">>, Get(prefix)),

    %% The credential type is a closed vocabulary and the count is a number.
    ?assertEqual(<<"password">>, Get(type)),
    ?assertEqual(3, Get(count)).

%% What ns_audit:settings/3 builds for modify_jwt. It wraps every settings
%% audit as [{settings, {KVs}}], so the pair menelaus_web_jwt supplies ends up
%% nested inside an ejson object rather than at the top level of the body, and
%% prepare_list/1 has already dropped the {json, _} marker by then.
jwt_settings_body(Settings) ->
    [{settings, {[{jwt_settings, Settings}]}}].

tag_user_data_tags_jwt_settings_test() ->
    %% menelaus_web_jwt audits the encoded response, so the whole document
    %% arrives as one binary with nothing left to walk into, and is tagged as
    %% one item.
    Settings = <<"{\"issuers\":[{\"name\":\"idp\",\"groupsMaps\":"
                 "[\"eng->admins\"]}]}">>,
    ?assertEqual(jwt_settings_body(<<"<ud>", Settings/binary, "</ud>">>),
                 tag_user_data(jwt_settings_body(Settings))),

    %% A delete audits an atom, which has nothing to tag.
    ?assertEqual(jwt_settings_body(deleted),
                 tag_user_data(jwt_settings_body(deleted))).

-endif.
