%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Handles mapping of external identities (users, groups, roles) to
%% Couchbase identities using configurable regex rules.
%%
%% Each mapping rule consists of a pattern regex and a transformation template.
%% The pattern has to match the whole input value, and if it does, the
%% template is expanded to produce the output value.
%%
%% For example, the rule "(.*)@example.com cb-\\1" will map any email
%% address ending in @example.com to cb-<token preceding @example.com>.
%%
%% Each rule performs a single transformation, mapping one input value
%% to one output value (i.e., one group maps to one group, not multiple groups).
%% If multiple group/role mappings are needed, multiple rules should be used.
%%
%% Mapping behavior:
%% - Users: A user can only be mapped to a single value. The first rule that
%%   matches is used, and if its result is not a usable user name the
%%   authentication fails. StopFirstMatch is ignored.
%% - Groups & Roles: Multiple values can be mapped using multiple rules.
%%   Each value can match multiple rules, and behavior is controlled by
%%   `StopFirstMatch`:
%%   - `true`  → Stop at the first rule that matches. The value maps to that
%%     rule's result, or to nothing if the result is rejected.
%%   - `false` → Continue matching in priority order, collecting the results of
%%     every rule that matches.
%% By default, if no rules are specified, the identity is mapped to itself.
-module(auth_mapping).

-include("ns_common.hrl").
-include("rbac.hrl").

-export([validate_mapping_rule/1,
         map_identities/4,
         map_user/2,
         format_mapping_rules/1]).

%% Used when no mapping rules are configured, so that a value maps to itself.
-define(IDENTITY_RULE, {"^(.*)$", "\\1"}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% Types that can be mapped from external auth systems to Couchbase
-type mapped_type() :: user | groups | {roles, public | all}.
-type mapping_rule_str() :: string().
-type mapping_rule() :: {string(), string()}.
-type input_value() :: string().
-type mapped_user() :: string().
-type mapped_group() :: string().
-type mapped_role() :: rbac_role().
-type mapped_result() :: [mapped_user()] | [mapped_group()] | [mapped_role()].

%% @doc Validate a mapping rule that transforms a claim's value. A mapping rule
%% is a space-separated pair of a regular expression pattern and a substitution
%% template.
%%
%% The rule is split on the first space, so the pattern cannot contain a literal
%% space. Use \s (or \x20, [[:space:]]) to match whitespace in the value being
%% mapped. The template cannot contain whitespace at all, because every value it
%% can produce is a user, group or role name, and none of those may contain it.
-spec validate_mapping_rule(MappingRule :: mapping_rule_str()) ->
          {value, mapping_rule()} | {error, binary()}.
validate_mapping_rule(RuleStr) ->
    Trimmed = string:trim(RuleStr),
    %% Validates that only as many captured groups as the template are present
    %% in the pattern. Note that re:compile will not choke on the cases where we
    %% use special characters '[]:'.
    case re:compile(Trimmed) of
        {ok, _} ->
            case string:split(Trimmed, " ", leading) of
                [Pattern, Template] ->
                    Backreference = re:run(Template, "\\\\g"),
                    case re:run(Template, "\\s") of
                        {match, _} ->
                            {error, "Mapping rule template must not contain "
                             "whitespace, since user, group and role names "
                             "cannot. To match whitespace in the value being "
                             "mapped, use \\s in the pattern"};
                        nomatch when Backreference =/= nomatch ->
                            {error, "Mapping rule template must name a "
                             "capture group as \\1 to \\9. The \\g and \\g{} "
                             "spellings are not supported"};
                        nomatch ->
                            %% Validate the pattern separately.
                            case re:compile(Pattern) of
                                {ok, _} -> {value, {Pattern, Template}};
                                {error, {Error, At}} ->
                                    Err = io_lib:format(
                                            "~s (at character #~b)",
                                            [Error, At]),
                                    {error, lists:flatten(Err)}
                            end
                    end;
                _ ->
                    {error, "Invalid mapping rule"}
            end;
        {error, {Error, At}} ->
            Err = io_lib:format("~s (at character #~b)", [Error, At]),
            {error, lists:flatten(Err)}
    end.

%% @doc Applies a single regex mapping rule
%% A mapping rule is a string of the form "pattern template", split on the
%% first space. For example the rule "(.*)@example.com cb-\\1" maps any
%% address at example.com to cb- followed by the part before the @.
%%
%% The pattern has to match the whole value. It is wrapped in ^(?: )$ before
%% compiling, so a rule cannot match a fragment of a name and map it as
%% though it had matched all of it. The group is non capturing, which keeps
%% the pattern's own group numbers.
%%
%% The template is expanded here rather than handed to re:replace/4, so it
%% means one thing only: \1 to \9 name a capture group of the pattern, a
%% backslash before any other character yields that character, and anything
%% else is a literal. re:replace/4 interprets more than that. It gives & the
%% whole match and accepts \gN and \g{N} as further spellings of a capture,
%% neither of which a name wants, and it substitutes into the value rather
%% than building a result, so whatever the pattern did not match is carried
%% into the name. Expanding the template here removes all of it and leaves
%% re:run/3 answering only whether the value matched and what it captured,
%% which is the part of re that does not vary with the regex engine
%% underneath it.
-spec apply_mapping_rule(Value :: input_value(), Rule :: mapping_rule()) ->
          string() | nomatch.
apply_mapping_rule(Value, {Pattern, Template}) ->
    {ok, MP} = re:compile("^(?:" ++ Pattern ++ ")$"),
    case re:run(Value, MP, [{capture, all_but_first, list}, notempty]) of
        {match, Captures} ->
            expand_template(Template, Captures);
        nomatch ->
            nomatch
    end.

-spec expand_template(Template :: string(), Captures :: [string()]) ->
          string().
expand_template([$\\, N | Rest], Captures) when N >= $1, N =< $9 ->
    capture(N - $0, Captures) ++ expand_template(Rest, Captures);
expand_template([$\\, C | Rest], Captures) ->
    [C | expand_template(Rest, Captures)];
expand_template([C | Rest], Captures) ->
    [C | expand_template(Rest, Captures)];
expand_template([], _Captures) ->
    [].

%% A template cannot name a group the pattern does not have, since
%% validate_mapping_rule/1 rejects the rule. Tolerate it rather than fail an
%% authentication, should a rule ever reach here without being validated.
-spec capture(N :: pos_integer(), Captures :: [string()]) -> string().
capture(N, Captures) when N =< length(Captures) ->
    lists:nth(N, Captures);
capture(_N, _Captures) ->
    "".

%% @doc Maps a single value (user or a single group or role)
-spec map_value(Type :: mapped_type(),
                Value :: input_value(),
                Rules :: [mapping_rule()],
                StopFirstMatch :: boolean()) -> mapped_result().
map_value(Type, Value, Rules, StopFirstMatch) ->
    try_rules(Type, Value, Rules, StopFirstMatch, []).

-spec try_rules(mapped_type(), input_value(), [mapping_rule()],
                boolean(), [mapped_result()]) -> [mapped_result()].
try_rules(_Type, _Value, [], _StopFirstMatch, Results) ->
    Results;
try_rules(Type, Value, [Rule | Rest], StopFirstMatch, Acc) ->
    case apply_mapping_rule(Value, Rule) of
        nomatch ->
            try_rules(Type, Value, Rest, StopFirstMatch, Acc);
        Result ->
            case extract_mapped_result(Type, Result) of
                {ok, ValidResult} when StopFirstMatch -> [ValidResult];
                {ok, ValidResult} ->
                    try_rules(Type, Value, Rest, StopFirstMatch,
                              [ValidResult | Acc]);
                {error, _} when StopFirstMatch -> Acc;
                {error, _} ->
                    try_rules(Type, Value, Rest, StopFirstMatch, Acc)
            end
    end.

%% @doc Validates mapped result based on type
-spec extract_mapped_result(mapped_type(), mapped_result()) ->
          {ok, mapped_result()} | {error, binary()}.
extract_mapped_result(user, Value) ->
    case menelaus_web_rbac:validate_cred(Value, username) of
        true ->
            case menelaus_auth:is_external_auth_allowed(Value) of
                false ->
                    ?log_warning("User:~s cannot use external auth.",
                                 [ns_config_log:tag_user_name(Value)]),
                    {error, <<"External auth not allowed">>};
                true ->
                    {ok, Value}
            end;
        Error ->
            ?log_warning("Invalid user: ~s. ~s",
                         [ns_config_log:tag_user_name(Value), Error]),
            {error, Error}
    end;
extract_mapped_result(groups, Value) ->
    case menelaus_users:group_exists(Value) of
        true ->
            {ok, Value};
        false ->
            ?log_warning("Ignoring invalid group: ~s",
                         [ns_config_log:tag_group_name(Value)]),
            {error, <<"Invalid group">>}
    end;
extract_mapped_result({roles, RolesScope}, Value) ->
    case menelaus_web_rbac:parse_roles(Value) of
        [{error, _}] ->
            ?log_warning("Ignoring invalid roles ~s",
                         [ns_config_log:tag_misc_item(Value)]),
            {error, <<"Invalid role format">>};
        [ParsedRole] ->
            case menelaus_roles:validate_roles([ParsedRole], RolesScope) of
                {[ValidRole], []} ->
                    {ok, ValidRole};
                {[], [_InvalidRole]} ->
                    ?log_warning("Ignoring invalid role: ~s",
                                 [ns_config_log:tag_misc_item(Value)]),
                    {error, <<"Invalid role">>}
            end;
        _ ->
            ?log_warning("Ignoring invalid roles: ~s",
                         [ns_config_log:tag_misc_item(Value)]),
            {error, <<"Invalid role format">>}
    end.

%% @doc Maps external identities to Couchbase identities using provided rules.
%% For users: expects a single-element list (StopFirstMatch is ignored)
%% For groups/roles: expects a list of values
-spec map_identities(Type :: mapped_type(),
                     Values :: [input_value()],
                     Rules :: [mapping_rule()],
                     StopFirstMatch :: boolean()) ->
          mapped_result().
%% Apply the identity mapping if mapping rules aren't supplied.
map_identities(Type, Values, [], StopFirstMatch) ->
    map_identities(Type, Values, [?IDENTITY_RULE], StopFirstMatch);
map_identities(Type, Values, Rules, StopFirstMatch) ->
    lists:usort(
      lists:flatmap(fun(Value) ->
                            map_value(Type, Value, Rules, StopFirstMatch)
                    end, Values)).

%% @doc Maps a single external user name, keeping the reason a mapping failed.
%%
%% map_identities/4 drops values it cannot map, because a login must still
%% proceed with whichever groups and roles did map. A user is different: if it
%% cannot be mapped the authentication fails, and the caller has to report why.
%%
%% Rules are in priority order and the first one to match decides the outcome.
%% When no rule matches there is no mapped value to report on, only the absence.
-spec map_user(Value :: input_value(), Rules :: [mapping_rule()]) ->
          {ok, mapped_user()} | {error, binary()}.
map_user(Value, []) ->
    map_user(Value, [?IDENTITY_RULE]);
map_user(Value, Rules) ->
    try_user_rules(Value, Rules).

-spec try_user_rules(input_value(), [mapping_rule()]) ->
          {ok, mapped_user()} | {error, binary()}.
try_user_rules(_Value, []) ->
    {error, <<"Username not provisioned">>};
try_user_rules(Value, [Rule | Rest]) ->
    case apply_mapping_rule(Value, Rule) of
        nomatch -> try_user_rules(Value, Rest);
        Mapped -> extract_mapped_result(user, Mapped)
    end.

-spec format_mapping_rules(undefined | [{string(), string()}]) ->
          undefined | [binary()].
format_mapping_rules(undefined) -> undefined;
format_mapping_rules(Rules) ->
    lists:map(fun({Pattern, Template}) ->
                      list_to_binary(string:join([Pattern, Template], " "))
              end, Rules).

-ifdef(TEST).

validate_mapping_rule_test_() ->
    [
     %% Valid rules
     ?_assertEqual({value, {"^GoogleUser:(.*)", "\\1"}},
                   validate_mapping_rule("^GoogleUser:(.*) \\1")),
     ?_assertEqual({value, {"^(.*)@(.*)\\.com", "\\2-\\1"}},
                   validate_mapping_rule("^(.*)@(.*)\\.com \\2-\\1")),
     ?_assertEqual({value, {"(.*)", "user-\\1"}},
                   validate_mapping_rule("(.*) user-\\1")),

     %% Rules with special characters
     ?_assertEqual({value, {"^Role:(.*):(.*):admin",
                            "data_writer[\\1:\\2:c1]"}},
                   validate_mapping_rule("^Role:(.*):(.*):admin "
                                         "data_writer[\\1:\\2:c1]")),
     ?_assertEqual({value, {"^Group:analytics:(.*)",
                            "analytics_reader[\\1]"}},
                   validate_mapping_rule("^Group:analytics:(.*) "
                                         "analytics_reader[\\1]")),

     %% Invalid patterns
     ?_assertMatch({error, _},
                   validate_mapping_rule("[")), % Unmatched bracket
     ?_assertMatch({error, _},
                   validate_mapping_rule("(.*")), % Unmatched parenthesis

     %% Invalid format
     ?_assertEqual({error, "Invalid mapping rule"},
                   validate_mapping_rule("single_part")),
     ?_assertEqual({error, "Invalid mapping rule"},
                   validate_mapping_rule("")),

     %% Invalid template references
     ?_assertMatch({error, _},
                   validate_mapping_rule("(.*) \\2")), % Non-existent group

     %% Template must not contain whitespace
     ?_assertMatch({error, _},
                   validate_mapping_rule("^my group$ cb-admins")),
     ?_assertMatch({error, _},
                   validate_mapping_rule("^admin$ role one")),
     ?_assertMatch({error, _},
                   validate_mapping_rule("(.*) \\1 extra")),

     %% Whitespace in the value being mapped is matched from the pattern with
     %% an escape instead of a literal space.
     ?_assertEqual({value, {"^my\\sgroup$", "cb-admins"}},
                   validate_mapping_rule("^my\\sgroup$ cb-admins")),
     ?_assertEqual({value, {"^my[[:space:]]group$", "cb-admins"}},
                   validate_mapping_rule("^my[[:space:]]group$ cb-admins")),
     ?_assertEqual({value, {"(.*)\\s(.*)", "cb-\\1-\\2"}},
                   validate_mapping_rule("(.*)\\s(.*) cb-\\1-\\2"))
    ].

whole_value_mapping_test_() ->
    Map = fun(P, T, V) -> apply_mapping_rule(V, {P, T}) end,
    [
     %% A rule whose pattern is anchored and whose template holds only
     %% literals and \\1 to \\9 is unaffected by any of it.
     ?_assertEqual("alice", Map("^(.*)$", "\\1", "alice")),
     ?_assertEqual("cb-alice", Map("^(.*)@x$", "cb-\\1", "alice@x")),
     ?_assertEqual("ro_admin", Map("^readonly$", "ro_admin", "readonly")),
     ?_assertEqual("g-db", Map("^a(.)c(.)e$", "g-\\2\\1", "abcde")),

     %% A nullable pattern matched a second time on the empty string past
     %% the end of the value, expanding the template once per match.
     ?_assertEqual("ui_access", Map("(.*)", "ui_access", "alice")),
     ?_assertEqual("ui_access", Map(".*", "ui_access", "alice")),

     %% notempty still matters once the pattern is anchored: .* matches an
     %% empty value emptily, and a rule must not map nothing to a name.
     ?_assertEqual(nomatch, Map("^(.*)$", "ui_access", "")),

     %% A pattern matching only part of the value no longer maps it. The
     %% remainder used to be carried into the name.
     ?_assertEqual(nomatch, Map("^admin", "super", "admins")),
     ?_assertEqual(nomatch, Map("browser", "ui_access", "browsertest")),
     ?_assertEqual(nomatch, Map("[a-z]*", "ui_access", "alice@example.com")),

     %% An alternation is anchored on every branch, not just the first.
     ?_assertEqual(nomatch, Map("admin|ro", "ro_admin", "administrator")),
     ?_assertEqual("ro_admin", Map("admin|ro", "ro_admin", "admin")),

     %% Replacing every occurrence within the value is not a mapping, and
     %% no longer happens.
     ?_assertEqual(nomatch, Map("-", "_", "a-b-c")),

     %% & is a literal. re:replace/4 gave it the whole match, which turned a
     %% name such as R&D into R<value>D.
     ?_assertEqual("R&D", Map("^(.*)$", "R&D", "alice")),
     ?_assertEqual("cb-&", Map("^(.*)$", "cb-\\&", "alice")),

     %% A backslash before anything that is not 1 to 9 yields the character,
     %% as it did before.
     ?_assertEqual("cb-0", Map("^(.*)$", "cb-\\0", "alice")),
     ?_assertEqual("cb-s", Map("^(.*)$", "cb-\\s", "alice"))
    ].

%% A template names a capture group one way, so the rule is rejected if it
%% names one the pattern does not have or spells the reference differently.
template_reference_test_() ->
    [
     ?_assertMatch({value, _}, validate_mapping_rule("^(.*)$ cb-\\1")),
     ?_assertMatch({error, _}, validate_mapping_rule("^(.*)$ cb-\\2")),
     ?_assertMatch({error, _}, validate_mapping_rule("^(.*)$ cb-\\g1")),
     ?_assertMatch({error, _}, validate_mapping_rule("^(.*)$ cb-\\g{1}"))
    ].

mapping_test_() ->
    {setup,
     fun() ->
             meck:new(menelaus_web_rbac),
             meck:new(menelaus_auth),
             meck:new(menelaus_users),
             meck:new(menelaus_roles),

             meck:expect(menelaus_web_rbac, validate_cred,
                         fun("alice", username) -> true;
                            ("@bob", username) -> true;
                            (_, username) -> <<"Invalid username">>
                         end),

             meck:expect(menelaus_auth, is_external_auth_allowed,
                         fun("@" ++ _) -> false;
                            (_) -> true
                         end),

             meck:expect(menelaus_users, group_exists,
                         fun("cb-admins") -> true;
                            ("users@cb") -> true;
                            (_) -> false
                         end),

             meck:expect(menelaus_web_rbac, parse_roles,
                         fun("admin") -> ["admin"];
                            ("internal") -> ["internal"];
                            ("data_writer[b1:s1:c1]") ->
                                 ["data_writer[b1:s1:c1]"];
                            (_) -> [{error, "Invalid role"}]
                         end),

             meck:expect(menelaus_roles, validate_roles,
                         fun(["admin"], _) ->
                                 {["admin"], []};
                            (["data_writer[b1:s1:c1]"], _) ->
                                 {["data_writer[b1:s1:c1]"], []};
                            (["internal"], all) ->
                                 {["internal"], []};
                            (_, _) -> {[], ["invalid"]}
                         end)
     end,
     fun(_) ->
             meck:unload(menelaus_web_rbac),
             meck:unload(menelaus_auth),
             meck:unload(menelaus_users),
             meck:unload(menelaus_roles)
     end,
     [
      %% Single value, single rule tests
      ?_assertEqual(["alice"],
                    map_identities(user, ["GoogleUser:alice"],
                                   [{"^GoogleUser:(.*)", "\\1"}], true)),
      ?_assertEqual([],
                    map_identities(user, ["GoogleUser:@bob"],
                                   [{"^GoogleUser:(.*)", "\\1"}], true)),
      ?_assertEqual(["cb-admins"],
                    map_identities(groups, ["GoogleGroup:admins"],
                                   [{"^GoogleGroup:(.*)", "cb-\\1"}], true)),
      ?_assertEqual([],
                    map_identities(groups, ["GoogleGroup:users"],
                                   [{"^GoogleGroup:(.*)", "cb-\\1"}], true)),
      ?_assertEqual(["admin"],
                    map_identities({roles, public}, ["GoogleRole:admin"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),
      ?_assertEqual(["admin"],
                    map_identities({roles, all}, ["GoogleRole:admin"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),
      ?_assertEqual([],
                    map_identities({roles, public}, ["GoogleRole:internal"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),
      ?_assertEqual(["internal"],
                    map_identities({roles, all}, ["GoogleRole:internal"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),
      ?_assertEqual([],
                    map_identities({roles, public},
                                   ["GoogleRole:data_reader[b2:s2:c2]"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),

      %% Single value, multiple rules tests
      ?_assertEqual(["alice"],
                    map_identities(user, ["GoogleUser:alice"],
                                   [{"^AzureUser:(.*)", "\\0"},
                                    {"^GoogleUser:(.*)", "\\1"}], true)),
      ?_assertEqual(["cb-admins", "users@cb"],
                    map_identities(groups, ["GoogleGroup:admins"],
                                   [{"^GoogleGroup:(.*)", "cb-\\1"},
                                    {"^GoogleGroup:(.*)", "users@cb"}], false)),
      ?_assertEqual(["cb-admins"],
                    map_identities(groups, ["GoogleGroup:admins"],
                                   [{"^GoogleGroup:(.*)", "cb-\\1"},
                                    {"^GoogleGroup:(.*)", "users@cb"}], true)),
      ?_assertEqual(["admin", "data_writer[b1:s1:c1]"],
                    map_identities({roles, public}, ["GoogleRole:admin"],
                                   [{"^GoogleRole:(.*)", "\\1"},
                                    {"^GoogleRole:admin",
                                     "data_writer[b1:s1:c1]"}],
                                   false)),
      ?_assertEqual(["admin"],
                    map_identities({roles, public}, ["GoogleRole:admin"],
                                   [{"^GoogleRole:(.*)", "\\1"},
                                    {"^GoogleRole:admin",
                                     "data_writer[b1:s1:c1]"}],
                                   true)),

      %% Multiple values tests
      ?_assertEqual(["cb-admins", "users@cb"],
                    map_identities(groups,
                                   ["GoogleGroup:cb-admins",
                                    "GoogleGroup:users@cb"],
                                   [{"^GoogleGroup:(.*)", "\\1"}], true)),
      ?_assertEqual(["admin", "data_writer[b1:s1:c1]"],
                    map_identities({roles, public},
                                   ["GoogleRole:admin",
                                    "GoogleRole:data_writer[b1:s1:c1]"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),

      %% Validates that invalid roles are ignored
      ?_assertEqual(["admin"],
                    map_identities({roles, public},
                                   ["GoogleRole:admin",
                                    "GoogleRole:invalid_role"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),
      ?_assertEqual([],
                    map_identities({roles, public},
                                   ["GoogleRole:invalid1",
                                    "GoogleRole:invalid2"],
                                   [{"^GoogleRole:(.*)", "\\1"}], true)),

      %% Empty values/rules tests
      ?_assertEqual([],
                    map_identities(groups, [],
                                   [{"^GoogleGroup:(.*)", "cb-\\1"}], true)),
      ?_assertEqual(["cb-admins", "users@cb"],
                    map_identities(groups, ["group1", "cb-admins", "users@cb"],
                                   [], true)),

      %% Stopping at the first match means stopping at the rule that matched,
      %% not at the first one whose result was usable, so a rejected result
      %% does not hand the value to a later rule.
      ?_assertEqual([],
                    map_identities(groups, ["GoogleGroup:admins"],
                                   [{"^GoogleGroup:(.*)", "\\1"},
                                    {"^GoogleGroup:(.*)", "cb-\\1"}], true)),
      ?_assertEqual([],
                    map_identities({roles, public}, ["GoogleRole:invalid"],
                                   [{"^GoogleRole:(.*)", "\\1"},
                                    {"^GoogleRole:.*", "admin"}], true)),

      %% Collecting every match is different: each rule contributes on its own,
      %% so a rejected result only drops itself.
      ?_assertEqual(["cb-admins"],
                    map_identities(groups, ["GoogleGroup:admins"],
                                   [{"^GoogleGroup:(.*)", "\\1"},
                                    {"^GoogleGroup:(.*)", "cb-\\1"}], false)),

      %% map_user/2 reports why a mapping failed, where map_identities/4 only
      %% drops the value.
      ?_assertEqual({ok, "alice"},
                    map_user("GoogleUser:alice",
                             [{"^GoogleUser:(.*)", "\\1"}])),
      ?_assertEqual({ok, "alice"}, map_user("alice", [])),

      %% No rule matched, so there is no mapped value to report on.
      ?_assertEqual({error, <<"Username not provisioned">>},
                    map_user("AzureUser:alice",
                             [{"^GoogleUser:(.*)", "\\1"}])),

      %% A rule matched and its result was rejected, so the specific reason is
      %% reported rather than the generic one.
      ?_assertEqual({error, <<"Invalid username">>},
                    map_user("GoogleUser:carol",
                             [{"^GoogleUser:(.*)", "\\1"}])),
      ?_assertEqual({error, <<"External auth not allowed">>},
                    map_user("GoogleUser:bob",
                             [{"^GoogleUser:(.*)", "@\\1"}])),

      %% The first rule to match decides, so a later rule neither reports the
      %% failure nor maps the user itself.
      ?_assertEqual({error, <<"Invalid username">>},
                    map_user("GoogleUser:carol",
                             [{"^GoogleUser:(.*)", "\\1"},
                              {"^GoogleUser:(.*)", "@\\1"}])),
      ?_assertEqual({error, <<"Invalid username">>},
                    map_user("GoogleUser:carol",
                             [{"^GoogleUser:(.*)", "\\1"},
                              {"^GoogleUser:.*", "alice"}])),

      %% A rule that does not match is skipped, so a later rule still applies.
      ?_assertEqual({ok, "alice"},
                    map_user("GoogleUser:carol",
                             [{"^AzureUser:(.*)", "\\1"},
                              {"^GoogleUser:.*", "alice"}]))
     ]}.

-endif.
