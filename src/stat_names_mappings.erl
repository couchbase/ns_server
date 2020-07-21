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
-module(stat_names_mappings).

-export([pre_70_stats_to_prom_query/2, prom_name_to_pre_70_name/2]).

pre_70_stats_to_prom_query(StatSection, StatList) ->
    {Instance, Type} =
        case StatSection of
            "@global" -> {"ns_server", "audit"};
            "@system" -> {"ns_server", "system"};
            "@system-processes" -> {"ns_server", "system-processes"}
        end,

    CommonLabels = [{<<"instance">>, Instance}, {<<"type">>, Type}],

    Metrics = case StatList of
                  all -> [{[], []}];
                  L ->
                      misc:groupby_map(
                        fun ({Name, Labels}) ->
                            {lists:usort(Labels), Name}
                        end,
                        [pre_70_name_to_prom_name(StatSection, S) || S <- L])
              end,

    Asts =
        lists:map(
          fun ({Labels, Names}) ->
                  NamesStr = lists:join("|", lists:usort(Names)),
                  {[{re, <<"name">>, NamesStr} || NamesStr =/= ""] ++
                   [{eq, K, V} || {K, V} <- Labels ++ CommonLabels]}
          end, Metrics),
    prometheus:format_promql({'or', Asts}).

pre_70_name_to_prom_name(Section, Name) when is_atom(Name) ->
    pre_70_name_to_prom_name(Section, atom_to_binary(Name, latin1));
pre_70_name_to_prom_name("@system", Name) -> {<<"sys_", Name/binary>>, []};
pre_70_name_to_prom_name("@system-processes", Name) ->
    case binary:split(Name, <<"/">>) of
        [ProcName, MetricName] ->
            {MetricName, [{proc, ProcName}]};
        _ ->
            {Name, []}
    end;
pre_70_name_to_prom_name("@global", Name) -> {Name, []}.

prom_name_to_pre_70_name(Bucket, {JSONProps}) ->
    BinName =
        case proplists:get_value(<<"name">>, JSONProps) of
            <<"sys_", Name/binary>> -> Name;
            <<"sysproc_", Name/binary>> ->
                Proc = proplists:get_value(<<"proc">>, JSONProps, <<>>),
                <<Proc/binary, "/", Name/binary>>;
            <<"audit_", _/binary>> = Name -> Name
        end,
    %% Since pre-7.0 stats don't care much about stats name type,
    %% 7.0 stats have to convert names to correct types based on stat section.
    case key_type_by_stat_type(Bucket) of
        atom -> binary_to_atom(BinName, latin1);
        binary -> BinName
    end.

key_type_by_stat_type("@global") -> atom;
key_type_by_stat_type("@system") -> atom;
key_type_by_stat_type("@system-processes") -> binary.
