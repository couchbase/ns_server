-module(yaml).

-export([encode/1]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

encode(Term) ->
    iolist_to_binary(lists:join("\n", format(Term))).

format(#{} = Map) ->
    lists:flatmap(
      fun ({K, V}) ->
          KBin = if
                     is_atom(K) -> atom_to_binary(K, latin1);
                     is_binary(K) -> K
                 end,
          case format(V) of
              [] -> [[KBin, ":"]];
              [Line] when not is_list(V) -> [[KBin, ": ", Line]];
              [_|_] = MultiLine ->
                  [[KBin, ":"]] ++
                  ["  " ++ L || L <- MultiLine]
          end
      end, maps:to_list(Map));
format([]) ->
    [];
format([El | Tail]) ->
    case format(El) of
        [] ->
            ["-"];
        Lines when is_list(El) ->
            ["-"] ++ ["  " ++ L || L <- Lines];
        [First | Rest] ->
            ["- " ++ First] ++ ["  " ++ L || L <- Rest]
    end ++ format(Tail);
format({Format, Args}) ->
    format(iolist_to_binary(io_lib:format(Format, Args)));
format(N) when is_integer(N) ->
    [integer_to_binary(N)];
format(F) when is_float(F) ->
    [float_to_binary(F)];
format(A) when is_atom(A) ->
    [["'", atom_to_binary(A, latin1), "'"]];
format(B) when is_binary(B) ->
    [["'", B, "'"]].

-ifdef(TEST).
encode_test() ->
    ?assertEqual(encode([]), <<>>),
    ?assertEqual(encode(#{}), <<>>),
    ?assertEqual(encode([atom1, <<"bin">>, 123, {"format ~b and ~b", [1, 2]}]),
                 <<"- 'atom1'\n"
                   "- 'bin'\n"
                   "- 123\n"
                   "- 'format 1 and 2'">>),
    ?assertEqual(encode(#{atom1 => 123, <<"binary1">> => atom2}),
                 <<"atom1: 123\n"
                   "binary1: 'atom2'">>),
    ?assertEqual(encode([[], [1, 2]]),
                 <<"-\n"
                   "-\n"
                   "  - 1\n"
                   "  - 2">>),
    ?assertEqual(encode(#{global =>
                            #{scrape_interval => <<"10s">>,
                              scrape_timeout  => <<"20s">>},
                          scrape_configs => [
                              #{job_name => general,
                                metrics_path => <<"/_prometheusMetrics">>,
                                basic_auth =>
                                  #{username => <<"test">>,
                                    password_file => <<"/test/path">>},
                                static_configs => [
                                    #{targets => [<<"127.0.0.1:9000">>,
                                                  <<"[::1]:9200">>]}
                                  ],
                                metric_relabel_configs => [
                                    #{source_labels => [<<"__name__">>],
                                      target_label => <<"name">>}
                                  ],
                                relabel_configs => [
                                    #{regex => <<"127\\.0\\.0\\.1:9000">>,
                                      source_labels => [<<"__address__">>],
                                      target_label => instance,
                                      replacement => ns_server},
                                    #{regex => <<"127\\.0\\.0\\.1:9200">>,
                                      source_labels => [<<"__address__">>],
                                      target_label => instance,
                                      replacement => fts}
                                  ]}]}),
                 <<"global:\n"
                   "  scrape_interval: '10s'\n"
                   "  scrape_timeout: '20s'\n"
                   "scrape_configs:\n"
                   "  - basic_auth:\n"
                   "      password_file: '/test/path'\n"
                   "      username: 'test'\n"
                   "    job_name: 'general'\n"
                   "    metric_relabel_configs:\n"
                   "      - source_labels:\n"
                   "          - '__name__'\n"
                   "        target_label: 'name'\n"
                   "    metrics_path: '/_prometheusMetrics'\n"
                   "    relabel_configs:\n"
                   "      - regex: '127\\.0\\.0\\.1:9000'\n"
                   "        replacement: 'ns_server'\n"
                   "        source_labels:\n"
                   "          - '__address__'\n"
                   "        target_label: 'instance'\n"
                   "      - regex: '127\\.0\\.0\\.1:9200'\n"
                   "        replacement: 'fts'\n"
                   "        source_labels:\n"
                   "          - '__address__'\n"
                   "        target_label: 'instance'\n"
                   "    static_configs:\n"
                   "      - targets:\n"
                   "          - '127.0.0.1:9000'\n"
                   "          - '[::1]:9200'">>).

-endif.
