GetCAs =
    fun () ->
            [proplists:get_value(pem, P) ||
                P <- ns_server_cert:trusted_CAs(props)]
    end,
GetChains =
    fun () ->
            [{N, T, Pem} || N <- ns_node_disco:nodes_wanted(),
                            T <- [node_cert, client_cert],
                            Pem <- [proplists:get_value(
                                      pem,
                                      ns_config:read_key_fast({node, N, T},
                                                              []))]]
    end,
CAPems = GetCAs(),
Chains = GetChains(),
PemToCerts =
    fun (Pem) ->
            [{Der, public_key:pkix_decode_cert(Der, otp)} ||
                {'Certificate', Der, not_encrypted} <-
                    public_key:pem_decode(Pem)]
    end,
TBS = fun ({_Der, {'OTPCertificate', T, _, _}}) -> T end,
Version =
    fun (C) ->
            {'OTPTBSCertificate', V, _, _, _, _, _, _, _, _, _} = TBS(C),
            case V of
                0 -> v1;
                v1 -> v1;
                1 -> v2;
                v2 -> v2;
                2 -> v3;
                v3 -> v3
            end
    end,
Extensions =
    fun (C) ->
            {'OTPTBSCertificate', _, _, _, _, _, _, _, _, _, Exts} = TBS(C),
            case Exts of
                asn1_NOVALUE -> [];
                L when is_list(L) -> L
            end
    end,
IsSelfSigned = fun ({_Der, Otp}) -> public_key:pkix_is_self_signed(Otp) end,
IsCA =
    fun (C) ->
            Exts = Extensions(C),
            Decoded = [{Id, V} || {'Extension', Id, _, V} <- Exts],
            true = length(Decoded) =:= length(Exts),
            case [V || {{2,5,29,19}, V} <- Decoded] of
                [{'BasicConstraints', true, _}] -> true;
                [{'BasicConstraints', false, _}] -> false;
                [] -> missing
            end
    end,
AttrValue =
    fun ({utf8String, V}) -> unicode:characters_to_list(V);
        ({_, V}) when is_list(V) -> V;
        ({_, V}) when is_binary(V) -> binary_to_list(V);
        (V) when is_list(V) -> V;
        (V) when is_binary(V) -> binary_to_list(V);
        (V) -> io_lib:format("~p", [V])
    end,
AttrNames = [{{2,5,4,3}, "CN"}, {{2,5,4,11}, "OU"}, {{2,5,4,10}, "O"}],
Subject =
    fun (C) ->
            try
                {'OTPTBSCertificate', _, _, _, _, _, {rdnSequence, RDNs},
                 _, _, _, _} = TBS(C),
                Parts = [Name ++ "=" ++ AttrValue(V) ||
                            RDN <- RDNs,
                            {'AttributeTypeAndValue', T, V} <- RDN,
                            {T1, Name} <- AttrNames, T1 =:= T],
                case Parts of
                    [] -> "(no CN/OU/O)";
                    _ -> lists:flatten(lists:join(", ", Parts))
                end
            catch _:_ -> "(unknown subject)"
            end
    end,
CheckIntermediate =
    fun (C) ->
            case {Version(C), IsCA(C)} of
                {v3, true} ->
                    [];
                {v3, missing} ->
                    [{C, "has no basicConstraints extension, so it can't "
                      "be an intermediate CA"}];
                {v3, false} ->
                    [{C, "has basicConstraints CA:FALSE, so it can't be "
                      "an intermediate CA"}];
                {V, _} ->
                    [{C, "is an X.509 " ++ atom_to_list(V) ++ " certificate; "
                      "Erlang/OTP 28.5.0.8 and later reject v1/v2 "
                      "intermediate CAs"}]
            end
    end,
CheckIntermediates =
    fun (Certs) ->
            lists:usort(
              lists:append([CheckIntermediate(C) || C <- Certs,
                                                    not IsSelfSigned(C)]))
    end,
Run =
    fun (F) ->
            try F() of
                [] -> ok;
                Problems -> {problems, Problems}
            catch E:R -> {error, {E, R}}
            end
    end,
TypeName = fun (node_cert) -> "server certificate";
               (client_cert) -> "internal client certificate"
           end,
CAResult =
    {"Trusted CAs",
     Run(fun () ->
                 CheckIntermediates(
                   lists:append([PemToCerts(P) || P <- CAPems]))
         end)},
ChainResults =
    [{io_lib:format("~s ~s", [N, TypeName(T)]),
      case Pem of
          undefined ->
              not_found;
          _ ->
              Run(fun () ->
                          [_Leaf | Rest] = PemToCerts(Pem),
                          CheckIntermediates(Rest)
                  end)
      end} || {N, T, Pem} <- Chains,
              Pem =/= undefined orelse T =/= client_cert],
Results = [CAResult | ChainResults],
FormatResult =
    fun ({Label, Res}) ->
            Prefix = [Label, ": "],
            case Res of
                ok ->
                    [Prefix, "OK\n"];
                not_found ->
                    [Prefix, "not found\n"];
                {error, Err} ->
                    [Prefix, io_lib:format("COULD NOT CHECK: ~p~n", [Err])];
                {problems, Ps} ->
                    [Prefix, "PROBLEM\n" |
                     [io_lib:format("    \"~ts\" ~ts~n", [Subject(C), Msg]) ||
                         {C, Msg} <- Ps]]
            end
    end,
Safe = lists:all(fun ({_, ok}) -> true;
                     ({_, not_found}) -> true;
                     (_) -> false
                 end, Results),
OTPRelease = erlang:system_info(otp_release),
OTPVersion =
    case file:read_file(filename:join([code:root_dir(), "releases",
                                       OTPRelease, "OTP_VERSION"])) of
        {ok, V} -> string:trim(binary_to_list(V));
        _ -> OTPRelease
    end,
Verdict =
    case Safe of
        true ->
            "RESULT: SAFE TO UPGRADE\n";
        false ->
            "RESULT: NOT SAFE TO UPGRADE\n\n"
            "Erlang/OTP 28.5.0.8 and later reject any certificate chain that "
            "goes\nthrough an intermediate CA listed above. After the "
            "upgrade, nodes using\nsuch chains may fail to start or to "
            "connect to each other.\n\n"
            "Before upgrading: re-issue each listed intermediate CA as an "
            "X.509 v3\ncertificate with basicConstraints CA:TRUE. Replace it "
            "in the trusted CAs\nand re-sign the node and client "
            "certificates that use it. Load them\non the current version, "
            "then run this check again.\n"
    end,
Text = ["Certificate check before upgrading to Erlang/OTP 28.5.0.8 "
        "(MB-74788)\n",
        io_lib:format("Checked on ~s, Erlang/OTP ~s, ~b trusted CA(s)~n~n",
                      [node(), OTPVersion, length(CAPems)]),
        [FormatResult(R) || R <- Results],
        "\n", Verdict],
menelaus_util:reply_text(Req, unicode:characters_to_binary(Text), 200),
done
