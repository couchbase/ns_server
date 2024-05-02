-ifndef(_CLUSTER_SECRETS__HRL_).
-define(_CLUSTER_SECRETS__HRL_,).

-define(CHRONICLE_SECRETS_KEY, cluster_secrets).
-define(CHRONICLE_NEXT_ID_KEY, cluster_secrets_next_id).
-define(GENERATED_KEY_TYPE, 'auto-generated-aes-key-256').
-define(AWSKMS_KEY_TYPE, 'awskms-aes-key-256').
-define(ENVELOP_CIPHER, aes_256_gcm).

-endif.
