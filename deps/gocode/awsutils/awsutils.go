// @author Couchbase <info@couchbase.com>
// @copyright 2024-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.

package awsutils

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"gocloud.dev/secrets"
	"gocloud.dev/secrets/awskms"
)

func keeperGetError(err error) error {
	return fmt.Errorf("failed to get keeper due to error: %w", err)
}

func getAwsSecretsKeeper(ctx context.Context, keyArn string) (*secrets.Keeper, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, keeperGetError(err)
	}

	client, err := awskms.DialV2(cfg)
	if err != nil {
		return nil, keeperGetError(err)
	}

	keeper := awskms.OpenKeeperV2(client, keyArn, nil)
	return keeper, nil
}

func KmsEncryptData(keyArn string, data []byte) ([]byte, error) {
	ctx := context.Background()
	keeper, err := getAwsSecretsKeeper(ctx, keyArn)
	if err != nil {
		return nil, err
	}

	defer keeper.Close()

	encryptedData, err := keeper.Encrypt(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt data error: %w", err)
	}
	return encryptedData, nil
}

func KmsDecryptData(keyArn string, data []byte) ([]byte, error) {
	ctx := context.Background()
	keeper, err := getAwsSecretsKeeper(ctx, keyArn)
	if err != nil {
		return nil, err
	}

	defer keeper.Close()

	decryptedData, err := keeper.Decrypt(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data error: %w", err)
	}

	return decryptedData, nil
}
