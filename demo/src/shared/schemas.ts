import { z } from "zod";

import { CLIENT_ORIGIN, RP_ID } from "./constants.js";

const decimalString = z.string().regex(/^(0|[1-9][0-9]*)$/);
const base64url = z.string().min(1).regex(/^[A-Za-z0-9_-]+$/);

function hexBytes(bytes: number) {
  return z.string().regex(new RegExp(`^0x[0-9a-f]{${bytes * 2}}$`));
}

export const Hash32Schema = hexBytes(32);
export const PublicKeySchema = z
  .string()
  .regex(/^0x04[0-9a-f]{128}$/);
export const AccountLockArgsSchema = z
  .string()
  .regex(/^0x01[0-9a-f]{64}$/);

const DeploymentArtifactSchema = z
  .object({
    name: z.enum(["account_lock", "verifier_p256"]),
    dataHash: Hash32Schema,
    hashType: z.literal("data2"),
    txHash: Hash32Schema,
    index: z.number().int().nonnegative(),
    capacityShannons: decimalString,
  })
  .strict();

export const DeploymentManifestSchema = z
  .object({
    schema_version: z.literal(1),
    network: z.literal("testnet"),
    published: z.literal(true),
    hash_type: z.literal("data2"),
    note: z.string().max(500).optional(),
    artifacts: z
      .object({
        account_lock: DeploymentArtifactSchema.extend({
          name: z.literal("account_lock"),
        }),
        verifier_p256: DeploymentArtifactSchema.extend({
          name: z.literal("verifier_p256"),
        }),
      })
      .strict(),
  })
  .strict();

export const OutPointSchema = z
  .object({
    tx_hash: Hash32Schema,
    index: z.number().int().nonnegative(),
  })
  .strict();

export const AccountManifestSchema = z
  .object({
    schema_version: z.literal(1),
    network: z.literal("testnet"),
    account_id: Hash32Schema,
    account_lock: z
      .object({
        code_hash: Hash32Schema,
        hash_type: z.literal("data2"),
        args: AccountLockArgsSchema,
      })
      .strict(),
    type_id_args: Hash32Schema,
    state_out_point: OutPointSchema,
    asset_out_point: OutPointSchema,
    state_bytes: z.number().int().positive(),
  })
  .strict()
  .superRefine((manifest, context) => {
    if (manifest.account_lock.args.slice(4) !== manifest.account_id.slice(2)) {
      context.addIssue({
        code: "custom",
        path: ["account_lock", "args"],
        message: "AccountLock args must contain the account ID",
      });
    }
  });

export const PasskeyRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    credentialId: base64url,
    publicKey: PublicKeySchema,
    keyId: Hash32Schema,
    rpId: z.literal(RP_ID),
    origin: z.literal(CLIENT_ORIGIN),
    createdAt: z.string().datetime(),
  })
  .strict();

export const BootstrapRequestSchema = z
  .object({
    publicKey: PublicKeySchema,
    credentialId: base64url,
  })
  .strict();

export const DemoStatusSchema = z
  .object({
    schemaVersion: z.literal(1),
    network: z.literal("testnet"),
    origin: z.literal(CLIENT_ORIGIN),
    rpId: z.literal(RP_ID),
    deploymentVerified: z.boolean(),
    deployment: DeploymentManifestSchema,
    funderAddress: z.string().min(1).max(200),
    funderBalanceShannons: decimalString,
    account: AccountManifestSchema.nullable(),
  })
  .strict();

const ReceiptBaseSchema = z.object({
  txHash: Hash32Schema,
  explorerUrl: z.string().url(),
  remainingCapacityShannons: decimalString,
});

export const SubmittedReceiptSchema = ReceiptBaseSchema.extend({
  status: z.literal("submitted"),
}).strict();

export const CommittedReceiptSchema = ReceiptBaseSchema.extend({
  status: z.literal("committed"),
}).strict();

export const ConfirmationTimedOutReceiptSchema = ReceiptBaseSchema.extend({
  status: z.literal("confirmation_timeout"),
}).strict();

export const TransactionReceiptSchema = z.discriminatedUnion("status", [
  SubmittedReceiptSchema,
  CommittedReceiptSchema,
  ConfirmationTimedOutReceiptSchema,
]);

export const ApiErrorBodySchema = z
  .object({
    error: z
      .object({
        code: z.enum([
          "BAD_ORIGIN",
          "INVALID_REQUEST",
          "KEY_UNAVAILABLE",
          "DEPLOYMENT_INVALID",
          "ACCOUNT_NOT_CREATED",
          "ACCOUNT_MISMATCH",
          "INSUFFICIENT_BALANCE",
          "BOOTSTRAP_FAILED",
          "CONFIRMATION_TIMEOUT",
          "INTERNAL_ERROR",
        ]),
        message: z.string().max(240),
      })
      .strict(),
  })
  .strict();

export type DeploymentManifest = z.infer<typeof DeploymentManifestSchema>;
export type AccountManifest = z.infer<typeof AccountManifestSchema>;
export type PasskeyRecord = z.infer<typeof PasskeyRecordSchema>;
export type DemoStatus = z.infer<typeof DemoStatusSchema>;
export type BootstrapRequest = z.infer<typeof BootstrapRequestSchema>;
export type ApiErrorBody = z.infer<typeof ApiErrorBodySchema>;
export type SubmittedReceipt = z.infer<typeof SubmittedReceiptSchema>;
export type CommittedReceipt = z.infer<typeof CommittedReceiptSchema>;
export type ConfirmationTimedOutReceipt = z.infer<
  typeof ConfirmationTimedOutReceiptSchema
>;
export type TransactionReceipt = z.infer<typeof TransactionReceiptSchema>;
