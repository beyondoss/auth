import type { Client } from "openapi-fetch";
import type { components, paths } from "../types.js";
import type { Camelize } from "../utils/camelize.js";
import { wrap } from "../utils/wrap.js";

export type TotpEnrollment = Camelize<
  components["schemas"]["EnrollmentResponse"]
>;
export type RecoveryCodes = Camelize<
  components["schemas"]["RecoveryCodesResponse"]
>;

export const enrollTotp = (client: Client<paths>) =>
  wrap(client.POST("/v1/totp", {}));

export const confirmTotp = (client: Client<paths>, code: string) =>
  wrap(client.POST("/v1/totp/confirmations", { body: { code } }));

export const disableTotp = (client: Client<paths>) =>
  wrap(client.DELETE("/v1/totp", {}));

export const regenerateTotpRecoveryCodes = (
  client: Client<paths>,
  code: string,
) => wrap(client.POST("/v1/totp/recovery-codes", { body: { code } }));
