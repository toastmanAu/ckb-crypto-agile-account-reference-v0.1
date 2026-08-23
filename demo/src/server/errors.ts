import type { ApiErrorBody } from "../shared/schemas.js";

export type ApiErrorCode = ApiErrorBody["error"]["code"];

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  readonly safeMessage: string;

  constructor(code: ApiErrorCode, status: number, safeMessage: string) {
    super(safeMessage);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.safeMessage = safeMessage;
  }
}

export function toSafeErrorBody(error: unknown): ApiErrorBody {
  if (error instanceof ApiError) {
    return {
      error: {
        code: error.code,
        message: error.safeMessage,
      },
    };
  }
  return {
    error: {
      code: "INTERNAL_ERROR",
      message: "Unexpected local server error",
    },
  };
}
