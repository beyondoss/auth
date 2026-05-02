import React from "react";
import { camelize } from "../utils/camelize.js";
import { ErrorResponse } from "./client.js";
import { useAuthContext } from "./context.js";
import type { Org } from "./useOrgs.js";

export type UpdateOrgStatus = "idle" | "fetching" | "success" | "error";

export interface UseUpdateOrgResult {
  updateOrg(
    id: string,
    patch: {
      name?: string;
      slug?: string;
      imageUrl?: string;
      metadata?: unknown;
    },
  ): Promise<Org>;
  status: UpdateOrgStatus;
  error: ErrorResponse<any> | null;
}

export function useUpdateOrg(): UseUpdateOrgResult {
  const { client } = useAuthContext();
  const action = client.useAction({ path: "PATCH /v1/orgs/{id}" });
  const [error, setError] = React.useState<ErrorResponse<any> | null>(null);

  const updateOrg = React.useCallback(
    async (
      id: string,
      patch: {
        name?: string;
        slug?: string;
        imageUrl?: string;
        metadata?: unknown;
      },
    ): Promise<Org> => {
      setError(null);
      try {
        const body: {
          name?: string | null;
          slug?: string | null;
          image_url?: string | null;
          metadata?: unknown;
        } = {};
        if (patch.name !== undefined) body.name = patch.name;
        if (patch.slug !== undefined) body.slug = patch.slug;
        if (patch.imageUrl !== undefined) body.image_url = patch.imageUrl;
        if (patch.metadata !== undefined) body.metadata = patch.metadata;
        const raw = await action.send({ path: { id }, body });
        return camelize(raw) as Org;
      } catch (err) {
        if (err instanceof ErrorResponse) setError(err);
        throw err;
      }
    },
    [action],
  );

  return { updateOrg, status: action.status, error };
}
