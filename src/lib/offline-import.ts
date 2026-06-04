import {
  AuthenticationStrengthPolicy,
  ConditionalAccessPolicy,
  DirectoryObject,
  NamedLocation,
  ServicePrincipal,
  TenantContext,
  TenantLicenses,
  inferLicensesFromPolicies,
} from "./graph-client";

type UnknownRecord = Record<string, unknown>;

export interface OfflineExportPayload {
  tenantId?: string;
  tenantDisplayName?: string;
  conditionalAccessPolicies?: unknown[];
  policies?: unknown[];
  namedLocations?: unknown[];
  servicePrincipals?: unknown[];
  directoryObjects?: unknown[];
  authenticationStrengthPolicies?: unknown[];
  authStrengthPolicies?: unknown[];
  licenses?: Partial<TenantLicenses>;
  subscribedSkus?: unknown[];
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string");
}

function toRecord(value: unknown): UnknownRecord {
  return (value && typeof value === "object" ? value : {}) as UnknownRecord;
}

function isMeaningfulGuestExternalUsers(value: unknown): boolean {
  const record = toRecord(value);
  if (Object.keys(record).length === 0) return false;
  const guestTypes = record.guestOrExternalUserTypes;
  if (typeof guestTypes === "string" && guestTypes.trim().length > 0) return true;
  const externalTenants = toRecord(record.externalTenants);
  const membershipKind = externalTenants.membershipKind;
  return typeof membershipKind === "string" && membershipKind.trim().length > 0;
}

function normalizeGrantAuthStrength(
  value: unknown
): { id: string; displayName: string } | undefined {
  const record = toRecord(value);
  const id = typeof record.id === "string" ? record.id : "";
  const displayName =
    typeof record.displayName === "string" ? record.displayName : "";
  if (!id && !displayName) return undefined;
  return { id, displayName };
}

function toCamelKey(key: string): string {
  if (!key) return key;
  if (key.startsWith("@") || key.startsWith("$")) return key;
  return key[0].toLowerCase() + key.slice(1);
}

const MAX_NORMALIZE_DEPTH = 40;

function normalizeKeysDeep(value: unknown, depth = 0): unknown {
  if (depth > MAX_NORMALIZE_DEPTH) {
    throw new Error(
      `Offline export nesting exceeds safe limit (${MAX_NORMALIZE_DEPTH}).`
    );
  }
  if (Array.isArray(value)) {
    return value.map((v) => normalizeKeysDeep(v, depth + 1));
  }
  if (!value || typeof value !== "object") return value;
  const input = value as UnknownRecord;
  const out: UnknownRecord = {};
  for (const [key, v] of Object.entries(input)) {
    out[toCamelKey(key)] = normalizeKeysDeep(v, depth + 1);
  }
  return out;
}

function unwrapCollection(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  const record = toRecord(value);
  if (Array.isArray(record.value)) return record.value;
  // PowerShell exports may emit a single object rather than an array.
  if (Object.keys(record).length > 0) return [record];
  return [];
}

function normalizePolicy(input: unknown): ConditionalAccessPolicy | null {
  const raw = toRecord(input);
  const additionalProperties = toRecord(raw.additionalProperties);
  const id = typeof raw.id === "string" ? raw.id : "";
  const displayName = typeof raw.displayName === "string" ? raw.displayName : "";
  if (!id || !displayName) return null;

  const conditions = toRecord(raw.conditions);
  const users = toRecord(conditions.users);
  const applications = toRecord(conditions.applications);
  const platforms = toRecord(conditions.platforms);
  const locations = toRecord(conditions.locations);
  const clientApplications = toRecord(conditions.clientApplications);
  const authenticationFlows = toRecord(conditions.authenticationFlows);
  const grantControls = toRecord(raw.grantControls);
  const sessionControls = toRecord(raw.sessionControls);

  return {
    id,
    templateId:
      typeof raw.templateId === "string"
        ? raw.templateId
        : typeof additionalProperties.templateId === "string"
          ? additionalProperties.templateId
          : null,
    displayName,
    state:
      raw.state === "enabled" ||
      raw.state === "disabled" ||
      raw.state === "enabledForReportingButNotEnforced"
        ? raw.state
        : "disabled",
    createdDateTime:
      typeof raw.createdDateTime === "string" ? raw.createdDateTime : "",
    modifiedDateTime:
      typeof raw.modifiedDateTime === "string" ? raw.modifiedDateTime : "",
    conditions: {
      users: {
        includeUsers: asStringArray(users.includeUsers),
        excludeUsers: asStringArray(users.excludeUsers),
        includeGroups: asStringArray(users.includeGroups),
        excludeGroups: asStringArray(users.excludeGroups),
        includeRoles: asStringArray(users.includeRoles),
        excludeRoles: asStringArray(users.excludeRoles),
        includeGuestsOrExternalUsers: isMeaningfulGuestExternalUsers(
          users.includeGuestsOrExternalUsers
        )
          ? users.includeGuestsOrExternalUsers
          : undefined,
        excludeGuestsOrExternalUsers: isMeaningfulGuestExternalUsers(
          users.excludeGuestsOrExternalUsers
        )
          ? users.excludeGuestsOrExternalUsers
          : undefined,
      },
      applications: {
        includeApplications: asStringArray(applications.includeApplications),
        excludeApplications: asStringArray(applications.excludeApplications),
        includeUserActions: asStringArray(applications.includeUserActions),
        includeAuthenticationContextClassReferences: asStringArray(
          applications.includeAuthenticationContextClassReferences
        ),
        applicationFilter: applications.applicationFilter as
          | { mode: string; rule: string }
          | undefined,
      },
      clientAppTypes: asStringArray(conditions.clientAppTypes),
      platforms:
        Object.keys(platforms).length > 0
          ? {
              includePlatforms: asStringArray(platforms.includePlatforms),
              excludePlatforms: asStringArray(platforms.excludePlatforms),
            }
          : undefined,
      locations:
        Object.keys(locations).length > 0
          ? {
              includeLocations: asStringArray(locations.includeLocations),
              excludeLocations: asStringArray(locations.excludeLocations),
            }
          : undefined,
      userRiskLevels: asStringArray(conditions.userRiskLevels),
      signInRiskLevels: asStringArray(conditions.signInRiskLevels),
      servicePrincipalRiskLevels: asStringArray(
        conditions.servicePrincipalRiskLevels
      ),
      devices: conditions.devices as
        | { deviceFilter?: { mode: string; rule: string } }
        | undefined,
      clientApplications:
        Object.keys(clientApplications).length > 0
          ? {
              includeServicePrincipals: asStringArray(
                clientApplications.includeServicePrincipals
              ),
              excludeServicePrincipals: asStringArray(
                clientApplications.excludeServicePrincipals
              ),
              servicePrincipalFilter: clientApplications.servicePrincipalFilter as
                | { mode: string; rule: string }
                | undefined,
            }
          : undefined,
      insiderRiskLevels:
        typeof conditions.insiderRiskLevels === "string"
          ? conditions.insiderRiskLevels
          : undefined,
      authenticationFlows:
        Object.keys(authenticationFlows).length > 0
          ? {
              transferMethods:
                typeof authenticationFlows.transferMethods === "string"
                  ? authenticationFlows.transferMethods
                  : undefined,
            }
          : undefined,
    },
    grantControls:
      Object.keys(grantControls).length > 0
        ? {
            operator:
              grantControls.operator === "AND" ? "AND" : "OR",
            builtInControls: asStringArray(grantControls.builtInControls),
            customAuthenticationFactors: asStringArray(
              grantControls.customAuthenticationFactors
            ),
            termsOfUse: asStringArray(grantControls.termsOfUse),
            authenticationStrength: normalizeGrantAuthStrength(
              grantControls.authenticationStrength
            ),
          }
        : undefined,
    sessionControls:
      Object.keys(sessionControls).length > 0
        ? (sessionControls as ConditionalAccessPolicy["sessionControls"])
        : undefined,
  };
}

function normalizeNamedLocation(input: unknown): NamedLocation | null {
  const raw = toRecord(input);
  const additional = toRecord(raw.additionalProperties);
  const id = typeof raw.id === "string" ? raw.id : "";
  const displayName = typeof raw.displayName === "string" ? raw.displayName : "";
  const odataType =
    typeof raw["@odata.type"] === "string"
      ? raw["@odata.type"]
      : typeof additional["@odata.type"] === "string"
        ? additional["@odata.type"]
        : "#microsoft.graph.countryNamedLocation";
  if (!id || !displayName) return null;
  return {
    id,
    displayName,
    "@odata.type": odataType,
    isTrusted:
      typeof raw.isTrusted === "boolean"
        ? raw.isTrusted
        : typeof additional.isTrusted === "boolean"
          ? additional.isTrusted
          : undefined,
    ipRanges: Array.isArray(raw.ipRanges)
      ? (raw.ipRanges as { cidrAddress: string }[])
      : Array.isArray(additional.ipRanges)
        ? (additional.ipRanges as { cidrAddress: string }[])
      : undefined,
    countriesAndRegions:
      asStringArray(raw.countriesAndRegions).length > 0
        ? asStringArray(raw.countriesAndRegions)
        : asStringArray(additional.countriesAndRegions),
    countryLookupMethod:
      typeof raw.countryLookupMethod === "string"
        ? raw.countryLookupMethod
        : typeof additional.countryLookupMethod === "string"
          ? additional.countryLookupMethod
        : undefined,
    includeUnknownCountriesAndRegions:
      typeof raw.includeUnknownCountriesAndRegions === "boolean"
        ? raw.includeUnknownCountriesAndRegions
        : typeof additional.includeUnknownCountriesAndRegions === "boolean"
          ? additional.includeUnknownCountriesAndRegions
        : undefined,
  };
}

function normalizeServicePrincipal(input: unknown): ServicePrincipal | null {
  const raw = toRecord(input);
  const id = typeof raw.id === "string" ? raw.id : "";
  const appId = typeof raw.appId === "string" ? raw.appId : "";
  const displayName = typeof raw.displayName === "string" ? raw.displayName : appId;
  if (!id || !appId) return null;
  return {
    id,
    appId,
    displayName,
    servicePrincipalType:
      typeof raw.servicePrincipalType === "string"
        ? raw.servicePrincipalType
        : "Application",
    appOwnerOrganizationId:
      typeof raw.appOwnerOrganizationId === "string"
        ? raw.appOwnerOrganizationId
        : undefined,
    tags: asStringArray(raw.tags),
  };
}

function normalizeDirectoryObject(input: unknown): DirectoryObject | null {
  const raw = toRecord(input);
  const additional = toRecord(raw.additionalProperties);
  const id = typeof raw.id === "string" ? raw.id : "";
  if (!id) return null;
  return {
    id,
    displayName:
      typeof raw.displayName === "string"
        ? raw.displayName
        : typeof additional.displayName === "string"
          ? additional.displayName
          : id,
    "@odata.type":
      typeof raw["@odata.type"] === "string"
        ? raw["@odata.type"]
        : typeof additional["@odata.type"] === "string"
          ? additional["@odata.type"]
        : "unknown",
  };
}

function normalizeAuthStrength(input: unknown): AuthenticationStrengthPolicy | null {
  const raw = toRecord(input);
  const id = typeof raw.id === "string" ? raw.id : "";
  const displayName = typeof raw.displayName === "string" ? raw.displayName : "";
  if (!id || !displayName) return null;
  return {
    id,
    displayName,
    description: typeof raw.description === "string" ? raw.description : "",
    policyType:
      raw.policyType === "builtIn" ||
      raw.policyType === "custom" ||
      raw.policyType === "unknownFutureValue"
        ? raw.policyType
        : "unknownFutureValue",
    allowedCombinations: asStringArray(raw.allowedCombinations),
    requirementsSatisfied:
      raw.requirementsSatisfied === "none" ||
      raw.requirementsSatisfied === "mfa" ||
      raw.requirementsSatisfied === "unknownFutureValue"
        ? raw.requirementsSatisfied
        : "unknownFutureValue",
  };
}

function inferLicensesFromSubscribedSkus(skus: unknown[]): TenantLicenses {
  const planIds = new Set<string>();
  for (const sku of skus) {
    const rec = toRecord(sku);
    const plans = asArray(rec.servicePlans);
    for (const p of plans) {
      const plan = toRecord(p);
      if (typeof plan.servicePlanId === "string") {
        planIds.add(plan.servicePlanId.toLowerCase());
      }
    }
  }

  const entraP1 = "41781fb2-bc02-4b7c-bd55-b576c07bb09d";
  const entraP2 = "eec0eb4f-6444-4f95-aba0-50c24d67f998";
  const intuneP1 = "c1ec4a95-1f05-45b3-a911-aa3fa01094f5";
  const workloadP1 = "84c289f0-efcb-486f-8581-07f44fc9efad";
  const workloadP2 = "7dc0e92d-bf15-401d-907e-0884efe7c760";

  return {
    hasEntraIdP1: planIds.has(entraP1) || planIds.has(entraP2),
    hasEntraIdP2: planIds.has(entraP2),
    hasIntunePlan1: planIds.has(intuneP1),
    hasWorkloadIdPremium: planIds.has(workloadP1) || planIds.has(workloadP2),
  };
}

export function buildTenantContextFromOfflineExport(
  payload: OfflineExportPayload
): TenantContext {
  const normalized = normalizeKeysDeep(payload) as OfflineExportPayload;

  const policiesRaw =
    normalized.conditionalAccessPolicies ?? normalized.policies ?? [];
  const policies = unwrapCollection(policiesRaw)
    .map(normalizePolicy)
    .filter((p): p is ConditionalAccessPolicy => p !== null);

  const namedLocations = unwrapCollection(normalized.namedLocations)
    .map(normalizeNamedLocation)
    .filter((v): v is NamedLocation => v !== null);

  const servicePrincipalsList = unwrapCollection(normalized.servicePrincipals)
    .map(normalizeServicePrincipal)
    .filter((v): v is ServicePrincipal => v !== null);
  const servicePrincipals = new Map<string, ServicePrincipal>(
    servicePrincipalsList.map((sp) => [sp.appId.toLowerCase(), sp])
  );

  const directoryObjectList = unwrapCollection(normalized.directoryObjects)
    .map(normalizeDirectoryObject)
    .filter((v): v is DirectoryObject => v !== null);
  const directoryObjects = new Map<string, DirectoryObject>(
    directoryObjectList.map((obj) => [obj.id, obj])
  );

  const authStrengthList = asArray(
    normalized.authenticationStrengthPolicies ?? normalized.authStrengthPolicies
  )
    .map(normalizeAuthStrength)
    .filter((v): v is AuthenticationStrengthPolicy => v !== null);
  const authStrengthPolicies = new Map<string, AuthenticationStrengthPolicy>(
    authStrengthList.map((a) => [a.id, a])
  );

  const tenantId = normalized.tenantId ?? "";
  const tenantDisplayName =
    normalized.tenantDisplayName ??
    (tenantId ? `Offline Tenant (${tenantId})` : "Offline Tenant");

  const licenses: TenantLicenses = normalized.licenses
    ? {
        hasEntraIdP1: Boolean(normalized.licenses.hasEntraIdP1),
        hasEntraIdP2: Boolean(normalized.licenses.hasEntraIdP2),
        hasIntunePlan1: Boolean(normalized.licenses.hasIntunePlan1),
        hasWorkloadIdPremium: Boolean(normalized.licenses.hasWorkloadIdPremium),
      }
    : unwrapCollection(normalized.subscribedSkus).length > 0
      ? inferLicensesFromSubscribedSkus(unwrapCollection(normalized.subscribedSkus))
      : inferLicensesFromPolicies(policies);

  return {
    tenantDisplayName,
    tenantId,
    policies,
    namedLocations,
    servicePrincipals,
    directoryObjects,
    licenses,
    authStrengthPolicies,
  };
}
