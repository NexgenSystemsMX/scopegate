/**
 * In-memory mock of RailwayBridgeClient (EPIC-16) — same semantics as the real
 * client, backed by plain data. Used when RAILWAY_MOCK=1: unit tests and the
 * local e2e run WITHOUT network or a live Railway account (the token is not
 * validated).
 *
 * The mock works at the semantic level: it stores projects/services/
 * deployments/variables/domains exactly as seeded and applies the same
 * resolution + redaction rules as the real client (variables always come out
 * as REDACTED — the seeded values below exist precisely to prove they never
 * leak).
 *
 * Seeded state (deterministic, so tests/e2e can assert against it):
 *   - project "Demo Project" (mock-project-1, env production)
 *       service "api"      SUCCESS deployment with url, 3 log lines,
 *                          variables (API_KEY / DATABASE_URL / NODE_ENV),
 *                          1 service domain + 1 custom domain
 *       service "worker"   FAILED deployment, no variables, no domains
 *   - project "Infra" (mock-project-2, env production)
 *       service "worker"   BUILDING deployment — duplicate name on purpose to
 *                          exercise the ambiguous-service error
 *       service "postgres" no deployments, variable POSTGRES_PASSWORD
 *
 * deploy/redeploy mutate the mock state like the real API would (a new
 * QUEUED deployment / the latest one back to QUEUED). The error strings are
 * duplicated from client.ts on purpose (the huly-bridge pattern: the mock is
 * a standalone spec of the bridge semantics, no import cycle).
 */
import type {
  RailwayBridgeClient,
  RailwayDeployAccepted,
  RailwayDeploymentInfo,
  RailwayDomainStatus,
  RailwayLogLine,
  RailwayLogs,
  RailwayProjectServices,
  RailwayServiceStatus,
  RailwayVariables,
} from "./client.js";

// --- Self-contained duplicates of client.ts constants/helpers (huly pattern:
// --- no runtime import cycle; the mock reads as a standalone spec) -----------

const REDACTED = "[redacted]";

function projectNotFoundMessage(projectId: string): string {
  return `Project not found: "${projectId}" — use list_services (without projectId) to see the accessible projects`;
}

function serviceNotFoundMessage(service: string, project?: string, available?: string[]): string {
  if (project !== undefined) {
    const known = available !== undefined && available.length > 0 ? available.join(", ") : "(none)";
    return `Service not found: "${service}" in project "${project}" — available services: ${known} (use list_services)`;
  }
  return `Service not found: "${service}" in any accessible project — use list_services to see what exists`;
}

function ambiguousServiceMessage(service: string, projects: string[]): string {
  return `Service "${service}" is ambiguous — it exists in projects ${projects
    .map((p) => `"${p}"`)
    .join(", ")}; pass "projectId" to disambiguate`;
}

function noDeploymentsMessage(service: string, action: string): string {
  return `Service "${service}" has no deployments yet — ${action}`;
}

interface MockServiceData {
  id: string;
  name: string;
  deployments: RailwayDeploymentInfo[];
  variables: Record<string, string>;
  serviceDomains: Array<{ id: string; domain: string }>;
  customDomains: Array<{ id: string; domain: string; dnsStatus: string | null }>;
  logs: RailwayLogLine[];
}

interface MockProjectData {
  id: string;
  name: string;
  environment: { id: string; name: string };
  services: MockServiceData[];
}

function seedProjects(): MockProjectData[] {
  return [
    {
      id: "mock-project-1",
      name: "Demo Project",
      environment: { id: "mock-env-1", name: "production" },
      services: [
        {
          id: "mock-service-1",
          name: "api",
          deployments: [
            {
              id: "mock-deploy-1",
              status: "SUCCESS",
              createdAt: "2026-07-20T10:00:00.000Z",
              url: "https://api-demo.up.railway.app",
            },
          ],
          variables: {
            API_KEY: "sk-railway-demo-secret",
            DATABASE_URL: "postgres://user:pass@db.internal:5432/app",
            NODE_ENV: "production",
          },
          serviceDomains: [{ id: "mock-sdom-1", domain: "api-demo.up.railway.app" }],
          customDomains: [{ id: "mock-cdom-1", domain: "api.example.com", dnsStatus: "VALID" }],
          logs: [
            { timestamp: "2026-07-20T10:00:01.000Z", severity: "info", message: "Starting deployment" },
            { timestamp: "2026-07-20T10:00:02.000Z", severity: "info", message: "Build succeeded" },
            { timestamp: "2026-07-20T10:00:03.000Z", severity: "info", message: "Healthcheck passed" },
          ],
        },
        {
          id: "mock-service-2",
          name: "worker",
          deployments: [
            {
              id: "mock-deploy-2",
              status: "FAILED",
              createdAt: "2026-07-19T09:30:00.000Z",
              url: null,
            },
          ],
          variables: {},
          serviceDomains: [],
          customDomains: [],
          logs: [{ timestamp: "2026-07-19T09:30:01.000Z", severity: "error", message: "Build failed: exit code 1" }],
        },
      ],
    },
    {
      id: "mock-project-2",
      name: "Infra",
      environment: { id: "mock-env-2", name: "production" },
      services: [
        {
          id: "mock-service-3",
          name: "worker",
          deployments: [
            {
              id: "mock-deploy-3",
              status: "BUILDING",
              createdAt: "2026-07-21T08:00:00.000Z",
              url: null,
            },
          ],
          variables: {},
          serviceDomains: [],
          customDomains: [],
          logs: [{ timestamp: "2026-07-21T08:00:01.000Z", severity: "info", message: "Cloning repository" }],
        },
        {
          id: "mock-service-4",
          name: "postgres",
          deployments: [],
          variables: { POSTGRES_PASSWORD: "super-secret-pw" },
          serviceDomains: [],
          customDomains: [],
          logs: [],
        },
      ],
    },
  ];
}

interface ResolvedMock {
  project: MockProjectData;
  service: MockServiceData;
}

export class MockRailwayClient implements RailwayBridgeClient {
  private seq = 0;
  private readonly projects: MockProjectData[];

  constructor(private readonly now: () => number = () => Date.now()) {
    this.projects = seedProjects();
  }

  async connect(): Promise<void> {}
  async close(): Promise<void> {}

  private nextId(prefix: string): string {
    this.seq += 1;
    return `${prefix}-${this.seq}`;
  }

  private static matchService(services: MockServiceData[], ref: string): MockServiceData | undefined {
    const needle = ref.trim().toLowerCase();
    return services.find((s) => s.id === ref) ?? services.find((s) => s.name.toLowerCase() === needle);
  }

  private resolveService(serviceRef: string, projectId?: string): ResolvedMock {
    if (projectId !== undefined && projectId.trim() !== "") {
      const project = this.projects.find((p) => p.id === projectId);
      if (project === undefined) throw new Error(projectNotFoundMessage(projectId));
      const svc = MockRailwayClient.matchService(project.services, serviceRef);
      if (svc === undefined) {
        throw new Error(serviceNotFoundMessage(serviceRef, project.name, project.services.map((s) => s.name)));
      }
      return { project, service: svc };
    }
    const matches: ResolvedMock[] = [];
    for (const project of this.projects) {
      const svc = MockRailwayClient.matchService(project.services, serviceRef);
      if (svc !== undefined) matches.push({ project, service: svc });
    }
    if (matches.length === 0) throw new Error(serviceNotFoundMessage(serviceRef));
    if (matches.length > 1) {
      throw new Error(ambiguousServiceMessage(serviceRef, matches.map((m) => m.project.name)));
    }
    return matches[0];
  }

  async listServices(projectId?: string): Promise<RailwayProjectServices[]> {
    if (projectId !== undefined && projectId.trim() !== "") {
      const project = this.projects.find((p) => p.id === projectId);
      if (project === undefined) throw new Error(projectNotFoundMessage(projectId));
      return [MockRailwayClient.toProjectServices(project)];
    }
    return this.projects.map((p) => MockRailwayClient.toProjectServices(p)).sort((a, b) => a.name.localeCompare(b.name));
  }

  private static toProjectServices(p: MockProjectData): RailwayProjectServices {
    return {
      id: p.id,
      name: p.name,
      services: p.services.map((s) => ({ id: s.id, name: s.name })).sort((a, b) => a.name.localeCompare(b.name)),
    };
  }

  async getServiceStatus(service: string, projectId?: string): Promise<RailwayServiceStatus> {
    const r = this.resolveService(service, projectId);
    return {
      projectId: r.project.id,
      project: r.project.name,
      serviceId: r.service.id,
      service: r.service.name,
      environment: r.project.environment.name,
      deployment: r.service.deployments[0] ?? null,
    };
  }

  async deploy(service: string, projectId?: string): Promise<RailwayDeployAccepted> {
    const r = this.resolveService(service, projectId);
    const deployment: RailwayDeploymentInfo = {
      id: this.nextId("mock-deploy-new"),
      status: "QUEUED",
      createdAt: new Date(this.now()).toISOString(),
      url: null,
    };
    r.service.deployments.unshift(deployment);
    return {
      accepted: true,
      kind: "deploy",
      deploymentId: deployment.id,
      projectId: r.project.id,
      project: r.project.name,
      serviceId: r.service.id,
      service: r.service.name,
      environment: r.project.environment.name,
    };
  }

  async redeploy(service: string, projectId?: string): Promise<RailwayDeployAccepted> {
    const r = this.resolveService(service, projectId);
    const latest = r.service.deployments[0];
    if (latest === undefined) {
      throw new Error(noDeploymentsMessage(r.service.name, "use deploy to trigger the first one"));
    }
    latest.status = "QUEUED";
    return {
      accepted: true,
      kind: "redeploy",
      deploymentId: latest.id,
      projectId: r.project.id,
      project: r.project.name,
      serviceId: r.service.id,
      service: r.service.name,
      environment: r.project.environment.name,
    };
  }

  async getLogs(service: string, lines?: number, projectId?: string): Promise<RailwayLogs> {
    const r = this.resolveService(service, projectId);
    const latest = r.service.deployments[0];
    if (latest === undefined) {
      throw new Error(noDeploymentsMessage(r.service.name, "nothing to read logs from; use deploy first"));
    }
    const limit = lines !== undefined && lines > 0 ? Math.floor(lines) : 100;
    const logs = r.service.logs.slice(-limit);
    return {
      projectId: r.project.id,
      project: r.project.name,
      serviceId: r.service.id,
      service: r.service.name,
      deploymentId: latest.id,
      count: logs.length,
      logs,
    };
  }

  async listVariables(service: string, projectId?: string): Promise<RailwayVariables> {
    const r = this.resolveService(service, projectId);
    // Same hard redaction as the real client: names only, values REDACTED.
    const names = Object.keys(r.service.variables).sort((a, b) => a.localeCompare(b));
    const variables = names.map((name) => ({ name, value: REDACTED }));
    return {
      projectId: r.project.id,
      project: r.project.name,
      serviceId: r.service.id,
      service: r.service.name,
      environment: r.project.environment.name,
      count: variables.length,
      variables,
    };
  }

  async getDomains(service: string, projectId?: string): Promise<RailwayDomainStatus> {
    const r = this.resolveService(service, projectId);
    return {
      projectId: r.project.id,
      project: r.project.name,
      serviceId: r.service.id,
      service: r.service.name,
      environment: r.project.environment.name,
      serviceDomains: r.service.serviceDomains.map((d) => ({ ...d })),
      customDomains: r.service.customDomains.map((d) => ({ ...d })),
    };
  }
}

export function createMockClient(now?: () => number): MockRailwayClient {
  return new MockRailwayClient(now);
}
