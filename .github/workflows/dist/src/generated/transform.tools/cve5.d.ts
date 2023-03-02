export interface Cve5 {
    containers?: Containers;
    cveMetadata?: CveMetadata;
    dataType?: string;
    dataVersion?: number;
}
export interface Containers {
    cna?: Cna;
}
export interface Cna {
    affected?: Affected;
    descriptions?: CnaDescription[];
    problemTypes?: ProblemType[];
    providerMetadata?: ProviderMetadata;
    references?: Reference[];
}
export interface Affected {
    vendor?: string;
    versions?: Version[];
}
export interface Version {
    status?: string;
    version?: string;
}
export interface CnaDescription {
    lang?: string;
    value?: string;
}
export interface ProblemType {
    descriptions?: ProblemTypeDescription[];
}
export interface ProblemTypeDescription {
    description?: string;
    lang?: string;
    type?: string;
}
export interface ProviderMetadata {
    orgId?: string;
}
export interface Reference {
    name?: string;
    refsource?: string;
    url?: string;
}
export interface CveMetadata {
    assignerOrgId?: string;
    assignerShortName?: string;
    cveId?: string;
    datePublished?: string;
    dateReserved?: string;
    requesterUserId?: string;
    state?: string;
}
export declare class Convert {
    static toCve5(json: string): Cve5;
    static cve5ToJson(value: Cve5): string;
}
