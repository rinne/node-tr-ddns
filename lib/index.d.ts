// Type declarations for tr-ddns.

import { EventEmitter } from 'node:events';

/** A record type that a host can have. */
export type RecordType = 'a' | 'aaaa' | 'txt' | 'mx' | 'cname' | 'ns' | 'srv' | 'caa';

/**
 * The values of one record type as given to NameDB.set(): a single
 * value, several values, or an empty string for no values.
 */
export type RecordInput = string | string[] | Set<string>;

/** The records of a host as given to NameDB.set(). */
export type HostInput = Partial<Record<RecordType, RecordInput | null>>;

/** The records of a host as returned by NameDB.getHostData(). */
export type HostData = Record<RecordType, Set<string>>;

/** The settings of a domain. Null or an empty string resets a setting. */
export interface DomainOptions {
	/** Name servers of the domain. The default is the domain itself. */
	ns?: string | string[] | null;
	/** Mail address of the administrator, user@example.com or user.example.com. */
	admin?: string | null;
	/** Time to live of the records in seconds. The default is 60. */
	ttl?: number | '' | null;
	/** SOA refresh in seconds. The default is 300. */
	refresh?: number | '' | null;
	/** SOA retry in seconds. The default is 3. */
	retry?: number | '' | null;
	/** SOA expiration in seconds. The default is 10. */
	expiration?: number | '' | null;
	/** SOA minimum, the time to live of negative answers. The default is 10. */
	minimum?: number | '' | null;
}

export interface AddDomainOptions extends DomainOptions {
	/** Continue the SOA serial from a previously used value. */
	serial?: number;
}

/** A served domain with its settings in effect. */
export interface DomainInfo {
	name: string;
	lcname: string;
	serial: number;
	ns: string[];
	admin: string;
	ttl: number;
	refresh: number;
	retry: number;
	expiration: number;
	minimum: number;
}

/** A resource record as passed to the DNS packet encoder. */
export interface ResourceRecord {
	name: string;
	type: number;
	class: number;
	ttl: number;
	[field: string]: unknown;
}

/** The result of NameDB.lookup() for a name inside a served domain. */
export interface LookupResult {
	/** DNS response code: 0, or 3 when the name does not exist. */
	rcode: number;
	/** False for a referral to the name servers of a delegated name. */
	aa: boolean;
	answers: ResourceRecord[];
	authorities: ResourceRecord[];
	additionals: ResourceRecord[];
}

export interface DumpedHost {
	name: string;
	lcname: string;
	domain: string;
	data: Record<RecordType, string[]>;
	/** Milliseconds since the epoch, or null for a host that does not expire. */
	expires: number | null;
}

export interface DumpedDomain {
	name: string;
	lcname: string;
	serial: number;
	expires: null;
	ns?: string[];
	admin?: string;
	ttl?: number;
	refresh?: number;
	retry?: number;
	expiration?: number;
	minimum?: number;
}

export interface Dump {
	hosts: DumpedHost[];
	domains: DumpedDomain[];
}

export interface NameDBStats {
	lookup: { total: number; errors: number };
	domains: number;
	hosts: number;
}

export interface NameDBOptions {
	debug?: boolean;
}

/**
 * The domains and hosts that are served.
 *
 * Events: 'add', 'update' and 'remove' with the lower case host name,
 * 'adddomain', 'updatedomain' and 'removedomain' with the lower case
 * domain name, and 'flush'.
 */
export class NameDB extends EventEmitter {
	constructor(config?: NameDBOptions);
	/** Stops the timers. Hosts no longer expire after this. */
	close(): void;
	/** Throws if the domain is invalid, served already, or overlaps a served domain. */
	addDomain(domain: string, options?: AddDomainOptions): void;
	/** Returns false if the domain is not served. Throws for an invalid setting. */
	setDomainOptions(domain: string, options: DomainOptions): boolean;
	getDomain(domain: string): DomainInfo | undefined;
	/** Removes the domain with its hosts. Returns false if it was not served. */
	removeDomain(domain: string): boolean;
	/**
	 * Sets the records of a host. Returns false, changing nothing, if
	 * anything in the call is invalid.
	 *
	 * @param ttlMs lifetime of the host in milliseconds; none if omitted
	 * @param merge keep the record types that are absent from data and
	 *              add single values to the existing ones
	 */
	set(name: string, data: HostInput, ttlMs?: number | null, merge?: boolean): boolean;
	/** Returns false if there was no such host. */
	remove(name: string): boolean;
	/** Milliseconds since the epoch, null for no expiry, undefined for no such host. */
	getHostExpires(name: string): number | null | undefined;
	/** False for an invalid name, undefined for a name outside the served domains. */
	getHostData(name: string): HostData | undefined | false;
	/** The lookup used by the name server. False for a name outside the served domains. */
	lookup(name: string, type: number): LookupResult | false;
	/**
	 * The records of the given type that the name itself has. False for
	 * an invalid name and for a name outside the served domains.
	 */
	get(name: string, type: number): ResourceRecord[] | false;
	/** Removes all hosts and all domains. */
	flush(): void;
	stats(): NameDBStats;
	valid(name: unknown): boolean;
	validDomain(domain: unknown): boolean;
	dump(): Dump;
}

export interface DnsCoreOptions {
	/** The database to answer from. */
	nameDB: NameDB;
	/** Queries per second answered to one source. 0 or false for no limit. The default is 500. */
	rateLimit?: number | false;
	/** Answer REFUSED outside the served domains instead of nothing. */
	refuseOutOfZone?: boolean;
	debug?: boolean;
}

/** A DNS message as parsed and encoded by the dns2 package. */
export interface DnsPacket {
	header: { id: number; qr: number; opcode: number; aa: number; tc: number; rd: number; ra: number; rcode: number; [field: string]: unknown };
	questions: { name: string; type: number; class: number }[];
	answers: ResourceRecord[];
	authorities: ResourceRecord[];
	additionals: ResourceRecord[];
	toBuffer(): Buffer;
}

/** Why a query gets no answer. */
export type DnsDropReason = 'notQuery' | 'invalid' | 'outOfZone' | 'rateLimited' | 'error';

export type DnsAnswer = { response: DnsPacket; dropped?: undefined } | { dropped: DnsDropReason; response?: undefined };

/** Answering DNS queries without a transport. */
export class DnsCore {
	static DEFAULT_RATE_LIMIT: number;
	constructor(config: DnsCoreOptions);
	/**
	 * Answers one parsed query from the given source address. Never
	 * throws.
	 */
	answer(request: unknown, source?: string, options?: { refuseOutOfZone?: boolean }): DnsAnswer;
	/** Counts a packet that could not be parsed. */
	countInvalid(): void;
	stats(): NameServerStats;
}

export interface NameServerOptions {
	/** The database to answer from. Required unless core is given. */
	nameDB?: NameDB;
	/** A DNS core to share with other transports. */
	core?: DnsCore;
	udp?: boolean;
	/** An address, a comma separated list or an array. The default is 0.0.0.0. */
	udpListenAddress?: string | string[];
	/** The default is 53. */
	udpListenPort?: number;
	tcp?: boolean;
	/** An address, a comma separated list or an array. The default is 0.0.0.0. */
	tcpListenAddress?: string | string[];
	/** The default is 53. */
	tcpListenPort?: number;
	/** Queries per second answered to one source. 0 or false for no limit. The default is 500. */
	rateLimit?: number | false;
	/** Answer REFUSED outside the served domains instead of staying silent. */
	refuseOutOfZone?: boolean;
	debug?: boolean;
}

export interface NameServerStats {
	queries: number;
	answered: number;
	nxdomain: number;
	empty: number;
	refused: number;
	dropped: {
		notQuery: number;
		invalid: number;
		outOfZone: number;
		rateLimited: number;
		error: number;
	};
}

/**
 * The DNS server.
 *
 * Events: 'ready' when all listeners are up, 'error' when a listener
 * cannot be started, 'close'.
 */
export class NameServer extends EventEmitter {
	static DEFAULT_RATE_LIMIT: number;
	constructor(config: NameServerOptions);
	stats(): NameServerStats;
	close(): Promise<void>;
}

export interface ApiCoreOptions {
	nameDB: NameDB;
	/** Adds the counters of the name server to /stats as dns. */
	nameServer?: { stats(): unknown };
	/** Adds the counters of the DoH server to /stats as doh. */
	dohServer?: { stats(): unknown };
	debug?: boolean;
}

export interface ApiRequest {
	method?: string;
	/** The path without a query string, for example /host. */
	path: string;
	params?: Record<string, unknown>;
}

export interface ApiResult {
	/** The HTTP status, also in body.code. */
	status: number;
	body: { status: 'ok' | 'error'; code: number; message?: string; data?: unknown };
}

/** The calls of the API without a transport. */
export class ApiCore {
	constructor(config: ApiCoreOptions);
	/** Performs one call. Never throws. */
	handle(request: ApiRequest): ApiResult;
	/** Counts a request for /stats. */
	countCall(): void;
	/** Counts a request refused for missing or wrong credentials. */
	countAuthFailure(): void;
}

export interface ApiServerOptions {
	/** Required unless api is given. */
	nameDB?: NameDB;
	/** An API core to share with other transports. */
	api?: ApiCore;
	/** Adds the counters of the name server to /stats. */
	nameServer?: NameServer;
	/** The default is 80. */
	port?: number;
	/** The default is 0.0.0.0. */
	address?: string;
	/** Base64 of user:password. Without it the API is open. */
	basicAuth?: string | null;
	/** Largest request body in bytes. The default is 65536. */
	maxBodySize?: number;
	debug?: boolean;
}

/**
 * The HTTP API.
 *
 * Events: 'ready' when listening, 'error' when the listener cannot be
 * started.
 */
export class ApiServer extends EventEmitter {
	constructor(config: ApiServerOptions);
	close(): Promise<void>;
}

export interface ControlServerOptions {
	/** The socket file. */
	path: string;
	/** Permissions of the socket file, a number or an octal string. The default is 0600. */
	mode?: number | string;
	/** An API core to share with other transports. */
	api?: ApiCore;
	/** Required unless api is given. */
	nameDB?: NameDB;
	/** Largest request body in bytes. The default is 65536. */
	maxBodySize?: number;
	debug?: boolean;
}

/**
 * The HTTP API on a Unix domain socket, without authentication.
 *
 * Events: 'ready' when listening, 'error' when the socket cannot be
 * created.
 */
export class ControlServer extends EventEmitter {
	constructor(config: ControlServerOptions);
	/** Stops listening and removes the socket file. */
	close(): Promise<void>;
}

export interface ConfigStoreOptions {
	file: string;
	nameDB: NameDB;
	/** Shortest time between two writes in milliseconds. The default is 10000. */
	writeIntervalMs?: number;
}

/**
 * Keeps the contents of a NameDB in a JSON file.
 *
 * Events: 'write' after each write, 'error' when a scheduled write fails.
 */
export class ConfigStore extends EventEmitter {
	static ConfigError: typeof ConfigError;
	constructor(config: ConfigStoreOptions);
	/** Creates the file. Rejects with code EEXIST if it exists. */
	init(): Promise<void>;
	/**
	 * Reads the file into the database and resolves to messages about
	 * the entries that were skipped. Rejects with a ConfigError whose
	 * code is ENOENT, EMALFORMED or a file system error code.
	 */
	load(): Promise<string[]>;
	write(options?: { untimed?: boolean }): Promise<void>;
	/** Starts writing the file whenever the database changes. */
	watch(): void;
	schedule(): void;
	/** Writes pending changes now. */
	flush(): Promise<void>;
	close(): void;
}

/** The error that ConfigStore.load() rejects with. */
declare class ConfigError extends Error {
	code: string;
}

export type LogLevel = 'none' | 'error' | 'warn' | 'info' | 'debug';

export interface Log {
	(...args: unknown[]): void;
	error(...args: unknown[]): void;
	warn(...args: unknown[]): void;
	info(...args: unknown[]): void;
	debug(...args: unknown[]): void;
	setLevel(level: LogLevel): void;
	getLevel(): LogLevel;
	enableDebug(): void;
	LEVELS: readonly LogLevel[];
}

export const log: Log;

/** True for undefined and null. */
export function nullish(x: unknown): x is null | undefined;

/** The current time as YYYY-MM-DD HH:MM:SS in UTC. */
export function ts(): string;
