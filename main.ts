enum Attribute {
    accessKeyId = 'accessKeyId',
    secretAccessKey = 'secretAccessKey',
    sessionToken = 'sessionToken'
}

interface CredentialSet {
    accessKeyId?: string
    secretAccessKey?: string
    sessionToken?: string
}

// --- Consistent credential snapshot cache -----------------------------------
//
// An AWS IAM auth block invokes this template tag once per field (access key,
// secret key, session token), so run() fires multiple times per request. A
// background credential refresher (e.g. one backed by a `credential_process`)
// may rewrite the underlying credentials between those calls, and AWS
// temporary credentials are a matched triplet that only validate together.
// Reading each field with an independent load can therefore mix an old access
// key with a new secret/session token if a rotation happens mid-request,
// producing an intermittent SigV4 "signature does not match" error.
//
// To prevent that, we load the full triplet once and serve all three fields
// from a single snapshot, cached for a short TTL and keyed by profile name. We
// cache the in-flight Promise (not just the resolved value) so concurrent field
// renders within one request share the exact same load. Insomnia v13 runs
// plugins in a persistent hidden process, so this module-level cache survives
// across invocations; the short TTL keeps us picking up credential rotations
// promptly.
const CACHE_TTL_MS = 5000
const credsCache = new Map<string, { promise: Promise<CredentialSet>; expiresAt: number }>()

// --- credential_process support ---------------------------------------------
//
// Profiles configured with `credential_process` (a command that prints a JSON
// credentials payload to stdout) live in ~/.aws/config, not
// ~/.aws/credentials, and are never written to a static credentials file.
// SharedIniFileCredentials only reads ~/.aws/credentials, so it silently
// returns empty fields for such profiles. We detect a credential_process line
// for the requested profile in ~/.aws/config and, if present, resolve
// credentials by running that process directly (matching how the AWS CLI/SDK
// resolve credential_process profiles), falling back to
// SharedIniFileCredentials for ordinary static profiles so existing users of
// this plugin are unaffected.
//
// We run credential_process ourselves (rather than delegating to
// AWS.ProcessCredentials) so we can turn each failure mode into a specific,
// actionable message. AWS.ProcessCredentials collapses every exec failure
// into the single generic "credential_process returned error", which hides
// the most common real cause: GUI apps like Insomnia launch with macOS's
// minimal default PATH, not your shell's PATH, so a bare command name that
// only resolves in an interactive shell is "not found" here even though it
// works fine from a terminal.
function findCredentialProcess(profileName: string): string | undefined {
    const os = require('os')
    const path = require('path')
    const fs = require('fs')

    const configPath = process.env.AWS_CONFIG_FILE || path.join(os.homedir(), '.aws', 'config')
    let contents: string
    try {
        contents = fs.readFileSync(configPath, 'utf8')
    } catch {
        return undefined
    }

    // AWS config sections are named "[default]" or "[profile <name>]" (every
    // profile except "default" carries the "profile " prefix).
    const targetHeader = profileName === 'default' ? '[default]' : `[profile ${profileName}]`

    const lines = contents.split(/\r?\n/)
    let inTargetSection = false
    for (const rawLine of lines) {
        const line = rawLine.trim()
        if (line.startsWith('[')) {
            inTargetSection = line === targetHeader
            continue
        }
        if (inTargetSection) {
            const match = line.match(/^credential_process\s*=\s*(.+)$/)
            if (match) {
                return match[1].trim()
            }
        }
    }
    return undefined
}

interface ProcessCredentialsPayload {
    Version: number
    AccessKeyId: string
    SecretAccessKey: string
    SessionToken?: string
    Expiration?: string
}

function runCredentialProcess(command: string, profileName: string): Promise<CredentialSet> {
    const { exec } = require('child_process')

    return new Promise<CredentialSet>((resolve, reject) => {
        exec(command, { env: process.env }, (err: (Error & { code?: string | number }) | null, stdout: string, stderr: string) => {
            if (err) {
                // ENOENT / "command not found" is by far the most common failure
                // here, and almost always means the command isn't reachable in
                // the PATH this process was launched with.
                const looksLikeNotFound = err.code === 'ENOENT'
                    || /command not found|not recognized|No such file or directory/i.test(stderr || err.message || '')

                if (looksLikeNotFound) {
                    reject(new Error(
                        `credential_process for profile "${profileName}" could not run ` +
                        `"${command}": command not found.\n` +
                        `Insomnia was likely launched from Finder/Dock/Spotlight, so it does ` +
                        `not inherit your shell's PATH additions. Fix: use the full absolute ` +
                        `path to the executable in the credential_process line of ~/.aws/config ` +
                        `(e.g. run "which <command>" in your terminal and use that path instead ` +
                        `of the bare command name).`
                    ))
                    return
                }

                reject(new Error(
                    `credential_process for profile "${profileName}" exited with an error ` +
                    `running "${command}": ${(stderr || err.message || '').trim() || 'no output'}`
                ))
                return
            }

            let payload: ProcessCredentialsPayload
            try {
                payload = JSON.parse(stdout)
            } catch (parseErr) {
                reject(new Error(
                    `credential_process for profile "${profileName}" ("${command}") did not ` +
                    `return valid JSON. Output was: ${stdout.slice(0, 300)}`
                ))
                return
            }

            if (payload.Version !== 1) {
                reject(new Error(
                    `credential_process for profile "${profileName}" ("${command}") returned ` +
                    `an unsupported payload (expected "Version": 1).`
                ))
                return
            }

            if (payload.Expiration && new Date(payload.Expiration) < new Date()) {
                reject(new Error(
                    `credential_process for profile "${profileName}" ("${command}") returned ` +
                    `already-expired credentials (Expiration: ${payload.Expiration}). ` +
                    `Check that the underlying credential tool is authenticated and try again.`
                ))
                return
            }

            if (!payload.AccessKeyId || !payload.SecretAccessKey) {
                reject(new Error(
                    `credential_process for profile "${profileName}" ("${command}") returned ` +
                    `a payload missing AccessKeyId/SecretAccessKey.`
                ))
                return
            }

            resolve({
                accessKeyId: payload.AccessKeyId,
                secretAccessKey: payload.SecretAccessKey,
                sessionToken: payload.SessionToken,
            })
        })
    })
}

function loadCredentials(profileName: string): Promise<CredentialSet> {
    const now = Date.now()
    const cached = credsCache.get(profileName)
    if (cached && cached.expiresAt > now) {
        return cached.promise
    }

    // Insomnia v13 hardening: require Node dependencies inside the hook/helper
    // (no top-level/entry-point requires) so they run in the plugin's
    // Node-capable execution context.
    const aws = require('aws-sdk')

    const promise = (async (): Promise<CredentialSet> => {
        const processCommand = findCredentialProcess(profileName)

        if (processCommand) {
            return runCredentialProcess(processCommand, profileName)
        }

        const creds = new aws.SharedIniFileCredentials({ profile: profileName })
        // Ensure the profile is actually read from disk before we read fields
        // off it (the object is not guaranteed to be populated synchronously).
        await new Promise<void>((resolve, reject) => {
            creds.refresh((err: Error | null) => (err ? reject(err) : resolve()))
        })
        return {
            accessKeyId: creds.accessKeyId,
            secretAccessKey: creds.secretAccessKey,
            sessionToken: creds.sessionToken,
        }
    })()

    // Don't cache a transient failure for the full TTL; evict on rejection.
    promise.catch(() => {
        const entry = credsCache.get(profileName)
        if (entry && entry.promise === promise) {
            credsCache.delete(profileName)
        }
    })

    credsCache.set(profileName, { promise, expiresAt: now + CACHE_TTL_MS })
    return promise
}

export const templateTags = [
    {
        name: 'awsprofilecreds',
        displayName: 'awsprofilecreds',
        description: 'Insomnia plugin - AWS IAM credential loader from an AWS profile',
        args: [
            {
                displayName: 'Profile name',
                help: 'Specify the AWS profile name for fetching credentials.',
                type: 'string',
                placeholder: 'Specify the AWS profile name for fetching credentials.'
            },
            {
                displayName: 'Attribute',
                type: 'enum',
                options: [
                    {
                        displayName: Attribute.accessKeyId,
                        value: Attribute.accessKeyId,
                    },
                    {
                        displayName: Attribute.secretAccessKey,
                        value: Attribute.secretAccessKey,
                    },
                    {
                        displayName: Attribute.sessionToken,
                        value: Attribute.sessionToken,
                    }
                ]
            }
        ],
        async run(context: object, profileName: string, attribute: Attribute) {
            const creds = await loadCredentials(profileName)

            // Return a plain, JSON-serializable string. Everything now crosses a
            // process boundary and is JSON-serialized in Insomnia v13.
            const value = (creds as Record<string, string | undefined>)[attribute]
            return value == null ? '' : String(value)
        }
    }
];
