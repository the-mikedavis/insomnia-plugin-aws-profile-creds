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
// secret key, session token), so run() fires multiple times per request. ADA
// rewrites ~/.aws/credentials in the background, and AWS temporary credentials
// are a matched triplet that only validate together. Reading each field with
// an independent SharedIniFileCredentials load can therefore mix an old access
// key with a new secret/session token if ADA rotates mid-request, producing an
// intermittent SigV4 "signature does not match" error.
//
// To prevent that, we load the full triplet once and serve all three fields
// from a single snapshot, cached for a short TTL and keyed by profile name. We
// cache the in-flight Promise (not just the resolved value) so concurrent field
// renders within one request share the exact same load. Insomnia v13 runs
// plugins in a persistent hidden process, so this module-level cache survives
// across invocations; the short TTL keeps us picking up ADA rotations promptly.
const CACHE_TTL_MS = 5000
const credsCache = new Map<string, { promise: Promise<CredentialSet>; expiresAt: number }>()

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
