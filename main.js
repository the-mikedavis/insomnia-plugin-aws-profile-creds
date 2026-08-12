"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.templateTags = void 0;
var Attribute;
(function (Attribute) {
    Attribute["accessKeyId"] = "accessKeyId";
    Attribute["secretAccessKey"] = "secretAccessKey";
    Attribute["sessionToken"] = "sessionToken";
})(Attribute || (Attribute = {}));
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
var CACHE_TTL_MS = 5000;
var credsCache = new Map();
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
function findCredentialProcess(profileName) {
    var os = require('os');
    var path = require('path');
    var fs = require('fs');
    var configPath = process.env.AWS_CONFIG_FILE || path.join(os.homedir(), '.aws', 'config');
    var contents;
    try {
        contents = fs.readFileSync(configPath, 'utf8');
    }
    catch (_a) {
        return undefined;
    }
    // AWS config sections are named "[default]" or "[profile <name>]" (every
    // profile except "default" carries the "profile " prefix).
    var targetHeader = profileName === 'default' ? '[default]' : "[profile ".concat(profileName, "]");
    var lines = contents.split(/\r?\n/);
    var inTargetSection = false;
    for (var _i = 0, lines_1 = lines; _i < lines_1.length; _i++) {
        var rawLine = lines_1[_i];
        var line = rawLine.trim();
        if (line.startsWith('[')) {
            inTargetSection = line === targetHeader;
            continue;
        }
        if (inTargetSection) {
            var match = line.match(/^credential_process\s*=\s*(.+)$/);
            if (match) {
                return match[1].trim();
            }
        }
    }
    return undefined;
}
function runCredentialProcess(command, profileName) {
    var exec = require('child_process').exec;
    return new Promise(function (resolve, reject) {
        exec(command, { env: process.env }, function (err, stdout, stderr) {
            if (err) {
                // ENOENT / "command not found" is by far the most common failure
                // here, and almost always means the command isn't reachable in
                // the PATH this process was launched with.
                var looksLikeNotFound = err.code === 'ENOENT'
                    || /command not found|not recognized|No such file or directory/i.test(stderr || err.message || '');
                if (looksLikeNotFound) {
                    reject(new Error("credential_process for profile \"".concat(profileName, "\" could not run ") +
                        "\"".concat(command, "\": command not found.\n") +
                        "Insomnia was likely launched from Finder/Dock/Spotlight, so it does " +
                        "not inherit your shell's PATH additions. Fix: use the full absolute " +
                        "path to the executable in the credential_process line of ~/.aws/config " +
                        "(e.g. run \"which <command>\" in your terminal and use that path instead " +
                        "of the bare command name)."));
                    return;
                }
                reject(new Error("credential_process for profile \"".concat(profileName, "\" exited with an error ") +
                    "running \"".concat(command, "\": ").concat((stderr || err.message || '').trim() || 'no output')));
                return;
            }
            var payload;
            try {
                payload = JSON.parse(stdout);
            }
            catch (parseErr) {
                reject(new Error("credential_process for profile \"".concat(profileName, "\" (\"").concat(command, "\") did not ") +
                    "return valid JSON. Output was: ".concat(stdout.slice(0, 300))));
                return;
            }
            if (payload.Version !== 1) {
                reject(new Error("credential_process for profile \"".concat(profileName, "\" (\"").concat(command, "\") returned ") +
                    "an unsupported payload (expected \"Version\": 1)."));
                return;
            }
            if (payload.Expiration && new Date(payload.Expiration) < new Date()) {
                reject(new Error("credential_process for profile \"".concat(profileName, "\" (\"").concat(command, "\") returned ") +
                    "already-expired credentials (Expiration: ".concat(payload.Expiration, "). ") +
                    "Check that the underlying credential tool is authenticated and try again."));
                return;
            }
            if (!payload.AccessKeyId || !payload.SecretAccessKey) {
                reject(new Error("credential_process for profile \"".concat(profileName, "\" (\"").concat(command, "\") returned ") +
                    "a payload missing AccessKeyId/SecretAccessKey."));
                return;
            }
            resolve({
                accessKeyId: payload.AccessKeyId,
                secretAccessKey: payload.SecretAccessKey,
                sessionToken: payload.SessionToken
            });
        });
    });
}
function loadCredentials(profileName) {
    var _this = this;
    var now = Date.now();
    var cached = credsCache.get(profileName);
    if (cached && cached.expiresAt > now) {
        return cached.promise;
    }
    // Insomnia v13 hardening: require Node dependencies inside the hook/helper
    // (no top-level/entry-point requires) so they run in the plugin's
    // Node-capable execution context.
    var aws = require('aws-sdk');
    var promise = (function () { return __awaiter(_this, void 0, void 0, function () {
        var processCommand, creds;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    processCommand = findCredentialProcess(profileName);
                    if (processCommand) {
                        return [2 /*return*/, runCredentialProcess(processCommand, profileName)];
                    }
                    creds = new aws.SharedIniFileCredentials({ profile: profileName });
                    // Ensure the profile is actually read from disk before we read fields
                    // off it (the object is not guaranteed to be populated synchronously).
                    return [4 /*yield*/, new Promise(function (resolve, reject) {
                            creds.refresh(function (err) { return (err ? reject(err) : resolve()); });
                        })];
                case 1:
                    // Ensure the profile is actually read from disk before we read fields
                    // off it (the object is not guaranteed to be populated synchronously).
                    _a.sent();
                    return [2 /*return*/, {
                            accessKeyId: creds.accessKeyId,
                            secretAccessKey: creds.secretAccessKey,
                            sessionToken: creds.sessionToken
                        }];
            }
        });
    }); })();
    // Don't cache a transient failure for the full TTL; evict on rejection.
    promise["catch"](function () {
        var entry = credsCache.get(profileName);
        if (entry && entry.promise === promise) {
            credsCache["delete"](profileName);
        }
    });
    credsCache.set(profileName, { promise: promise, expiresAt: now + CACHE_TTL_MS });
    return promise;
}
exports.templateTags = [
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
                        value: Attribute.accessKeyId
                    },
                    {
                        displayName: Attribute.secretAccessKey,
                        value: Attribute.secretAccessKey
                    },
                    {
                        displayName: Attribute.sessionToken,
                        value: Attribute.sessionToken
                    }
                ]
            }
        ],
        run: function (context, profileName, attribute) {
            return __awaiter(this, void 0, void 0, function () {
                var creds, value;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0: return [4 /*yield*/, loadCredentials(profileName)
                            // Return a plain, JSON-serializable string. Everything now crosses a
                            // process boundary and is JSON-serialized in Insomnia v13.
                        ];
                        case 1:
                            creds = _a.sent();
                            value = creds[attribute];
                            return [2 /*return*/, value == null ? '' : String(value)];
                    }
                });
            });
        }
    }
];
